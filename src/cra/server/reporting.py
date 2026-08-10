"""Vulnerability, incident, and reporting-clock handlers.

These write Postgres rows rather than the state blob — deadlines are queried
across every product a user owns, which has to hit an index rather than
deserialise blobs. They therefore require `DATABASE_URL`.

The important behaviour here is the cascade: marking a vulnerability
**actively exploited** opens an incident and materialises its obligations
automatically. Article 14 turns on active exploitation, not severity, and a
developer who has just discovered they are being exploited is not going to
remember to also file a separate incident record. The clock should start
whether or not they thought about reporting.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from cra.agents import dispatch as _dispatch
from cra.db import (
    Incident,
    Product,
    ProductMember,
    ReportingObligation,
    Vulnerability,
    session_scope,
)
from cra.deadlines import (
    OBLIGATION_SCHEDULE,
    hours_remaining,
    obligation_state,
    pending_stages,
    schedule_for,
)
from cra.schemas.enums import IncidentKind, ObligationState, ReportStage
from cra.server import audit, entitlements
from cra.server.timestamps import parse_ts
from cra.server.errors import InvalidState, NotFound

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str], *, field: str) -> Optional[datetime]:
    """See `server/timestamps.parse_ts`. Kept as a name because this module
    calls it in a dozen places and the phrasing of its refusal is tuned to
    reporting."""
    return parse_ts(value, field=field, what="a statutory deadline")


def _anchor_ts(value: Optional[str], *, now: datetime, field: str = "became_aware_at") -> Optional[datetime]:
    """Parse a timestamp an Article 14 clock counts from, refusing a future one.

    There are two such anchors, and this guarded only the first for a long
    time. Awareness is the more consequential — the 24-hour early warning and
    the 72-hour notification both run from it — but **the final report's
    fourteen days run from the corrective measure**, not from awareness, so a
    date on that field schedules a statutory deadline just as firmly.

    Both are unverifiable claims: the tool cannot know when someone knew, or
    when a fix really shipped. So the only checks worth making are the ones
    that catch an obviously wrong answer, and a date that has not happened yet
    is one. It says an event occurred that has not, and counts from it.

    The two fields fail in opposite directions, which is why neither can be
    left out. A future awareness date pushes a deadline outwards. A future
    corrective measure marks a mitigation available when none is — the error
    that points the reassuring way.
    """
    dt = _parse_ts(value, field=field)
    if dt is not None and dt > now:
        raise InvalidState(
            f"{field} is {dt.isoformat()}, which is in the future — it has not "
            "happened yet. This field records when something did occur, and an "
            "Article 14 clock "
            "counts from it — dating it forward would schedule a statutory "
            "deadline from an event that has not taken place. If you are "
            "planning the date rather than recording it, leave the field unset "
            "until it is true."
        )
    return dt


def _overdue_now(views: list[dict]) -> list[dict]:
    return [v for v in views if v["state"] == ObligationState.OVERDUE.value]


def _backdated_note(
    aware: datetime,
    now: datetime,
    overdue: list[dict],
    *,
    anchor_supplied: bool = True,
) -> Optional[str]:
    """Say plainly that a clock started in the past and what it already cost.

    A backdated anchor can produce obligations that are already overdue. That
    has to be stated, not left to the reader to infer from a negative
    `hours_remaining` — the whole reason the anchor is being fixed is that the
    tool used to imply someone was on time when they were not.

    **Silent when the anchor was assumed rather than given**, and that guard is
    the point of the parameter. Omitting `became_aware_at` defaults the anchor
    to now, and `now` is then recomputed microseconds later downstream — so
    `aware < now` by a hair, and this fired with "Clocks anchored 0.0h ago, at
    the time you became aware — not at the time you recorded it." Which is the
    opposite of what happened, next to a soothing "Nothing is overdue yet" that
    is true only of the assumption.

    `anchor_assumed` already says the honest thing in that case. Two fields
    contradicting each other in one response is worse than one, and the
    comforting one appeared first — in this product that is the direction that
    costs, because the risk being managed is a team believing a statutory
    deadline is further away than it is.
    """
    if not anchor_supplied or aware >= now:
        return None
    late_by = round((now - aware).total_seconds() / 3600, 1)
    if not overdue:
        return (
            f"Clocks anchored {late_by}h ago, at the time you became aware — "
            "not at the time you recorded it. Nothing is overdue yet."
        )
    stages = ", ".join(v["stage"].replace("_", " ") for v in overdue)
    return (
        f"Clocks anchored {late_by}h ago, at the time you became aware. "
        f"{len(overdue)} obligation(s) are ALREADY OVERDUE: {stages}. File "
        "immediately — a late report is materially better than a later one, "
        "and the lateness is on the record either way."
    )


def _materialise_obligations(db: Session, incident: Incident) -> list[ReportingObligation]:
    """Create the obligation rows whose clocks have actually started.

    Idempotent: stages already present are left alone, so recording a
    corrective measure later adds the final report without disturbing the
    early warning someone may have already submitted.
    """
    existing = {
        o.stage
        for o in db.execute(
            select(ReportingObligation).where(ReportingObligation.incident_id == incident.id)
        ).scalars()
    }
    created: list[ReportingObligation] = []
    for stage, due_at in schedule_for(
        incident.kind,
        became_aware_at=incident.became_aware_at,
        corrective_measure_available_at=incident.corrective_measure_available_at,
    ):
        if stage.value in existing:
            continue
        row = ReportingObligation(
            product_id=incident.product_id,
            incident_id=incident.id,
            stage=stage.value,
            due_at=due_at,
        )
        db.add(row)
        created.append(row)
    if created:
        db.flush()
    return created


def _obligation_view(o: ReportingObligation, now: datetime) -> dict:
    state = obligation_state(
        due_at=o.due_at,
        submitted_at=o.submitted_at,
        waived_reason=o.waived_reason,
        stage=o.stage,
        now=now,
    )
    return {
        "obligation_id": o.id,
        "product_id": o.product_id,
        "incident_id": o.incident_id,
        "stage": o.stage,
        "due_at": o.due_at.isoformat(),
        "hours_remaining": hours_remaining(o.due_at, now),
        "state": state.value,
        "submitted_at": o.submitted_at.isoformat() if o.submitted_at else None,
        "submission_ref": o.submission_ref,
    }


def _require_member(db: Session, product_id: str, actor_id: str) -> None:
    if not actor_id:
        return
    row = db.execute(
        select(ProductMember).where(
            ProductMember.product_id == product_id,
            ProductMember.user_id == actor_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFound(f"no product {product_id!r} for this user")


# ---- vulnerabilities ---------------------------------------------------------


def unremediated_exploited(db: Session, product_id: str) -> list[Vulnerability]:
    """Actively exploited vulnerabilities with nothing recorded to fix them.

    The release gate's input, and the reason it exists as a separate query from
    `advisories.open_candidate_counts`.

    A candidate stops being open the moment a human confirms it — which is
    correct, the candidate queue is a queue of *questions* and confirming
    answers one. But the gate counted only candidates, so confirming an
    exploited advisory removed it from the gate. The incentive that produced
    was exact and backwards: an exploited candidate blocked your release, and
    the way to clear it was to agree that your product was affected. An
    end-to-end run shipped a product with a confirmed, actively exploited
    log4j while an unfiled 24-hour Article 14 clock ran, and the frozen
    determination recorded `exploited_open: 0`.

    **Unremediated means nothing has been recorded, not that nothing was done.**
    Two places a manufacturer says a fix exists, and either is enough to stop
    this blocking — because shipping the release that carries the fix is
    exactly the case where it must not:

      * `Vulnerability.remediation_ref` — the artefact that fixes it.
      * `Incident.corrective_measure_available_at` — the Article 14 anchor for
        the final report, which by definition means a corrective measure is
        available. It lives on the incident rather than the vulnerability, so
        this has to reach across the link.

    `Vulnerability.status` is deliberately not consulted. It is free text with
    no vocabulary behind it, so keying a release gate on it would be keying it
    on a convention nobody enforces.
    """
    remedied_by_incident = (
        select(Incident.vulnerability_id)
        .where(
            Incident.product_id == product_id,
            Incident.vulnerability_id.isnot(None),
            Incident.corrective_measure_available_at.isnot(None),
        )
    )
    return list(
        db.execute(
            select(Vulnerability).where(
                Vulnerability.product_id == product_id,
                Vulnerability.actively_exploited.is_(True),
                Vulnerability.remediation_ref.is_(None),
                Vulnerability.id.not_in(remedied_by_incident),
            )
        ).scalars()
    )


def record_vulnerability(
    *,
    product_id: str,
    actor_id: str = "",
    summary: str,
    identifier: Optional[str] = None,
    affected_component: Optional[str] = None,
    discovered_at: Optional[str] = None,
    actively_exploited: bool = False,
    became_aware_at: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
) -> dict:
    with session_scope() as db:
        _require_member(db, product_id, actor_id)
        now = _now()
        discovered = _parse_ts(discovered_at, field="discovered_at") or now
        # The Article 14 anchor. Distinct from `discovered_at`: knowing a
        # vulnerability exists and knowing it is being exploited are different
        # moments, and only the second starts a clock.
        aware = _anchor_ts(became_aware_at, now=now) or now
        vuln = Vulnerability(
            product_id=product_id,
            identifier=identifier,
            affected_component=affected_component,
            summary=summary,
            discovered_at=discovered,
            source=source,
            cvss_score=severity,
            actively_exploited=bool(actively_exploited),
            exploitation_determined_at=aware if actively_exploited else None,
        )
        db.add(vuln)
        db.flush()

        audit.record(
            db,
            product_id=product_id,
            subject_type="vulnerability",
            subject_id=vuln.id,
            op="record_vulnerability",
            accountable_user_id=actor_id or None,
            rationale=summary[:500],
            payload={
                "identifier": identifier,
                "actively_exploited": bool(actively_exploited),
                "became_aware_at": aware.isoformat() if actively_exploited else None,
            },
        )

        result = {
            "ok": True,
            "vulnerability_id": vuln.id,
            "actively_exploited": vuln.actively_exploited,
        }
        if actively_exploited:
            result.update(_cascade(
                db, vuln, became_aware_at=aware, actor_id=actor_id,
                anchor_supplied=became_aware_at is not None,
            ))
            result["became_aware_at"] = aware.isoformat()
            if became_aware_at is None:
                # A silent default on this field is what made the tool report
                # people as on time when they were late. Say what was assumed,
                # and how to correct it.
                result["anchor_assumed"] = (
                    "No became_aware_at given, so the clocks were anchored at "
                    "the moment you recorded this. If you knew earlier, the "
                    "deadlines above are too late — correct it with "
                    "update_vulnerability(became_aware_at=..., "
                    "awareness_rationale=...)."
                )
        else:
            result["note"] = (
                "No reporting clock started. If this turns out to be actively "
                "exploited, call update_vulnerability(actively_exploited=true) "
                "immediately — the 24-hour clock runs from awareness."
            )
        return result


def _cascade(
    db: Session,
    vuln: Vulnerability,
    *,
    became_aware_at: datetime,
    actor_id: str,
    anchor_supplied: bool = True,
) -> dict:
    """Open an incident for an actively exploited vulnerability and start its clocks."""
    existing = db.execute(
        select(Incident).where(Incident.vulnerability_id == vuln.id)
    ).scalar_one_or_none()
    if existing is not None:
        return {
            "incident_id": existing.id,
            "deadlines": [
                _obligation_view(o, _now())
                for o in db.execute(
                    select(ReportingObligation).where(
                        ReportingObligation.incident_id == existing.id
                    )
                ).scalars()
            ],
        }

    incident = Incident(
        product_id=vuln.product_id,
        kind=IncidentKind.ACTIVELY_EXPLOITED_VULN.value,
        vulnerability_id=vuln.id,
        became_aware_at=became_aware_at,
        description=vuln.summary,
        severity=vuln.cvss_score,
    )
    db.add(incident)
    db.flush()

    created = _materialise_obligations(db, incident)
    audit.record(
        db,
        product_id=vuln.product_id,
        subject_type="incident",
        subject_id=incident.id,
        op="open_incident",
        accountable_user_id=actor_id or None,
        rationale="actively exploited vulnerability — Article 14 clocks started",
        payload={"vulnerability_id": vuln.id, "stages": [o.stage for o in created]},
    )

    now = _now()
    pending = [r.stage.value for r in pending_stages(IncidentKind.ACTIVELY_EXPLOITED_VULN)]
    views = [_obligation_view(o, now) for o in created]
    overdue = _overdue_now(views)
    out = {
        "incident_id": incident.id,
        "deadlines": views,
        "not_yet_scheduled": {
            "stages": pending,
            "why": (
                "The final report's 14 days run from when a corrective measure "
                "becomes available, not from awareness. Call "
                "update_vulnerability(corrective_measure_available_at=...) when "
                "the fix ships and this deadline will be created then."
            ),
        },
        "urgent": (
            "Reportable now. Early warning is due within 24 hours of becoming "
            "aware, via the CRA Single Reporting Platform to your CSIRT."
        ),
    }
    note = _backdated_note(
        became_aware_at, now, overdue, anchor_supplied=anchor_supplied
    )
    if note:
        out["backdated"] = note
    if overdue:
        out["already_overdue"] = [v["stage"] for v in overdue]
    return out


def _reanchor(
    db: Session,
    vuln: Vulnerability,
    *,
    became_aware_at: datetime,
    rationale: str,
    actor_id: str,
    now: datetime,
) -> dict:
    """Move an existing incident's awareness anchor and recompute its clocks.

    The correction path for the default. Someone who recorded an exploited
    vulnerability on Monday, having known since Friday, has deadlines that are
    two days too generous — and no way to fix them without this.

    Two things it will not do. It demands a rationale, because moving a
    statutory deadline after the fact is the kind of edit an auditor reads
    closely and "someone changed it" is not an answer. And it leaves submitted
    obligations alone: their due date is a historical fact that a filed report
    was judged against, so rewriting it would retroactively change whether a
    report already sent was late.
    """
    incident = db.execute(
        select(Incident).where(Incident.vulnerability_id == vuln.id)
    ).scalar_one_or_none()
    if incident is None:
        raise InvalidState(
            "no incident for this vulnerability, so there is no clock to "
            "re-anchor. became_aware_at only starts a clock alongside "
            "actively_exploited=true."
        )
    if incident.became_aware_at == became_aware_at:
        return {"awareness_unchanged": became_aware_at.isoformat()}
    if not rationale.strip():
        raise InvalidState(
            "awareness_rationale is required to move an awareness date. This "
            "shifts statutory deadlines that have already been communicated — "
            "say what established the earlier date (the alert, the log line, "
            "the customer report) so the change is defensible."
        )

    was = incident.became_aware_at
    incident.became_aware_at = became_aware_at
    vuln.exploitation_determined_at = became_aware_at

    rows = list(
        db.execute(
            select(ReportingObligation).where(
                ReportingObligation.incident_id == incident.id
            )
        ).scalars()
    )
    schedule = dict(
        schedule_for(
            incident.kind,
            became_aware_at=became_aware_at,
            corrective_measure_available_at=incident.corrective_measure_available_at,
        )
    )
    moved: list[dict] = []
    frozen: list[dict] = []
    for row in rows:
        due = schedule.get(ReportStage(row.stage))
        if due is None or due == row.due_at:
            continue
        if row.submitted_at is not None:
            frozen.append({"stage": row.stage, "due_at": row.due_at.isoformat()})
            continue
        moved.append(
            {
                "stage": row.stage,
                "was_due_at": row.due_at.isoformat(),
                "now_due_at": due.isoformat(),
            }
        )
        row.due_at = due
    db.flush()

    audit.record(
        db,
        product_id=vuln.product_id,
        subject_type="incident",
        subject_id=incident.id,
        op="reanchor_awareness",
        accountable_user_id=actor_id or None,
        rationale=rationale.strip()[:500],
        payload={
            "was": was.isoformat(),
            "now": became_aware_at.isoformat(),
            "moved": moved,
            "left_alone_because_submitted": frozen,
        },
    )

    views = [_obligation_view(o, now) for o in rows if o.submitted_at is None]
    overdue = _overdue_now(views)
    out: dict = {
        "awareness_reanchored": {
            "was": was.isoformat(),
            "now": became_aware_at.isoformat(),
            "deadlines_moved": moved,
        },
        "deadlines": views,
    }
    if frozen:
        out["awareness_reanchored"]["left_alone_because_submitted"] = frozen
        out["submitted_note"] = (
            "Obligations already submitted keep their original due date — "
            "whether that report was late is a matter of record, not "
            "something to recalculate."
        )
    note = _backdated_note(became_aware_at, now, overdue)
    if note:
        out["backdated"] = note
    if overdue:
        out["already_overdue"] = [v["stage"] for v in overdue]
    return out


def update_vulnerability(
    *,
    product_id: str,
    actor_id: str = "",
    vulnerability_id: str,
    actively_exploited: Optional[bool] = None,
    status: Optional[str] = None,
    remediation_ref: Optional[str] = None,
    corrective_measure_available_at: Optional[str] = None,
    became_aware_at: Optional[str] = None,
    awareness_rationale: str = "",
) -> dict:
    with session_scope() as db:
        _require_member(db, product_id, actor_id)
        vuln = db.get(Vulnerability, vulnerability_id)
        if vuln is None or vuln.product_id != product_id:
            raise NotFound(f"no vulnerability {vulnerability_id!r} on this product")

        now = _now()
        aware = _anchor_ts(became_aware_at, now=now)
        result: dict = {"ok": True, "vulnerability_id": vuln.id}
        changed: dict = {}

        if status is not None:
            vuln.status = status
            changed["status"] = status
        if remediation_ref is not None:
            vuln.remediation_ref = remediation_ref
            changed["remediation_ref"] = remediation_ref

        newly_exploited = bool(actively_exploited) and not vuln.actively_exploited
        if actively_exploited is not None:
            vuln.actively_exploited = bool(actively_exploited)
            if newly_exploited:
                vuln.exploitation_determined_at = aware or now
            changed["actively_exploited"] = bool(actively_exploited)

        cm = _anchor_ts(
            corrective_measure_available_at, now=now,
            field="corrective_measure_available_at",
        )

        audit.record(
            db,
            product_id=product_id,
            subject_type="vulnerability",
            subject_id=vuln.id,
            op="update_vulnerability",
            accountable_user_id=actor_id or None,
            payload=changed,
        )

        if newly_exploited:
            anchor = aware or now
            # `anchor` here is either supplied or already recorded, never
            # assumed at this moment, so the backdated note is meaningful.
            result.update(_cascade(db, vuln, became_aware_at=anchor, actor_id=actor_id))
            result["became_aware_at"] = anchor.isoformat()
            if became_aware_at is None:
                result["anchor_assumed"] = (
                    "No became_aware_at given, so the clocks were anchored at "
                    "the moment you recorded this. If you knew earlier, say so "
                    "now — the deadlines above are otherwise too late."
                )
        elif aware is not None:
            result.update(
                _reanchor(
                    db,
                    vuln,
                    became_aware_at=aware,
                    rationale=awareness_rationale,
                    actor_id=actor_id,
                    now=now,
                )
            )

        if cm is not None:
            incident = db.execute(
                select(Incident).where(Incident.vulnerability_id == vuln.id)
            ).scalar_one_or_none()
            if incident is None:
                raise InvalidState(
                    "no incident for this vulnerability — a corrective-measure date "
                    "only anchors a final report once the vulnerability is marked "
                    "actively exploited"
                )
            incident.corrective_measure_available_at = cm
            created = _materialise_obligations(db, incident)
            audit.record(
                db,
                product_id=product_id,
                subject_type="incident",
                subject_id=incident.id,
                op="set_corrective_measure",
                accountable_user_id=actor_id or None,
                payload={"corrective_measure_available_at": cm.isoformat()},
            )
            result["final_report_scheduled"] = [_obligation_view(o, now) for o in created]

        return result


# ---- incidents ---------------------------------------------------------------


def report_incident(
    *,
    product_id: str,
    actor_id: str = "",
    kind: str = IncidentKind.SEVERE_INCIDENT.value,
    became_aware_at: Optional[str] = None,
    description: str = "",
    severity: Optional[str] = None,
) -> dict:
    with session_scope() as db:
        _require_member(db, product_id, actor_id)
        now = _now()
        aware = _anchor_ts(became_aware_at, now=now) or now

        try:
            kind_enum = IncidentKind(kind)
        except ValueError as e:
            raise InvalidState(
                f"kind must be one of {[k.value for k in OBLIGATION_SCHEDULE]}"
            ) from e

        incident = Incident(
            product_id=product_id,
            kind=kind_enum.value,
            became_aware_at=aware,
            description=description,
            severity=severity,
        )
        db.add(incident)
        db.flush()
        created = _materialise_obligations(db, incident)

        audit.record(
            db,
            product_id=product_id,
            subject_type="incident",
            subject_id=incident.id,
            op="report_incident",
            accountable_user_id=actor_id or None,
            rationale=description[:500],
            payload={"kind": kind_enum.value, "became_aware_at": aware.isoformat()},
        )

        pending = [r.stage.value for r in pending_stages(kind_enum)]
        out = {
            "ok": True,
            "incident_id": incident.id,
            "became_aware_at": aware.isoformat(),
            "deadlines": [_obligation_view(o, now) for o in created],
            "next": (
                "Draft and submit the early warning via the CRA Single Reporting "
                "Platform, then record it with record_report_submission(). This "
                "tool tracks the clock; it does not submit on your behalf."
            ),
        }
        if pending:
            out["not_yet_scheduled"] = {"stages": pending}
        return out


# ---- the clocks --------------------------------------------------------------


def get_reporting_deadlines(
    *,
    product_id: str = "",
    actor_id: str = "",
    include_submitted: bool = False,
) -> dict:
    """Open obligations, soonest first.

    With no `product_id` this answers "what's due across everything I own",
    which is the question someone asks when they have several products and one
    of them is on fire.
    """
    not_covered: list[str] = []
    with session_scope() as db:
        now = _now()
        q = select(ReportingObligation)
        if product_id:
            _require_member(db, product_id, actor_id)
            q = q.where(ReportingObligation.product_id == product_id)
        elif actor_id:
            # Across everything this person is on — but only the products whose
            # owner's plan covers reporting. The rest are named in the result
            # rather than silently missing: an incomplete list of statutory
            # deadlines that looks complete is the worst output this tool has.
            covered, not_covered = entitlements.covered_product_ids(
                actor_id, entitlements.REPORTING
            )
            q = q.where(ReportingObligation.product_id.in_(covered))
        if not include_submitted:
            q = q.where(ReportingObligation.submitted_at.is_(None))

        rows = list(db.execute(q.order_by(ReportingObligation.due_at)).scalars())
        views = [_obligation_view(o, now) for o in rows]
        names = {
            p.id: p.name
            for p in db.execute(
                select(Product).where(Product.id.in_({o.product_id for o in rows}))
            ).scalars()
        } if rows else {}
        for v in views:
            v["product_name"] = names.get(v["product_id"])

        overdue = [v for v in views if v["state"] == ObligationState.OVERDUE.value]
        due_soon = [v for v in views if v["state"] == ObligationState.DUE_SOON.value]
        out = {
            "ok": True,
            "counts": {
                "open": len(views),
                "overdue": len(overdue),
                "due_soon": len(due_soon),
            },
            "deadlines": views,
            # Three states, not two. "Nothing due" while a 24-hour clock is
            # running is the single most dangerous sentence this tool could
            # emit — open-but-not-yet-urgent has to read differently from
            # nothing-open.
            "attention": (
                f"{len(overdue)} overdue, {len(due_soon)} due soon."
                if (overdue or due_soon)
                else (
                    f"{len(views)} open, none urgent yet — soonest is the "
                    f"{views[0]['stage'].replace('_', ' ')} in "
                    f"{views[0]['hours_remaining']}h."
                    if views
                    else "Nothing open."
                )
            ),
        }
        if not_covered:
            # Never let a filtered list read as a complete one. These products
            # may well have deadlines running; this tool simply is not tracking
            # them on the plan they are on.
            uncovered_names = {
                p.id: p.name
                for p in db.execute(
                    select(Product).where(Product.id.in_(not_covered))
                ).scalars()
            }
            out["not_covered"] = [
                {"product_id": pid, "product_name": uncovered_names.get(pid)}
                for pid in not_covered
            ]
            out["coverage_note"] = (
                f"{len(not_covered)} product(s) are not shown because reporting "
                "is not included in their plan. That is not a statement that "
                "nothing is due for them."
            )
        return out


def open_obligation_views(product_id: str) -> Optional[list[dict]]:
    """Open obligations for one product, for embedding in other tools' output.

    Returns None — not an empty list — when no database is configured, so a
    caller can say "deadlines unavailable" rather than the far more dangerous
    "nothing is due". The distinction matters: the file backend is dev-only and
    an empty deadline block there would read as all-clear.
    """
    if not os.environ.get("DATABASE_URL"):
        return None
    try:
        with session_scope() as db:
            now = _now()
            rows = db.execute(
                select(ReportingObligation)
                .where(
                    ReportingObligation.product_id == product_id,
                    ReportingObligation.submitted_at.is_(None),
                )
                .order_by(ReportingObligation.due_at)
            ).scalars()
            return [_obligation_view(o, now) for o in rows]
    except SQLAlchemyError:
        # A database that is configured but unreachable is "unknown", not
        # "nothing due" — and not a reason to fail the whole status read. The
        # caller still gets classification, requirements and members, with the
        # deadline block explicitly marked unavailable. Logged at error level
        # because it is an operational problem even though the read succeeds.
        log.exception("deadline read failed for product %s", product_id)
        return None


def record_report_submission(
    *,
    product_id: str,
    actor_id: str = "",
    obligation_id: str,
    submitted_at: Optional[str] = None,
    submission_ref: Optional[str] = None,
    recipient: Optional[str] = None,
) -> dict:
    """Close an obligation once the human has filed it on the SRP.

    This tool never submits. Submission happens on ENISA's Single Reporting
    Platform under the manufacturer's own EU Login; what gets recorded here is
    the proof that it happened.
    """
    with session_scope() as db:
        _require_member(db, product_id, actor_id)
        o = db.get(ReportingObligation, obligation_id)
        if o is None or o.product_id != product_id:
            raise NotFound(f"no obligation {obligation_id!r} on this product")
        if o.submitted_at is not None:
            raise InvalidState(
                f"{o.stage} was already recorded as submitted at {o.submitted_at.isoformat()}"
            )

        now = _now()
        when = _parse_ts(submitted_at, field="submitted_at") or now
        o.submitted_at = when
        o.submission_ref = submission_ref
        o.recipient = recipient

        audit.record(
            db,
            product_id=product_id,
            subject_type="obligation",
            subject_id=o.id,
            op="record_report_submission",
            accountable_user_id=actor_id or None,
            payload={
                "stage": o.stage,
                "submitted_at": when.isoformat(),
                "submission_ref": submission_ref,
            },
        )

        state = obligation_state(
            due_at=o.due_at, submitted_at=when, stage=o.stage, now=now
        )
        return {
            "ok": True,
            "obligation_id": o.id,
            "stage": o.stage,
            "state": state.value,
            "late_by_hours": (
                round((when - o.due_at).total_seconds() / 3600, 1)
                if state is ObligationState.SUBMITTED_LATE
                else None
            ),
        }


_dispatch.register_mutating("record_vulnerability", record_vulnerability)
_dispatch.register_mutating("update_vulnerability", update_vulnerability)
_dispatch.register_mutating("report_incident", report_incident)
_dispatch.register_mutating("record_report_submission", record_report_submission)
_dispatch.register_read("get_reporting_deadlines", get_reporting_deadlines)
