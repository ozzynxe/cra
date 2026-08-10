"""Scanning shipped components for exploited vulnerabilities, and disposing of
what turns up.

This is the only part of the system that can tell a user something they did not
already know, which makes it the only part that can *create* awareness. Article
14's clocks run from awareness, so everything here is arranged around one
question: at what moment did a person learn this, and what did they decide?

    scan_advisories        SBOM → OSV → KEV → candidate rows
    list_advisory_candidates   what is open, exploited first
    confirm_advisory       → a real vulnerability record, clocks anchored on
                             when the tool told you
    dismiss_advisory       → a VEX justification, which is itself evidence

The sweeper (`advisory_sweeper.py`) runs the scan when nobody is asking and
mails the exploited findings. That is the proactive half; these tools are how a
person acts on it.

**Nothing here opens an incident by itself.** A version-range match is not a
finding of fact — vendored patches, unreachable code paths and over-broad
affected ranges all produce false positives, and auto-filing would put spurious
notifications in front of a CSIRT while starting real 24-hour clocks.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from cra.advisories import build_findings, parse
from cra.advisories.feeds import (
    cve_aliases,
    epss_catalogue,
    epss_scores,
    kev_catalogue,
    osv_advisory,
    osv_query,
)
from cra.agents import dispatch as _dispatch
from cra.db import AdvisoryCandidate, AdvisoryScan, Evidence, session_scope
from cra.schemas.enums import Role
from cra.server import audit
from cra.server.errors import InvalidState, NotFound
from cra.server.scoping import _load, _member

log = logging.getLogger(__name__)

# CSAF / CycloneDX VEX "not affected" justifications. Standard vocabulary on
# purpose: a dismissal recorded in these terms is portable evidence an auditor
# or a downstream consumer already understands, rather than a private opinion.
VEX_JUSTIFICATIONS = {
    "component_not_present": "The component is not in the artifact we place on the market.",
    "vulnerable_code_not_present": "The affected code is not in the version we ship.",
    "vulnerable_code_not_in_execute_path": "The affected code ships but cannot be reached.",
    "vulnerable_code_cannot_be_controlled_by_adversary": "Reachable, but not attacker-influenced.",
    "inline_mitigations_already_exist": "A mitigation already prevents exploitation.",
    "false_positive": "The match itself is wrong — wrong package, or the version range overreaches.",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _reopen_rule() -> tuple[float, float]:
    """When a model's change of mind is big enough to disturb a settled answer.

    Returns `(factor, min_rise)`: the **probability** must at least multiply by
    `factor` *and* rise by at least `min_rise` in absolute terms. Defaults 2.0
    and 0.05.

    Probability, not percentile, and that was a correction. Percentile is a
    ranking, and near the top of the distribution it compresses: an advisory
    going from a 5% to a 71% chance of exploitation in the next 30 days moves
    only 0.917 → 0.990 in percentile, because it was already ahead of most
    CVEs. A percentile rule under-fires precisely on the candidates that have
    become most alarming. Probability is the quantity with a meaning of its
    own, so the trigger reads off that and the note shows both.

    Two conditions rather than one because each alone misbehaves at an end of
    the range. A bare ratio fires on 0.0001 → 0.001, which is noise wearing a
    ten-fold increase; a bare absolute rise never fires on 0.001 → 0.09, which
    is a real change. Together: doubled *and* materially higher.

    This is the only number in the EPSS work that looks like a threshold, and
    it is allowed to exist where `list_advisory_candidates` has none because
    **it decides who gets asked, not what is true.** Crossing it re-opens a
    candidate so a person looks again; it marks nothing exploitable, undoes no
    VEX justification, writes no determination. Set it wrong and somebody gets
    a prompt they did not need — the right direction for this to fail in.

    `CRA_EPSS_REOPEN_FACTOR=999` switches the behaviour off without a deploy.
    """

    def _num(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, str(default)))
        except ValueError:
            return default

    return _num("CRA_EPSS_REOPEN_FACTOR", 2.0), _num("CRA_EPSS_REOPEN_MIN_RISE", 0.05)


def scanning_enabled() -> bool:
    """Deployment-level switch.

    Off means no component data leaves the host at all — see the privacy page,
    which names OSV as a processor precisely because this is on.
    """
    return os.environ.get("CRA_ADVISORY_SCAN_ENABLED", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    )


def _latest_sbom(db, product_id: str) -> Optional[Evidence]:
    return db.execute(
        select(Evidence)
        .where(
            Evidence.product_id == product_id,
            Evidence.kind == "sbom",
            Evidence.deleted_at.is_(None),
        )
        .order_by(Evidence.collected_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def scan_product(product_id: str) -> dict:
    """Run one product's SBOM against the feeds and record what is new.

    Returns a summary; never raises for a feed failure. Used by both the tool
    and the sweeper, so there is exactly one implementation of what a scan is.
    """
    with session_scope() as db:
        sbom = _latest_sbom(db, product_id)
        sbom_body = sbom.inline_body if sbom else None
        sbom_ref = sbom.source_ref if sbom else None
        sbom_version = getattr(sbom, "applies_to_version", None) if sbom else None

    if not sbom_body:
        return {
            "ok": True,
            "scanned": False,
            "why": (
                "No SBOM recorded for this product, so there is no component "
                "list to check. record_sbom() first — Annex I Pt II(1) requires "
                "one anyway, and it is what makes this check possible."
            ),
        }

    parsed = parse(sbom_body)
    if not parsed.components:
        return {
            "ok": True,
            "scanned": False,
            "why": (
                f"The stored SBOM parsed as {parsed.format} but yielded no "
                "components with both a version and a supported ecosystem."
            ),
            "coverage": parsed.coverage_note,
        }

    kev = kev_catalogue()
    osv = osv_query(parsed.components)

    details: dict[str, dict] = {}
    for ids in osv.by_component.values():
        for advisory_id in ids:
            if advisory_id not in details:
                details[advisory_id] = osv_advisory(advisory_id) or {}

    # Scores only for the CVEs that actually matched. The feed is mirrored
    # whole, so this is a local filter and no CVE list leaves the host.
    wanted = {c for d in details.values() for c in cve_aliases(d)}
    wanted |= {a.upper() for a in details if a.upper().startswith("CVE-")}
    epss_cat = epss_catalogue()
    epss = epss_scores(wanted) if wanted else {}

    result = build_findings(
        parsed=parsed,
        osv_result=osv,
        kev=kev,
        advisory_details=details,
        epss=epss,
        epss_catalogue=epss_cat,
    )

    new, updated, reopened = _persist(product_id, result)
    _record_scan(product_id, result, sbom_ref, sbom_version)
    return {
        "ok": True,
        "scanned": True,
        "sbom_source_ref": sbom_ref,
        "sbom_applies_to_version": sbom_version,
        "components_checked": result.components_checked,
        "coverage": result.coverage_note,
        "sources_ok": result.sources_ok,
        "kev_ok": result.kev_ok,
        "osv_ok": result.osv_ok,
        # Separate from `sources_ok`: without EPSS the findings are all still
        # here and still right, only less usefully ordered.
        "epss_ok": result.epss_ok,
        "epss_model_version": result.epss_model_version,
        "epss_score_date": result.epss_score_date,
        "epss_scored": sum(1 for f in result.findings if f.epss_percentile is not None),
        "epss_unscored": sum(1 for f in result.findings if f.epss_percentile is None),
        "findings": len(result.findings),
        "exploited": len(result.exploited),
        "new_candidates": new,
        "reopened_or_updated": updated,
        "reopened_on_epss_rise": reopened,
        "summary": result.summary_line(),
        "scoring_note": (
            "EPSS orders the queue; it decides nothing. A percentile is a "
            "prediction about a CVE, not a finding about your product, and an "
            "unscored CVE is unscored — not low-risk. Both numbers are shown "
            "because probability alone misleads: 0.05 sounds negligible and "
            "can be the 92nd percentile."
        ),
    }


def _record_scan(
    product_id: str,
    result,
    sbom_ref: Optional[str],
    sbom_version: Optional[str] = None,
) -> None:
    """Leave a trace that a scan happened, even when it found nothing.

    Especially when it found nothing. `_persist` writes candidate rows, so a
    clean product used to produce silence indistinguishable from a product
    nobody ever scanned — and the Annex I Pt I(2)(a) release gate cannot stand
    on that. "No open candidates" is worth nothing without "and we looked, on
    this date, and the feeds answered".

    Its own transaction, deliberately outside `_persist`. A failure to record
    the scan must not roll back candidates that were genuinely found: losing
    the receipt is bad, losing an exploited finding is worse.
    """
    with session_scope() as db:
        db.add(
            AdvisoryScan(
                product_id=product_id,
                sources_ok=result.sources_ok,
                kev_ok=result.kev_ok,
                osv_ok=result.osv_ok,
                epss_ok=result.epss_ok,
                components_checked=result.components_checked,
                findings=len(result.findings),
                exploited=len(result.exploited),
                sbom_source_ref=sbom_ref,
                sbom_applies_to_version=sbom_version,
            )
        )


def latest_scan(db, product_id: str):
    """The most recent scan for a product, or None. Used by the release gate."""
    return db.execute(
        select(AdvisoryScan)
        .where(AdvisoryScan.product_id == product_id)
        .order_by(AdvisoryScan.ran_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def open_candidate_counts(db, product_id: str) -> tuple[int, int]:
    """`(open, exploited_open)` — what the release gate has to weigh."""
    rows = list(
        db.execute(
            select(AdvisoryCandidate).where(
                AdvisoryCandidate.product_id == product_id,
                AdvisoryCandidate.status == "open",
            )
        ).scalars()
    )
    return len(rows), sum(1 for r in rows if r.exploited)


def _persist(product_id: str, result) -> tuple[int, int, int]:
    """Upsert findings as candidates. Decisions already made are preserved.

    A dismissal must survive the next nightly scan — re-raising something a
    human already ruled out trains them to ignore the alerts, which is the one
    outcome that makes this feature worse than not having it. The exception is
    exploitation status: if CISA starts listing something previously dismissed,
    that is genuinely new information and the candidate is flagged again.

    Note what a dismissal actually is. The VEX justifications are statements
    that a vulnerability lacks "the potential to be effectively used by an
    adversary under practical operational conditions" — which is Art 3(41)'s
    definition of *exploitable* almost word for word. So dismissing a candidate
    is an exploitability determination under Annex I Pt I(2)(a), not merely
    triage, and it is the record that a product was placed on the market
    without a known exploitable vulnerability.
    """
    new = updated = reopened_on_epss = 0
    factor, min_rise = _reopen_rule()
    with session_scope() as db:
        for f in result.findings:
            row = db.execute(
                select(AdvisoryCandidate).where(
                    AdvisoryCandidate.product_id == product_id,
                    AdvisoryCandidate.advisory_id == f.advisory_id,
                    AdvisoryCandidate.component_name == f.component_name,
                    AdvisoryCandidate.component_version == f.component_version,
                )
            ).scalar_one_or_none()

            if row is None:
                db.add(
                    AdvisoryCandidate(
                        product_id=product_id,
                        advisory_id=f.advisory_id,
                        cve_ids=f.cve_ids,
                        summary=f.summary,
                        severity=f.severity,
                        component_name=f.component_name,
                        component_version=f.component_version,
                        component_ecosystem=f.component_ecosystem,
                        component_purl=f.component_purl,
                        exploited=f.exploited,
                        kev_cve_id=f.kev_cve_id,
                        kev_date_added=f.kev_date_added,
                        epss_probability=f.epss_probability,
                        epss_percentile=f.epss_percentile,
                        epss_model_version=result.epss_model_version,
                        epss_score_date=result.epss_score_date,
                    )
                )
                new += 1
                continue

            # Refresh the score on every scan — it is a daily model output, and
            # a stale number beside a live decision is worse than none. Only
            # when the feed actually answered, though: a scoring outage must not
            # blank a score that was there yesterday.
            materially_riskier = False
            if f.epss_probability is not None:
                was = row.epss_probability_at_decision
                if was is not None:
                    materially_riskier = (
                        f.epss_probability >= was * factor
                        and f.epss_probability - was >= min_rise
                    )
                row.epss_probability = f.epss_probability
                row.epss_percentile = f.epss_percentile
                row.epss_model_version = result.epss_model_version
                row.epss_score_date = result.epss_score_date

            became_exploited = f.exploited and not row.exploited
            if became_exploited:
                row.exploited = True
                row.kev_cve_id = f.kev_cve_id
                row.kev_date_added = f.kev_date_added
                # Newly exploited is new information even about a dismissed
                # finding: re-open it and let it be notified again.
                if row.status == "dismissed":
                    row.status = "open"
                    row.disposition_note = (
                        (row.disposition_note or "")
                        + " [re-opened: CISA subsequently listed this as exploited]"
                    ).strip()
                row.notified_at = None
                updated += 1
                continue

            # A dismissal is an exploitability determination under Art 3(41),
            # and it was made against the likelihood as it stood that day. When
            # the model moves that far, the determination deserves a second
            # look — so this re-opens the question and never answers it. The
            # note records both numbers precisely so the reader can judge
            # whether the rise means anything, rather than trusting the
            # threshold that surfaced it.
            if row.status == "dismissed" and materially_riskier:
                was_p = row.epss_probability_at_decision
                was_pct = row.epss_percentile_at_decision
                row.status = "open"
                row.disposition_note = (
                    (row.disposition_note or "")
                    + f" [re-opened: EPSS now puts this at {f.epss_probability:.1%} "
                    f"chance of exploitation in the next 30 days, up from "
                    f"{was_p:.1%} when it was dismissed"
                    + (
                        f" (percentile {was_pct:.3f} to {f.epss_percentile:.3f})"
                        if was_pct is not None and f.epss_percentile is not None
                        else ""
                    )
                    + ". That is a change in predicted likelihood, not a finding "
                    "that the product is affected — re-check, and dismiss again "
                    "if the original reasoning still holds.]"
                ).strip()
                row.notified_at = None
                reopened_on_epss += 1
                updated += 1
                log.info(
                    "advisory %s on product %s re-opened: EPSS probability %.5f -> %.5f",
                    row.advisory_id,
                    product_id,
                    was_p,
                    f.epss_probability,
                )
    return new, updated, reopened_on_epss


def _view(row: AdvisoryCandidate) -> dict:
    return {
        "candidate_id": row.id,
        "advisory_id": row.advisory_id,
        "cve_ids": row.cve_ids or [],
        "component": f"{row.component_name}@{row.component_version}",
        "ecosystem": row.component_ecosystem,
        "purl": row.component_purl,
        "summary": row.summary,
        "severity": row.severity,
        "actively_exploited": row.exploited,
        "kev_cve_id": row.kev_cve_id,
        "kev_date_added": row.kev_date_added,
        # Both numbers or neither, and `null` reads as unscored. `epss` stays
        # absent rather than zeroed when the model has nothing, so a consumer
        # that forgets to check cannot accidentally render "0%".
        "epss": (
            {
                "probability": row.epss_probability,
                "percentile": row.epss_percentile,
                "model_version": row.epss_model_version,
                "score_date": row.epss_score_date,
                "reading": (
                    f"{row.epss_probability:.1%} chance of exploitation in the "
                    f"next 30 days — {row.epss_percentile:.1%} of scored CVEs "
                    f"rank at or below this."
                ),
            }
            if row.epss_percentile is not None and row.epss_probability is not None
            else None
        ),
        "epss_unscored_reason": (
            None
            if row.epss_percentile is not None
            else "EPSS has not scored this CVE. That is not a low score."
        ),
        "status": row.status,
        "disposition": row.disposition,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "notified_at": row.notified_at.isoformat() if row.notified_at else None,
        "vulnerability_id": row.vulnerability_id,
    }


# ---- tools -------------------------------------------------------------------


def scan_advisories(*, product_id: str, actor_id: str = "") -> dict:
    """Check the product's SBOM against OSV and CISA KEV now."""
    state = _load(product_id)
    _member(state, actor_id, minimum=Role.EDITOR)
    if not scanning_enabled():
        raise InvalidState(
            "advisory scanning is disabled on this deployment "
            "(CRA_ADVISORY_SCAN_ENABLED=0), so no component data is sent "
            "anywhere. Nothing was checked."
        )
    out = scan_product(product_id)
    if out.get("scanned") and out.get("exploited"):
        out["next"] = (
            "list_advisory_candidates(filter='exploited') and work through them. "
            "Confirming one records an actively exploited vulnerability and "
            "starts the Article 14 clocks."
        )
    return out


def list_advisory_candidates(
    *,
    product_id: str,
    actor_id: str = "",
    filter: str = "open",
) -> dict:
    """Candidates for this product. Exploited first, always."""
    allowed = {"open", "exploited", "confirmed", "dismissed", "all"}
    if filter not in allowed:
        raise InvalidState(f"filter must be one of {sorted(allowed)}")

    state = _load(product_id)
    _member(state, actor_id)

    with session_scope() as db:
        q = select(AdvisoryCandidate).where(AdvisoryCandidate.product_id == product_id)
        if filter == "open":
            q = q.where(AdvisoryCandidate.status == "open")
        elif filter == "exploited":
            q = q.where(
                AdvisoryCandidate.status == "open", AdvisoryCandidate.exploited.is_(True)
            )
        elif filter in ("confirmed", "dismissed"):
            q = q.where(AdvisoryCandidate.status == filter)
        rows = list(
            db.execute(
                q.order_by(
                    # Statutory duty first, always. A prediction never outranks
                    # observed exploitation, however high it scores.
                    AdvisoryCandidate.exploited.desc(),
                    # Then most likely first. NULLS LAST is the whole point:
                    # unscored CVEs must not sort as though they scored zero,
                    # so they land after the scored ones rather than at the
                    # bottom looking negligible.
                    AdvisoryCandidate.epss_percentile.desc().nullslast(),
                    AdvisoryCandidate.first_seen_at.desc(),
                )
            ).scalars()
        )
        views = [_view(r) for r in rows]

    exploited_open = [v for v in views if v["actively_exploited"] and v["status"] == "open"]
    return {
        "ok": True,
        "count": len(views),
        "candidates": views,
        "exploited_open": len(exploited_open),
        "note": (
            "A candidate is a match between an advisory and a version string in "
            "your SBOM. It is not a finding that your product is affected — "
            "confirm or dismiss each one. Dismissing with a justification is "
            "itself Annex I Pt II(2) evidence."
        ),
        "two_duties": (
            "`actively_exploited` marks the Article 14 set: Art 3(42), reliable "
            "evidence a malicious actor has used it. Those carry a 24-hour "
            "reporting clock. The rest are not thereby harmless — Annex I Pt "
            "I(2)(a) bars placing a product on the market with a known "
            "*exploitable* vulnerability, which Art 3(41) defines as having the "
            "potential to be effectively used by an adversary under practical "
            "operational conditions. That is the broader set, and it is a "
            "release question rather than a reporting one. Working only the "
            "exploited ones answers one duty and drops the other."
        ),
        "not_a_clean_bill": (
            "An empty list means these feeds know of nothing today. It is not a "
            "statement that the product has no exploitable vulnerabilities."
        ),
        "on_epss": (
            "Ordering below the exploited set is by EPSS percentile: the "
            "model's predicted probability of exploitation in the next 30 "
            "days, and where that sits among all scored CVEs. There is no "
            "threshold and no cutoff, because any cutoff is a compliance "
            "policy rather than a fact — the ordering is a reading aid, and "
            "every candidate still needs a determination. Read both numbers: "
            "0.05 probability sounds negligible and can be the 92nd "
            "percentile. Where `epss` is null the model has not scored that "
            "CVE, which is unknown and not low. EPSS is never on its own a "
            "reason to dismiss — a dismissal still needs a VEX justification "
            "about *your product*."
        ),
    }


def confirm_advisory(
    *,
    product_id: str,
    actor_id: str = "",
    candidate_id: str,
    rationale: str = "",
    became_aware_at: Optional[str] = None,
    summary: Optional[str] = None,
) -> dict:
    """Accept a candidate as a real vulnerability in this product.

    For an exploited candidate this is the act that starts the Article 14
    clocks, so awareness defaults to `notified_at` — when the tool told you —
    rather than now. Filing from the later timestamp would understate how long
    you have known, which is the error the anchor work exists to prevent.
    """
    if not rationale.strip():
        raise InvalidState(
            "rationale is required: say what you checked to conclude the "
            "product is affected. A feed match is not that check, and for an "
            "exploited advisory this call starts a statutory clock."
        )

    state = _load(product_id)
    _member(state, actor_id, minimum=Role.EDITOR)

    with session_scope() as db:
        row = db.get(AdvisoryCandidate, candidate_id)
        if row is None or row.product_id != product_id:
            raise NotFound(f"no advisory candidate {candidate_id!r} on this product")
        if row.status == "confirmed":
            return {
                "ok": True,
                "already_confirmed": True,
                "vulnerability_id": row.vulnerability_id,
            }
        snapshot = _view(row)
        anchor = row.notified_at or row.first_seen_at
        exploited = row.exploited

    from cra.server import reporting  # local: avoids an import cycle

    aware = became_aware_at or (anchor.isoformat() if anchor else None)
    created = reporting.record_vulnerability(
        product_id=product_id,
        actor_id=actor_id,
        summary=summary or f"{snapshot['advisory_id']}: {snapshot['summary']}"[:500],
        identifier=(snapshot["cve_ids"] or [snapshot["advisory_id"]])[0],
        affected_component=snapshot["purl"] or snapshot["component"],
        actively_exploited=exploited,
        became_aware_at=aware,
        source="cisa-kev/osv",
    )

    with session_scope() as db:
        row = db.get(AdvisoryCandidate, candidate_id)
        row.status = "confirmed"
        row.decided_by = actor_id or None
        row.decided_at = _now()
        row.disposition_note = rationale.strip()
        row.vulnerability_id = created.get("vulnerability_id")
        audit.record(
            db,
            product_id=product_id,
            subject_type="advisory_candidate",
            subject_id=candidate_id,
            op="confirm_advisory",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=rationale.strip()[:500],
            payload={
                "advisory_id": snapshot["advisory_id"],
                "component": snapshot["component"],
                "actively_exploited": exploited,
                "became_aware_at": aware,
                "vulnerability_id": created.get("vulnerability_id"),
            },
        )

    created["confirmed_from_candidate"] = candidate_id
    if exploited:
        created["awareness_note"] = (
            f"Clocks anchored at {aware} — when this service notified you, not "
            "when you confirmed. If you can evidence that you could not "
            "reasonably have known until later, correct it with "
            "update_vulnerability(became_aware_at=..., awareness_rationale=...)."
        )

    # What this call just asserted, and on what.
    #
    # This is the one door between a candidate and a record. `list_advisory_
    # candidates` insists a candidate is "a match between an advisory and a
    # version string in the SBOM — not a finding that the product is affected",
    # and the refusal above says a feed match is not the check. An end-to-end run
    # was refused for an empty rationale, answered "the scanner found it", and
    # was accepted — so the record now held a human determination, an open
    # incident and a 24-hour clock resting on the thing the refusal had just
    # ruled out, with nothing in the response marking it apart from a
    # determination somebody made.
    #
    # Surfaced, not judged. No mechanical test reads a sentence, and a length
    # rule that refused would teach the next caller to pad — the line already
    # taken for Annex I justifications and the 13(3) statements. What changes is
    # that the assertion and what it rests on arrive together, at the moment it
    # becomes a legal deadline.
    from cra.server.conformity import _THIN_JUSTIFICATION_CHARS  # local: cycle

    reason = rationale.strip()
    created["recorded_determination"] = (
        f"You have recorded that this product is affected by "
        f"{snapshot['advisory_id']}, on the stated basis: {reason!r}. That is a "
        "human determination, attributed to you in the audit trail"
        + (
            ", and it opened an incident and started the Article 14 clocks above."
            if exploited
            else "."
        )
        + " A feed match is not that determination — it is a match between an "
        "advisory and a version string in your bill of materials. What makes it "
        "one is knowing the version you actually ship, whether the vulnerable "
        "code path is reachable, and how it is configured."
    )
    if len(reason) < _THIN_JUSTIFICATION_CHARS:
        created["review_this_reason"] = (
            f"The basis recorded is {len(reason)} characters: {reason!r}. It is "
            "kept as written and this is not a refusal — but it is what an "
            "auditor reads when asking why this product was reported as "
            "affected, and it is what a CSIRT was notified on. Add to it with "
            "update_vulnerability(awareness_rationale=...) if there is more."
        )
    return created


def dismiss_advisory(
    *,
    product_id: str,
    actor_id: str = "",
    candidate_id: str,
    justification: str,
    note: str = "",
) -> dict:
    """Rule a candidate out, in VEX terms, with the reasoning recorded."""
    if justification not in VEX_JUSTIFICATIONS:
        raise InvalidState(
            "justification must be one of "
            f"{sorted(VEX_JUSTIFICATIONS)} — these are the standard VEX "
            "'not affected' categories, so the reasoning is portable to anyone "
            "who consumes your advisories."
        )
    if not note.strip():
        raise InvalidState(
            "note is required: the category says which kind of reason, the note "
            "says why it is true here. An auditor reads the second one."
        )

    state = _load(product_id)
    _member(state, actor_id, minimum=Role.EDITOR)

    with session_scope() as db:
        row = db.get(AdvisoryCandidate, candidate_id)
        if row is None or row.product_id != product_id:
            raise NotFound(f"no advisory candidate {candidate_id!r} on this product")
        if row.status == "confirmed":
            raise InvalidState(
                "this candidate was already confirmed as a vulnerability. "
                "Dismissing it now would leave the vulnerability record without "
                "its basis — close the vulnerability instead."
            )
        row.status = "dismissed"
        row.disposition = justification
        row.disposition_note = note.strip()
        row.decided_by = actor_id or None
        row.decided_at = _now()
        # Pin the likelihood this judgement was made against. `epss_percentile`
        # is overwritten by every scan, so without this there is nothing to
        # measure a later rise from — and "the model has changed its mind since
        # you ruled this out" is the only thing that should disturb a
        # settled dismissal short of a KEV listing.
        row.epss_probability_at_decision = row.epss_probability
        row.epss_percentile_at_decision = row.epss_percentile
        was_exploited = row.exploited
        epss_at_decision = row.epss_probability
        epss_pct_at_decision = row.epss_percentile
        snapshot = _view(row)

        audit.record(
            db,
            product_id=product_id,
            subject_type="advisory_candidate",
            subject_id=candidate_id,
            op="dismiss_advisory",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=note.strip()[:500],
            payload={
                "advisory_id": snapshot["advisory_id"],
                "component": snapshot["component"],
                "justification": justification,
                "was_actively_exploited": was_exploited,
                # On the audit row because this is the fact that explains a
                # later re-open, and the trail is what has to make sense years
                # from now.
                "epss_probability_at_decision": epss_at_decision,
                "epss_percentile_at_decision": epss_pct_at_decision,
            },
        )

    out = {
        "ok": True,
        "candidate": snapshot,
        "justification": justification,
        "means": VEX_JUSTIFICATIONS[justification],
        "evidence_note": (
            "Recorded as a VEX-style disposition. Handling a vulnerability and "
            "documenting why it does not affect the product is Annex I Pt II(2) "
            "work — this is evidence of it, not an absence of it."
        ),
    }
    if epss_at_decision is not None:
        out["epss_watch"] = (
            f"Dismissed while EPSS put this at {epss_at_decision:.1%} chance of "
            f"exploitation in the next 30 days"
            + (
                f" (percentile {epss_pct_at_decision:.3f})"
                if epss_pct_at_decision is not None
                else ""
            )
            + ". If the model raises that materially, the candidate re-opens "
            "for a second look. EPSS played no part in this dismissal being "
            "accepted: the VEX justification is a statement about your product, "
            "and a likelihood score about a CVE cannot make one."
        )
    if was_exploited:
        out["care"] = (
            "This advisory is on CISA's exploited list. Dismissing it is a "
            "statement that your product is not affected despite that — make "
            "sure the note would satisfy someone reading it after an incident."
        )
    return out


_dispatch.register_mutating("scan_advisories", scan_advisories)
_dispatch.register_read("list_advisory_candidates", list_advisory_candidates)
_dispatch.register_mutating("confirm_advisory", confirm_advisory)
_dispatch.register_mutating("dismiss_advisory", dismiss_advisory)
