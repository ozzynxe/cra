"""Producing an SRP-shaped draft from the facts already on record.

`draft_report` never submits. Submission happens on ENISA's platform under the
manufacturer's own EU Login; what this produces is the thing they paste in,
plus an honest account of what is still missing.

The governing constraint is the 24-hour clock. ENISA's own posture on the early
warning is "send what you know, then follow up", so **a draft is always
emitted** — gaps are reported alongside it, never in place of it. A drafting
tool that refuses to produce output because a field is empty has failed at the
one moment it exists for.

Two behaviours come straight from the field markers (see `cra.report_templates`):

- `C` fields are pre-populated from the previous stage's draft, so the 72-hour
  notification is an edit rather than a retype.
- `A` fields are omitted entirely. The platform computes them; showing our own
  value would invite the user to reconcile two numbers.

Each draft is stored as `evidence` and linked from its obligation, because the
technical file is retained ten years and "what did we actually tell the CSIRT
on 14 September" is a question someone will eventually ask.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from cra.agents import dispatch as _dispatch
from cra.db import Evidence, Incident, ReportingObligation, Vulnerability, session_scope
from cra.report_templates import (
    DEFAULT_VERSION,
    Disposition,
    ResolvedField,
    gaps,
    load,
    resolve,
)
from cra.schemas.enums import EvidenceKind, IncidentKind, ReportStage
from cra.server import audit, store_backend
from cra.server.errors import InvalidState, NotFound
from cra.server.reporting import _parse_ts, _require_member
from cra.server.scoping import _member

_STAGE_LABEL = {
    ReportStage.EARLY_WARNING: "24h",
    ReportStage.NOTIFICATION: "72h",
    ReportStage.FINAL: "Final",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _from_record(
    state, incident: Incident, vuln: Optional[Vulnerability]
) -> tuple[dict[str, str], dict[str, str]]:
    """What the record can contribute, split by how much authority it has.

    Returns `(authoritative, seed)`. Only facts already recorded — nothing
    derived, nothing plausible. A field we guess is a field the user will not
    check.

    The split is the whole point. **Authoritative** fields are structured: a
    product name, a CVE id, the date a fix shipped. Correcting the record is
    how you correct them, so a fresh read beats anything an earlier draft
    said. **Seed** fields are prose we can only approximate from the one-line
    description someone typed while the incident was still unfolding. Those
    must lose to a later draft, or the careful narrative written at hour 70
    silently reverts to the terse first guess.
    """
    kind = IncidentKind(incident.kind)
    description = (incident.description or "").strip()

    authoritative: dict[str, Optional[str]] = {
        "1": "Vulnerability" if kind is IncidentKind.ACTIVELY_EXPLOITED_VULN else "Incident",
        "7": state.submitter.legal_name or None,
        "8": state.name,
        "9": (
            state.classification.product_class
            if state.classification.product_class != "unknown"
            else None
        ),
        "10": state.classification.annex_iii_category,
        "11": ", ".join(state.submitter.member_states_available) or None,
    }
    seed: dict[str, Optional[str]] = {
        "12": description.splitlines()[0][:200] if description else None,
    }

    if kind is IncidentKind.ACTIVELY_EXPLOITED_VULN and vuln is not None:
        ident = (vuln.identifier or "").strip()
        authoritative["v13"] = ident if ident.upper().startswith("CVE-") else None
        authoritative["v14"] = ident if ident.upper().startswith("EUVD") else None
        authoritative["v21"] = _iso(incident.corrective_measure_available_at)
        authoritative["v23"] = vuln.cvss_score
        authoritative["v26"] = vuln.remediation_ref
        seed["v16"] = vuln.summary or None
    else:
        authoritative["i13"] = "yes" if kind is IncidentKind.SEVERE_INCIDENT else None
        authoritative["i15"] = _iso(incident.became_aware_at)
        seed["i14"] = description or None

    return (
        {k: v for k, v in authoritative.items() if v},
        {k: v for k, v in seed.items() if v},
    )


def _previous_payload(db: Session, incident_id: str, stage: ReportStage) -> dict[str, str]:
    """The last drafted stage's fields, for carry-forward.

    Walks backwards through the stage order rather than assuming the
    immediately preceding one exists — a team that missed the early warning
    still gets its 72-hour notification pre-populated from whatever was drafted.
    """
    from cra.report_templates import STAGE_ORDER

    earlier = STAGE_ORDER[: STAGE_ORDER.index(stage)]
    for candidate in reversed(earlier):
        ob = db.execute(
            select(ReportingObligation).where(
                ReportingObligation.incident_id == incident_id,
                ReportingObligation.stage == candidate.value,
            )
        ).scalar_one_or_none()
        if ob is None or ob.draft_evidence_id is None:
            continue
        ev = db.get(Evidence, ob.draft_evidence_id)
        if ev is None or not ev.inline_body:
            continue
        try:
            return json.loads(ev.inline_body).get("fields", {})
        except (ValueError, AttributeError):
            continue
    return {}


def _render(resolved: list[ResolvedField], *, stage: ReportStage, version: str) -> str:
    """Markdown mirroring ENISA's table order and wording.

    Empty obligatory fields are rendered as a visible placeholder rather than
    dropped: an incomplete draft that shows its holes is pasteable; one that
    hides them is a trap.
    """
    lines = [
        f"# CRA report — {_STAGE_LABEL[stage]}",
        "",
        f"_Draft for the ENISA Single Reporting Platform. Template {version}. "
        "Not submitted — file this yourself under your EU Login._",
        "",
    ]
    for r in resolved:
        f = r.field
        if f.disposition_at(stage) is Disposition.GUIDANCE:
            lines += [f"> {f.label}", ""]
            continue
        if f.parent:
            lines += [f"**{f.label}**", ""]
            continue

        if r.value:
            suffix = " _(carried forward)_" if r.carried_from_previous else ""
            lines.append(f"- **{f.label}:** {r.value}{suffix}")
        elif r.disposition is Disposition.REQUIRED:
            lines.append(f"- **{f.label}:** ⚠️ REQUIRED — not yet supplied")
        elif r.disposition is Disposition.IF_AVAILABLE:
            lines.append(f"- **{f.label}:** to follow")
        else:
            lines.append(f"- {f.label}: —")
    return "\n".join(lines) + "\n"


def draft_report(
    *,
    product_id: str,
    actor_id: str = "",
    incident_id: str,
    stage: str = ReportStage.EARLY_WARNING.value,
    values: Optional[dict[str, str]] = None,
    template_version: str = DEFAULT_VERSION,
) -> dict:
    """Render the SRP fields for one stage. Always produces a draft."""
    try:
        stage_enum = ReportStage(stage)
    except ValueError as e:
        raise InvalidState(
            f"stage must be one of {[s.value for s in ReportStage]}"
        ) from e

    with session_scope() as db:
        _require_member(db, product_id, actor_id)
        incident = db.get(Incident, incident_id)
        if incident is None or incident.product_id != product_id:
            raise NotFound(f"no incident {incident_id!r} on this product")

        vuln = (
            db.get(Vulnerability, incident.vulnerability_id)
            if incident.vulnerability_id
            else None
        )
        state = store_backend.get_backend().load_state(product_id)

        known, seed = _from_record(state, incident, vuln)
        # Caller-supplied narrative wins over anything we inferred: the human
        # who just lived through the incident knows more than the record does.
        known.update({k: v for k, v in (values or {}).items() if v})
        known["2"] = _STAGE_LABEL[stage_enum]

        resolved = resolve(
            incident.kind,
            stage_enum,
            known=known,
            previous=_previous_payload(db, incident.id, stage_enum),
            fallback=seed,
            version=template_version,
        )
        missing = gaps(resolved)
        fields = {r.field.id: r.value for r in resolved if r.value}
        markdown = _render(resolved, stage=stage_enum, version=template_version)

        payload = {
            "template_version": template_version,
            "stage": stage_enum.value,
            "notification_type": known.get("1"),
            "fields": fields,
            "drafted_at": _now().isoformat(),
        }
        body = json.dumps(payload, indent=2, sort_keys=True)
        evidence = Evidence(
            product_id=product_id,
            subject_ref=f"incident:{incident.id}",
            title=f"SRP {_STAGE_LABEL[stage_enum]} draft — {state.name}",
            kind=EvidenceKind.REPORT_DRAFT.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=hashlib.sha256(body.encode()).hexdigest(),
            source_ref=f"cra-mcp draft_report template={template_version}",
            added_by_user_id=actor_id or None,
        )
        db.add(evidence)
        db.flush()

        obligation = db.execute(
            select(ReportingObligation).where(
                ReportingObligation.incident_id == incident.id,
                ReportingObligation.stage == stage_enum.value,
            )
        ).scalar_one_or_none()
        if obligation is not None:
            obligation.draft_evidence_id = evidence.id

        audit.record(
            db,
            product_id=product_id,
            subject_type="report_draft",
            subject_id=evidence.id,
            op="draft_report",
            accountable_user_id=actor_id or None,
            rationale=f"{_STAGE_LABEL[stage_enum]} draft for incident {incident.id}",
            payload={
                "stage": stage_enum.value,
                "template_version": template_version,
                "missing_required": [r.field.id for r in missing],
            },
            after_hash=evidence.sha256,
        )

        template = load(template_version)
        return {
            "ok": True,
            "stage": stage_enum.value,
            "incident_id": incident.id,
            "evidence_id": evidence.id,
            "template_version": template_version,
            "template_provisional": template.provisional,
            "fields": fields,
            "carried_forward": [
                r.field.id for r in resolved if r.carried_from_previous
            ],
            "missing_required": [
                {"field_id": r.field.id, "label": r.field.label} for r in missing
            ],
            "markdown": markdown,
            "next": (
                "Review, fill any required gaps, and submit it yourself on the "
                "CRA Single Reporting Platform. Then call "
                "record_report_submission() with the reference it gives back — "
                "this tool tracks the clock, it does not submit."
            ),
            "note": (
                "ENISA describes these fields as provisional and the platform "
                "is not yet live, so treat the layout as indicative."
                if template.provisional
                else None
            ),
        }


def set_submitter_profile(
    *,
    product_id: str,
    actor_id: str = "",
    legal_name: Optional[str] = None,
    postal_address: Optional[str] = None,
    member_states_available: Optional[list[str]] = None,
    eu_login_registered: Optional[bool] = None,
    srp_registered: Optional[bool] = None,
    security_contact: Optional[str] = None,
    disclosure_policy_url: Optional[str] = None,
) -> dict:
    """Record who files, and whether they can.

    Kept separate from the product because it answers a different question:
    not "what did we ship" but "who is answerable and are they able to submit".
    """
    def _apply(state, db):
        _member(state, actor_id)

        p = state.submitter
        changed: dict = {}
        for field, value in (
            ("legal_name", legal_name),
            ("postal_address", postal_address),
            ("member_states_available", member_states_available),
            ("eu_login_registered", eu_login_registered),
            ("srp_registered", srp_registered),
            ("security_contact", security_contact),
            ("disclosure_policy_url", disclosure_policy_url),
        ):
            if value is not None:
                setattr(p, field, value)
                changed[field] = value

        # This tool is registered as mutating and wrote no audit row at all —
        # the one rule this repo states outright for every mutation. It records
        # who files to a CSIRT and whether they can, so a silent change to it
        # is precisely the kind an auditor would ask about.
        audit.record(
            db,
            product_id=product_id,
            subject_type="submitter_profile",
            op="set_submitter_profile",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            payload=changed,
        )
        return state, p.model_dump(mode="json")

    submitter = store_backend.mutate(product_id, _apply)

    return {
        "ok": True,
        "product_id": product_id,
        "submitter": submitter,
        "readiness": check_reporting_readiness(
            product_id=product_id, actor_id=actor_id
        )["blockers"],
    }


def check_reporting_readiness(*, product_id: str, actor_id: str = "") -> dict:
    """The things you must not be setting up at hour 3 of a 24-hour clock.

    Preventive by design. EU Login enrolment and SRP registration can both be
    done in advance and neither is fast; discovering them mid-incident is the
    failure this tool exists to stop.
    """
    state = store_backend.get_backend().load_state(product_id)
    _member(state, actor_id)

    p = state.submitter
    blockers: list[dict] = []

    def _block(key: str, why: str, fix: str) -> None:
        blockers.append({"item": key, "why": why, "fix": fix})

    if not p.legal_name:
        _block(
            "legal_name",
            "SRP field 7 is obligatory at the 24-hour stage; without it no "
            "report can be filed.",
            "set_submitter_profile(legal_name=...) with the registered legal "
            "name of the manufacturer or open-source steward.",
        )
    if p.eu_login_registered is not True:
        _block(
            "eu_login",
            "Submission is via EU Login. Enrolment is not instant and cannot "
            "be done inside a 24-hour window.",
            "Register at ecas.ec.europa.eu now, then "
            "set_submitter_profile(eu_login_registered=true).",
        )
    if p.srp_registered is not True:
        _block(
            "srp_registration",
            "The SRP requires the organisation and its products to be "
            "registered before a notification can be submitted.",
            "Register on the CRA Single Reporting Platform, then "
            "set_submitter_profile(srp_registered=true).",
        )
    if not p.member_states_available:
        _block(
            "member_states",
            "SRP field 11 is obligatory if available, and it routes the report "
            "to the right national CSIRT.",
            "set_submitter_profile(member_states_available=['FI', 'SE', ...]).",
        )
    if not p.security_contact:
        _block(
            "security_contact",
            "A published contact point is how exploited-vulnerability reports "
            "reach you at all.",
            "set_submitter_profile(security_contact=...).",
        )

    return {
        "ok": True,
        "product_id": product_id,
        "ready": not blockers,
        "blockers": blockers,
        "summary": (
            "Ready to file."
            if not blockers
            else f"{len(blockers)} thing(s) to sort out before an incident, not during one."
        ),
    }


_dispatch.register_mutating("draft_report", draft_report)
_dispatch.register_mutating("set_submitter_profile", set_submitter_profile)
_dispatch.register_read("check_reporting_readiness", check_reporting_readiness)
