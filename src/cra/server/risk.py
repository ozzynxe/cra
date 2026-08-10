"""The Article 13(2) cybersecurity risk assessment.

This is the first thing that should happen after a product is found to be in
scope, because it is what everything in Annex I Part I is judged against.
Article 13(2) requires the manufacturer to assess the product's cybersecurity
risks; Annex I Part I applies "on the basis of" that assessment; Annex VII(3)
requires it in the technical file; Article 13(3) requires it kept up to date.
Answering the checklist first and assessing risk afterwards inverts the
regulation's own order, and produces applicability determinations resting on
nothing.

## The shape

    start_risk_assessment   → the Article 13(2) input frame + the Part I
                              requirements to map risks onto
    propose_risks           → the agent drafts; NOTHING is determined
    decide_risk             → a human accepts / rejects, with a rationale
    confirm_risk_assessment → freezes a hashed version, and only then sets
                              requirement applicability

## Why the drafting happens in the caller's agent

The agent invoking this connector is already sitting in the user's repository
with the code, the SBOM, the dependency graph and the architecture in context.
A model called server-side would see four free-text fields off the product row
and nothing else. So `start_risk_assessment` returns a worksheet rather than
prose, and the drafting model is the one that already has the material.

## The two rules that are not conveniences

**A proposal determines nothing.** Risks arrive `proposed`, carrying the model
that drafted them. Only `decide_risk` — an explicit, separately recorded act by
an accountable account, with a rationale — moves one to `accepted`, and only
accepted risks affect the checklist. The tool cannot verify a human typed the
second call, but it can insist that drafting and deciding are two recorded acts
by an identified account rather than one, and that the audit trail distinguishes
them.

**Confirming never marks anything `not_applicable`.** It marks requirements
named by accepted risks as `applicable`, and leaves everything else
`undetermined` — which still reads as a gap. The failure mode this exists to
prevent is an AI-drafted assessment quietly ruling most of Part I out: an
auditor reads a justification, and "the model did not mention it" is not one.
Ruling a requirement out stays a deliberate human act via
`update_requirement`.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from cra.agents import dispatch as _dispatch
from cra.db import session_scope
from cra.regulation import provenance, requirements
from cra.schemas import RiskAssessment, RiskItem
from cra.schemas.enums import (
    Applicability,
    AssessmentStatus,
    EvidenceKind,
    Lifecycle,
    RiskLikelihood,
    RiskSeverity,
    RiskStatus,
    RiskTreatment,
    Role,
)
from cra.server import audit, entitlements, store_backend
from cra.server.errors import InvalidState, NotFound
from cra.server.scoping import _load, _member

_CATALOGUE = {r.id: r for r in requirements()}
_PART_I = tuple(r for r in requirements() if r.part == "part_i")
_PART_II = tuple(r for r in requirements() if r.part == "part_ii")

# Guards against a model emitting an unbounded list. Generous enough that a
# real assessment never hits them; low enough that a runaway loop does.
_MAX_PER_CALL = 50
_MAX_TOTAL = 200

_DISCLAIMER = (
    "A risk assessment recorded here is the manufacturer's own. This tool "
    "structures and retains it; it does not perform or validate the "
    "assessment, and it cannot determine that the resulting decisions are "
    "adequate."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---- derivation (pure, no I/O) ------------------------------------------------


# The one lifecycle move that does not stale an assessment.
#
# `record_release` sets `placed_on_market`, which is the first time anything in
# this codebase writes `lifecycle` at all. Without this exemption, recording a
# first release would immediately report the assessment as no longer describing
# the product and demand a re-confirm — at the precise moment someone is
# shipping, and for a transition that was always the expected destination. The
# assessment was made *in order to* place the product on the market; arriving
# there does not invalidate it.
#
# Deliberately one pair and not a general "forward transitions are fine" rule.
# `placed_on_market → withdrawn`, or a move into `support_period_ended`, change
# which obligations are live and *should* prompt a fresh look.
_EXPECTED_LIFECYCLE_STEPS = {
    (Lifecycle.IN_DEVELOPMENT.value, Lifecycle.PLACED_ON_MARKET.value),
}


def staleness(state) -> list[dict]:
    """Reasons the confirmed assessment no longer describes the product.

    Derived, never stored — the same discipline as `deadlines.obligation_state`.
    A persisted `stale` flag flipped by some future sweeper would let an
    assessment that nobody updated keep looking current, which is the exact
    failure Article 13(3) is about.

    Returns an empty list when there is nothing to compare against: an
    assessment that was never confirmed is not stale, it is absent, and the
    caller must not conflate the two.
    """
    ra = state.risk_assessment
    if ra is None or not ra.content_hash:
        return []

    out: list[dict] = []
    current_class = state.classification.product_class
    if ra.basis_product_class and ra.basis_product_class != current_class:
        out.append(
            {
                "reason": "classification_changed",
                "detail": (
                    f"assessed as {ra.basis_product_class}, now recorded as "
                    f"{current_class} — the class changes the conformity route "
                    "and can change which requirements apply"
                ),
            }
        )
    if (
        ra.basis_lifecycle
        and ra.basis_lifecycle != state.lifecycle
        and (ra.basis_lifecycle, state.lifecycle) not in _EXPECTED_LIFECYCLE_STEPS
    ):
        out.append(
            {
                "reason": "lifecycle_changed",
                "detail": (
                    f"assessed while {ra.basis_lifecycle}, now {state.lifecycle}"
                ),
            }
        )
    if ra.status == AssessmentStatus.DRAFT:
        undecided = sum(1 for r in ra.risks if r.status == RiskStatus.PROPOSED)
        out.append(
            {
                "reason": "revision_in_progress",
                "detail": (
                    f"version {ra.version} is a draft with {undecided} risk(s) "
                    f"still undecided; the frozen copy is version "
                    f"{ra.version - 1}"
                ),
            }
        )
    return out


def _accepted(ra: RiskAssessment) -> list[RiskItem]:
    return [r for r in ra.risks if r.status == RiskStatus.ACCEPTED]


def apply_to_requirements(state, accepted: list[RiskItem]) -> dict:
    """Set applicability from accepted risks. Pure — mutates `state` only.

    Three outcomes are reported separately because they mean different things
    to whoever reads the result:

      `made_applicable` — a requirement now has a risk basis it did not have.
      `reopened`        — it had been ruled out, and an accepted risk now says
                          otherwise. The stale justification is cleared and the
                          conflict is surfaced loudly; silently keeping either
                          side would leave the file self-contradictory.
      `still_undetermined` — Part I requirements no accepted risk named. These
                          are NOT ruled out. They are unanswered, they remain
                          gaps, and each needs a deliberate decision.
    """
    by_req: dict[str, list[str]] = {}
    for risk in accepted:
        for req_id in risk.affects_requirements:
            by_req.setdefault(req_id, []).append(risk.risk_id)

    made_applicable: list[dict] = []
    reopened: list[dict] = []

    for item in state.requirements:
        risk_ids = by_req.get(item.req_id)
        if not risk_ids:
            continue
        was = item.applicability
        merged = sorted(set(item.risk_basis) | set(risk_ids))
        changed_basis = merged != sorted(item.risk_basis)
        item.risk_basis = merged

        if was == Applicability.NOT_APPLICABLE:
            reopened.append(
                {
                    "req_id": item.req_id,
                    "was_justified_as": item.justification,
                    "risk_basis": risk_ids,
                }
            )
            item.justification = ""
        if was != Applicability.APPLICABLE:
            item.applicability = Applicability.APPLICABLE
            made_applicable.append({"req_id": item.req_id, "risk_basis": risk_ids})
        elif changed_basis:
            made_applicable.append({"req_id": item.req_id, "risk_basis": risk_ids})

    have = {i.req_id: i for i in state.requirements}
    still_undetermined = [
        r.id
        for r in _PART_I
        if r.id in have and have[r.id].applicability == Applicability.UNDETERMINED
    ]
    return {
        "made_applicable": made_applicable,
        "reopened": reopened,
        "still_undetermined": still_undetermined,
    }


# ---- helpers ------------------------------------------------------------------


def _require_assessable(state):
    """The assessment only exists for a product the CRA actually covers."""
    if state.classification.in_scope is None:
        raise InvalidState(
            "classification is undetermined, so there is nothing to assess "
            "against yet. Run classify_product() first — the class decides the "
            "conformity route, and the risk assessment is performed for a "
            "product of a known class."
        )
    if state.classification.in_scope is False:
        raise InvalidState(
            "this product is recorded as out of scope, so Article 13(2) does "
            "not bite. If that is wrong, re-run classify_product(in_scope=true) "
            "with a rationale."
        )


def _ensure_draft(state, actor_id: str) -> tuple[RiskAssessment, Optional[int]]:
    """Return an editable assessment, opening the next version if needed.

    Editing a confirmed assessment is the normal case, not an error — Article
    13(3) requires it kept up to date. The previous version stays frozen in
    `evidence`, and `content_hash` keeps pointing at it so the technical file
    still has a confirmed assessment to cite while the revision is in flight.
    Returns the version that was opened, or None if nothing changed.
    """
    ra = state.risk_assessment
    if ra is None:
        state.risk_assessment = RiskAssessment(
            started_at=_now(), started_by=actor_id or None
        )
        return state.risk_assessment, None
    if ra.status == AssessmentStatus.CONFIRMED:
        # Reopening a confirmed assessment starts a new revision of a frozen
        # artefact. Refuse before touching `ra`, not after: this is called by
        # propose_risks, decide_risk and confirm_risk_assessment alike, and a
        # half-opened version would leave the frozen copy looking superseded by
        # a draft that does not exist.
        entitlements.require(
            actor_id,
            entitlements.REASSESSMENT,
            what=(
                f"Reopening the confirmed assessment as version {ra.version + 1} "
                "would have started a revision."
            ),
        )
        ra.version += 1
        ra.status = AssessmentStatus.DRAFT
        ra.confirmation_rationale = ""
        return ra, ra.version
    return ra, None


def _next_risk_id(ra: RiskAssessment) -> str:
    used = 0
    for r in ra.risks:
        _, _, tail = r.risk_id.partition("-")
        if tail.isdigit():
            used = max(used, int(tail))
    return f"risk-{used + 1:03d}"


def _find_risk(ra: RiskAssessment, risk_id: str) -> RiskItem:
    for r in ra.risks:
        if r.risk_id == risk_id:
            return r
    raise NotFound(
        f"no risk {risk_id!r} on this assessment. "
        "get_risk_assessment() lists them with their ids."
    )


def _risk_view(r: RiskItem, *, verbose: bool = False) -> dict:
    out = {
        "risk_id": r.risk_id,
        "title": r.title,
        "status": r.status,
        "severity": r.severity,
        "likelihood": r.likelihood,
        "treatment": r.treatment,
        "affects_requirements": list(r.affects_requirements),
        # Provenance travels with the risk, not just in the audit trail: a
        # reviewer scanning the list should see which entries a model drafted.
        "proposed_by_kind": r.proposed_by_kind,
        "proposed_by_model": r.proposed_by_model,
        "decided_by": r.decided_by,
    }
    if verbose:
        out.update(
            description=r.description,
            asset=r.asset,
            threat=r.threat,
            attack_vector=r.attack_vector,
            preconditions=r.preconditions,
            impact=r.impact,
            mitigation_note=r.mitigation_note,
            residual_note=r.residual_note,
            decision_rationale=r.decision_rationale,
            evidence_ids=list(r.evidence_ids),
            proposed_at=r.proposed_at.isoformat() if r.proposed_at else None,
            decided_at=r.decided_at.isoformat() if r.decided_at else None,
        )
    return out


def _assessment_view(state, *, verbose: bool = False) -> dict:
    ra = state.risk_assessment
    if ra is None:
        return {
            "present": False,
            "why_it_matters": (
                "Annex I Part I requirements apply on the basis of the Article "
                "13(2) risk assessment, and Annex VII(3) requires it in the "
                "technical file. Without one, every applicability decision "
                "rests on nothing."
            ),
            "next": "start_risk_assessment(product_id)",
        }
    counts: dict[str, int] = {}
    for r in ra.risks:
        counts[r.status] = counts.get(r.status, 0) + 1
    stale = staleness(state)
    return {
        "present": True,
        "version": ra.version,
        "status": ra.status,
        "method": ra.method,
        "risks": counts,
        "total_risks": len(ra.risks),
        "confirmed_at": ra.confirmed_at.isoformat() if ra.confirmed_at else None,
        "confirmed_by": ra.confirmed_by,
        "content_hash": ra.content_hash,
        "stale": bool(stale),
        "stale_reasons": stale,
    }


def _frozen_body(state, ra: RiskAssessment) -> str:
    """The bytes a confirmation hashes, and what the technical file cites."""
    payload = {
        "product_id": state.product_id,
        "product_name": state.name,
        "product_class": state.classification.product_class,
        "version": ra.version,
        "method": ra.method,
        "scope": {
            "intended_purpose": ra.intended_purpose,
            "foreseeable_misuse": ra.foreseeable_misuse,
            "conditions_of_use": ra.conditions_of_use,
            "support_duration_note": ra.support_duration_note,
            "scope_note": ra.scope_note,
        },
        # Article 13(3)'s last sentence, inside the hashed body because it is
        # part of the assessment the technical file cites — not metadata about
        # it. An auditor reading Annex VII(3) should find all of 13(3) in the
        # frozen artefact, not two thirds of it.
        "how_applied": {
            "annex_i_part_i_1": ra.part_i_1_approach,
            "annex_i_part_ii": ra.part_ii_approach,
        },
        "risks": [
            {
                "risk_id": r.risk_id,
                "title": r.title,
                "description": r.description,
                "asset": r.asset,
                "threat": r.threat,
                "attack_vector": r.attack_vector,
                "preconditions": r.preconditions,
                "impact": r.impact,
                "severity": r.severity,
                "likelihood": r.likelihood,
                "treatment": r.treatment,
                "mitigation_note": r.mitigation_note,
                "residual_note": r.residual_note,
                "affects_requirements": sorted(r.affects_requirements),
                "status": r.status,
                "proposed_by_kind": r.proposed_by_kind,
                "proposed_by_model": r.proposed_by_model,
                "decided_by": r.decided_by,
                "decision_rationale": r.decision_rationale,
            }
            # Rejected risks are retained in the frozen copy on purpose: "we
            # considered this and ruled it out, for this reason" is evidence of
            # a thorough assessment. Dropping them makes the file look like
            # nothing was ever discarded.
            for r in sorted(ra.risks, key=lambda x: x.risk_id)
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


# ---- tools --------------------------------------------------------------------


def start_risk_assessment(
    *,
    product_id: str,
    actor_id: str = "",
    method: Optional[str] = None,
    intended_purpose: Optional[str] = None,
    foreseeable_misuse: Optional[str] = None,
    conditions_of_use: Optional[str] = None,
    support_duration_note: Optional[str] = None,
    scope_note: Optional[str] = None,
    part_i_1_approach: Optional[str] = None,
    part_ii_approach: Optional[str] = None,
) -> dict:
    """Open (or update the scope of) the Article 13(2) assessment.

    `part_i_1_approach` and `part_ii_approach` are Article 13(3)'s last
    sentence: the assessment must *also* indicate how Annex I Part I(1) — an
    appropriate level of cybersecurity based on the risks — and the Part II
    vulnerability handling requirements are applied. Neither is a per-risk
    determination, which is why neither falls out of the risk list; both are
    statements of approach about the whole product, and both are required
    before the assessment can be confirmed.
    """
    def _apply(state, db):
        _member(state, actor_id, minimum=Role.EDITOR)
        _require_assessable(state)

        ra, opened_version = _ensure_draft(state, actor_id)
        changed: dict = {}
        for field, value in (
            ("method", method),
            ("intended_purpose", intended_purpose),
            ("foreseeable_misuse", foreseeable_misuse),
            ("conditions_of_use", conditions_of_use),
            ("support_duration_note", support_duration_note),
            ("scope_note", scope_note),
            ("part_i_1_approach", part_i_1_approach),
            ("part_ii_approach", part_ii_approach),
        ):
            if value is not None:
                setattr(ra, field, value.strip())
                changed[field] = value.strip()

        # Seed the two scope fields the product row already answers, so the
        # agent is not made to re-ask what the user has already said.
        if not ra.intended_purpose and state.intended_use:
            ra.intended_purpose = state.intended_use
        if not ra.conditions_of_use and state.deployment_context:
            ra.conditions_of_use = state.deployment_context

        audit.record(
            db,
            product_id=product_id,
            subject_type="risk_assessment",
            subject_id=f"v{ra.version}",
            op="start_risk_assessment",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=(ra.scope_note or "")[:500],
            payload={"version": ra.version, "changed": sorted(changed)},
        )
        # `ra` is a live reference into the committed state; the result block
        # below only reads it.
        return state, (ra, opened_version)

    ra, opened_version = store_backend.mutate(product_id, _apply)

    missing = [
        f
        for f in (
            "method",
            "intended_purpose",
            "foreseeable_misuse",
            "conditions_of_use",
            "support_duration_note",
            # 13(3)'s last sentence. Listed here so the worksheet asks for them
            # up front rather than the agent discovering them when confirming
            # is refused — the whole point of returning a worksheet is that it
            # names everything the paragraph wants.
            "part_i_1_approach",
            "part_ii_approach",
        )
        if not getattr(ra, f).strip()
    ]
    return {
        "ok": True,
        "version": ra.version,
        "opened_new_version": opened_version,
        "scope": {
            "method": ra.method,
            "intended_purpose": ra.intended_purpose,
            "foreseeable_misuse": ra.foreseeable_misuse,
            "conditions_of_use": ra.conditions_of_use,
            "support_duration_note": ra.support_duration_note,
            "scope_note": ra.scope_note,
        },
        # Surfaced beside the scope, not inside it: 13(3) asks for these *in
        # addition to* the scope, and an agent that cannot see they are empty
        # will not know to fill them until confirming is refused.
        "how_applied": {
            "annex_i_part_i_1": ra.part_i_1_approach,
            "annex_i_part_ii": ra.part_ii_approach,
        },
        "scope_gaps": missing,
        "how_to_draft": (
            "Work from what you can actually see — the codebase, the "
            "dependency manifest, the deployment topology, the auth model, the "
            "data it holds. For each risk name the asset, the threat, the "
            "attack vector, the preconditions and the impact, then say which "
            "Annex I Part I requirements it makes applicable. Ask the user "
            "about anything you cannot observe: who the users are, where it "
            "runs, what it connects to, what would actually hurt if it failed. "
            "Do not pad the list — a short assessment of real risks is worth "
            "more than twenty generic ones, and every entry has to be decided "
            "on individually."
        ),
        "map_risks_onto": [
            {"req_id": r.id, "anchor": r.anchor, "summary": r.summary}
            for r in _PART_I
        ],
        "note_on_part_ii": (
            "Annex I Part II (vulnerability handling) applies to every product "
            "in scope regardless of the risk assessment — it is a process "
            "obligation, not a risk-conditional one. Risks may still reference "
            "those requirements, but do not treat the assessment as what makes "
            "them apply."
        ),
        "next": (
            "propose_risks(product_id, risks=[...]) with what you have "
            "drafted. Nothing you propose determines anything until each risk "
            "is decided on."
        ),
        "disclaimer": _DISCLAIMER,
        "provenance": provenance(),
    }


def propose_risks(
    *,
    product_id: str,
    actor_id: str = "",
    risks: Optional[list[dict[str, Any]]] = None,
    basis: str = "",
    model: Optional[str] = None,
) -> dict:
    """Add drafted risks. They are proposals and determine nothing."""
    def _apply(state, db):
        _member(state, actor_id, minimum=Role.EDITOR)
        _require_assessable(state)

        items = risks or []
        if not items:
            raise InvalidState(
                "risks is empty — pass the drafted risks as a list of objects with "
                "at least a title. start_risk_assessment() returns the frame and "
                "the Part I requirements to map them onto."
            )
        if len(items) > _MAX_PER_CALL:
            raise InvalidState(
                f"{len(items)} risks in one call; the cap is {_MAX_PER_CALL}. "
                "Propose in batches — each one has to be decided on individually, "
                "so a list nobody can review is not progress."
            )
        if not basis.strip():
            raise InvalidState(
                "basis is required: say what these were drafted from — the "
                "repository and commit, the architecture document, the SBOM, a "
                "conversation with the user. It is recorded as the provenance of "
                "the draft."
            )

        ra, opened_version = _ensure_draft(state, actor_id)
        if len(ra.risks) + len(items) > _MAX_TOTAL:
            raise InvalidState(
                f"this assessment already holds {len(ra.risks)} risks; the cap is "
                f"{_MAX_TOTAL}."
            )

        now = _now()
        added: list[RiskItem] = []
        unknown_refs: dict[str, list[str]] = {}
        for raw in items:
            if not isinstance(raw, dict):
                raise InvalidState(
                    f"each risk must be an object, got {type(raw).__name__}"
                )
            title = str(raw.get("title") or "").strip()
            if not title:
                raise InvalidState("every risk needs a title")

            refs = [str(x) for x in (raw.get("affects_requirements") or [])]
            bad = [r for r in refs if r not in _CATALOGUE]
            risk_id = _next_risk_id(ra)
            if bad:
                unknown_refs[risk_id] = bad
            item = RiskItem(
                risk_id=risk_id,
                title=title,
                description=str(raw.get("description") or "").strip(),
                asset=str(raw.get("asset") or "").strip(),
                threat=str(raw.get("threat") or "").strip(),
                attack_vector=str(raw.get("attack_vector") or "").strip(),
                preconditions=str(raw.get("preconditions") or "").strip(),
                impact=str(raw.get("impact") or "").strip(),
                severity=_coerce(RiskSeverity, raw.get("severity"), "severity"),
                likelihood=_coerce(RiskLikelihood, raw.get("likelihood"), "likelihood"),
                treatment=_coerce(RiskTreatment, raw.get("treatment"), "treatment"),
                mitigation_note=str(raw.get("mitigation_note") or "").strip(),
                residual_note=str(raw.get("residual_note") or "").strip(),
                affects_requirements=[r for r in refs if r in _CATALOGUE],
                status=RiskStatus.PROPOSED,
                proposed_by=actor_id or None,
                proposed_by_kind="model" if model else "agent",
                proposed_by_model=model,
                proposed_at=now,
            )
            ra.risks.append(item)
            added.append(item)

        audit.record(
            db,
            product_id=product_id,
            subject_type="risk_assessment",
            subject_id=f"v{ra.version}",
            op="propose_risks",
            accountable_user_id=actor_id or None,
            # The accountable human is the token holder; the actor is the agent
            # or model that drafted. Both are recorded because "who suggested
            # this" and "who is answerable for it" are different questions.
            actor_kind="model" if model else "agent",
            actor_model=model,
            rationale=basis.strip()[:500],
            payload={
                "version": ra.version,
                "added": [r.risk_id for r in added],
                "unknown_requirement_refs": unknown_refs,
            },
        )
        return state, (ra, opened_version, added, unknown_refs)

    ra, opened_version, added, unknown_refs = store_backend.mutate(
        product_id, _apply
    )

    result = {
        "ok": True,
        "version": ra.version,
        "opened_new_version": opened_version,
        "added": [_risk_view(r) for r in added],
        "determined_nothing": (
            "These are proposals. No requirement's applicability has changed "
            "and none will until each risk is decided on with decide_risk() "
            "and the assessment is confirmed."
        ),
        "next": (
            "Walk the user through them and call decide_risk(risk_id, "
            "decision='accept'|'reject', rationale=...) for each. Present them "
            "as your draft, not as findings."
        ),
        "disclaimer": _DISCLAIMER,
    }
    if unknown_refs:
        result["dropped_requirement_refs"] = unknown_refs
        result["dropped_note"] = (
            "These requirement ids are not in the Annex I catalogue and were "
            "dropped rather than stored. list_requirements() has the real ids."
        )
    return result


def _coerce(enum_cls, value, field: str):
    if value is None or value == "":
        return None
    try:
        return enum_cls(value)
    except ValueError as e:
        raise InvalidState(
            f"{field} must be one of {[m.value for m in enum_cls]}, got {value!r}"
        ) from e


def decide_risk(
    *,
    product_id: str,
    actor_id: str = "",
    risk_id: str,
    decision: str,
    rationale: str = "",
    severity: Optional[str] = None,
    likelihood: Optional[str] = None,
    treatment: Optional[str] = None,
    affects_requirements: Optional[list[str]] = None,
    mitigation_note: Optional[str] = None,
    residual_note: Optional[str] = None,
) -> dict:
    """Accept or reject one drafted risk. This is the act that counts."""
    if decision not in ("accept", "reject"):
        raise InvalidState("decision must be 'accept' or 'reject'")
    if not rationale.strip():
        raise InvalidState(
            "rationale is required. An auditor reads why a risk was accepted "
            "or dismissed, not the flag — and for a risk drafted by a model, "
            "the rationale is the only record that a person actually "
            "considered it."
        )

    def _apply(state, db):
        _member(state, actor_id, minimum=Role.EDITOR)
        _require_assessable(state)
        if state.risk_assessment is None:
            raise InvalidState(
                "no risk assessment on this product yet — start_risk_assessment() "
                "first."
            )

        ra, opened_version = _ensure_draft(state, actor_id)
        item = _find_risk(ra, risk_id)

        if severity is not None:
            item.severity = _coerce(RiskSeverity, severity, "severity")
        if likelihood is not None:
            item.likelihood = _coerce(RiskLikelihood, likelihood, "likelihood")
        if treatment is not None:
            item.treatment = _coerce(RiskTreatment, treatment, "treatment")
        if mitigation_note is not None:
            item.mitigation_note = mitigation_note.strip()
        if residual_note is not None:
            item.residual_note = residual_note.strip()

        dropped: list[str] = []
        if affects_requirements is not None:
            refs = [str(x) for x in affects_requirements]
            dropped = [r for r in refs if r not in _CATALOGUE]
            item.affects_requirements = [r for r in refs if r in _CATALOGUE]

        item.status = RiskStatus.ACCEPTED if decision == "accept" else RiskStatus.REJECTED
        item.decided_by = actor_id or None
        item.decided_at = _now()
        item.decision_rationale = rationale.strip()

        if item.status == RiskStatus.ACCEPTED and not item.treatment:
            raise InvalidState(
                f"{risk_id} cannot be accepted without a treatment — pass "
                f"treatment as one of {[t.value for t in RiskTreatment]}. "
                "Accepting the risk as it stands is a legitimate answer "
                "('treatment=accept'), but it has to be the recorded decision "
                "rather than an omission."
            )

        audit.record(
            db,
            product_id=product_id,
            subject_type="risk",
            subject_id=risk_id,
            op="decide_risk",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=rationale.strip()[:500],
            payload={
                "decision": decision,
                "version": ra.version,
                "treatment": item.treatment,
                "severity": item.severity,
                "affects_requirements": list(item.affects_requirements),
                "drafted_by_model": item.proposed_by_model,
            },
        )
        return state, (ra, item, opened_version, dropped)

    ra, item, opened_version, dropped = store_backend.mutate(
        product_id, _apply
    )

    undecided = [r.risk_id for r in ra.risks if r.status == RiskStatus.PROPOSED]
    result = {
        "ok": True,
        "risk": _risk_view(item, verbose=True),
        "opened_new_version": opened_version,
        "undecided_remaining": undecided,
        "next": (
            f"{len(undecided)} risk(s) still undecided."
            if undecided
            else (
                "Every risk is decided. confirm_risk_assessment(rationale=...) "
                "freezes this version and sets requirement applicability from "
                "the accepted risks."
            )
        ),
    }
    if dropped:
        result["dropped_requirement_refs"] = dropped
    return result


def confirm_risk_assessment(
    *,
    product_id: str,
    actor_id: str = "",
    rationale: str = "",
) -> dict:
    """Freeze this version, then set applicability from the accepted risks."""
    if not rationale.strip():
        raise InvalidState(
            "rationale is required — this freezes a retained artifact and "
            "changes the Annex I checklist. Say what was assessed and on what "
            "basis you are confirming it."
        )

    def _apply(state, db):
        _member(state, actor_id, minimum=Role.MAINTAINER)
        _require_assessable(state)
        ra = state.risk_assessment
        if ra is None:
            raise InvalidState(
                "no risk assessment to confirm — start_risk_assessment() first."
            )

        undecided = [r.risk_id for r in ra.risks if r.status == RiskStatus.PROPOSED]
        if undecided:
            raise InvalidState(
                f"{len(undecided)} risk(s) still undecided: {', '.join(undecided)}. "
                "Confirming with drafted-but-unreviewed entries would freeze a "
                "model's output into the technical file as though a person had "
                "agreed with it. Decide each one first."
            )
        if not ra.risks:
            raise InvalidState(
                "this assessment identifies no risks at all. That is a conclusion "
                "an auditor will test hard — if it is genuinely the finding, "
                "record it as a risk with treatment='accept' and say why, so the "
                "reasoning is in the file."
            )
        missing_scope = [
            f
            for f in ("method", "intended_purpose", "foreseeable_misuse", "conditions_of_use")
            if not getattr(ra, f).strip()
        ]
        if missing_scope:
            raise InvalidState(
                "the assessment does not state what it was performed against: "
                f"{', '.join(missing_scope)} empty. Article 13(2) frames the "
                "assessment around intended purpose and reasonably foreseeable "
                "use — an assessment with no stated scope cannot be evaluated by "
                "anyone reading it later. Fill them with "
                "start_risk_assessment(...)."
            )

        # Article 13(3)'s last sentence, and the reason this was filed as a bug
        # rather than a feature: without it, confirming froze an assessment that
        # did not contain everything 13(3) requires of it — and that assessment
        # is the artefact Annex VII(3) cites. The risks answer Part I(2); these
        # two answer what the paragraph asks for *in addition*.
        missing_13_3 = [
            (field, anchor, what)
            for field, anchor, what in (
                (
                    "part_i_1_approach",
                    "Annex I Part I(1)",
                    "how you achieve an appropriate level of cybersecurity based "
                    "on the risks",
                ),
                (
                    "part_ii_approach",
                    "Annex I Part II",
                    "how you apply the vulnerability handling requirements",
                ),
            )
            if not getattr(ra, field).strip()
        ]
        if missing_13_3:
            detail = "; ".join(
                f"{anchor} ({field}) — {what}" for field, anchor, what in missing_13_3
            )
            raise InvalidState(
                "Article 13(3) requires the assessment to *also* indicate how "
                "Annex I Part I(1) and the Part II vulnerability handling "
                "requirements are applied. The risks here cover Part I(2) "
                f"applicability; this is the rest of the paragraph. Missing: "
                f"{detail}. Both are statements of approach about the whole "
                "product rather than per-risk determinations, so they are set "
                "with start_risk_assessment(...) and freeze with the rest of "
                "the assessment."
            )

        accepted = _accepted(ra)
        applied = apply_to_requirements(state, accepted)

        body = _frozen_body(state, ra)
        digest = hashlib.sha256(body.encode()).hexdigest()
        now = _now()

        from cra.db import Evidence  # local: keeps the module import surface small

        snapshot = Evidence(
            product_id=product_id,
            subject_ref=f"risk_assessment:v{ra.version}",
            title=f"Article 13(2) risk assessment v{ra.version} — {state.name}",
            kind=EvidenceKind.DOCUMENT.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=digest,
            source_ref=f"cra-mcp confirm_risk_assessment v{ra.version}",
            added_by_user_id=actor_id or None,
        )
        db.add(snapshot)
        db.flush()
        evidence_id = snapshot.id
        audit.record(
            db,
            product_id=product_id,
            subject_type="risk_assessment",
            subject_id=f"v{ra.version}",
            op="confirm_risk_assessment",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=rationale.strip()[:500],
            payload={
                "version": ra.version,
                "risks_accepted": len(accepted),
                "risks_rejected": len(ra.risks) - len(accepted),
                "made_applicable": [m["req_id"] for m in applied["made_applicable"]],
                "reopened": [m["req_id"] for m in applied["reopened"]],
                "still_undetermined": applied["still_undetermined"],
            },
            after_hash=digest,
        )

        ra.status = AssessmentStatus.CONFIRMED
        ra.confirmed_at = now
        ra.confirmed_by = actor_id or None
        ra.confirmation_rationale = rationale.strip()
        ra.content_hash = digest
        ra.evidence_id = evidence_id
        ra.basis_product_class = state.classification.product_class
        ra.basis_lifecycle = state.lifecycle
        # The snapshot, its audit row and the confirmation on the blob
        # are one transaction. A half-applied confirm is the worst of the
        # set: Annex I applicability is derived from it, so a hash with no
        # state — or state with no hash — makes every downstream
        # determination unexplainable.
        # `state` comes back too: the Part II summary below is computed
        # from the committed checklist, not from a pre-lock read.
        return state, (ra, evidence_id, digest, accepted, applied, state)

    ra, evidence_id, digest, accepted, applied, state = store_backend.mutate(
        product_id, _apply
    )

    # Part II items that are still gaps, not ones still undetermined.
    #
    # They are seeded applicable now — the chapeau is unconditional, so leaving
    # a user to mark them applicable was asking them to restate the law. That
    # made the old "still undetermined" list permanently empty, which would have
    # read as "Part II is handled". It is not: applicable is where these start,
    # and each still needs evidence.
    from cra.server.annex import _is_gap  # local: annex imports this module

    have = {i.req_id for i in state.requirements}
    by_id = {i.req_id: i for i in state.requirements}
    part_ii_open = [r.id for r in _PART_II if r.id in have and _is_gap(by_id[r.id])]

    # Echo the 13(3) statements back with their lengths. The confirmation check
    # is presence, not substance — it strips whitespace and accepts anything
    # that remains — so an end-to-end run froze `part_ii_approach = "x"` into a
    # ten-year artefact and the technical file then reported the section
    # satisfied.
    #
    # No threshold and no refusal: no mechanical test measures a reason, and a
    # length rule would only teach the next caller to pad. What was actually
    # missing was that nobody saw the text before it sealed. This is the last
    # moment that is true, so the text comes back.
    frozen_statements = {
        "part_i_1_approach": {
            "text": ra.part_i_1_approach,
            "chars": len(ra.part_i_1_approach.strip()),
        },
        "part_ii_approach": {
            "text": ra.part_ii_approach,
            "chars": len(ra.part_ii_approach.strip()),
        },
    }

    return {
        "ok": True,
        "version": ra.version,
        "content_hash": digest,
        "evidence_id": evidence_id,
        "frozen_article_13_3_statements": frozen_statements,
        "check_what_was_frozen": (
            "These two sentences are now sealed into version "
            f"{ra.version} and cited by Annex VII(3). Article 13(3) asks the "
            "assessment to indicate how Annex I Pt I(1) and the Part II "
            "vulnerability handling requirements are applied — read them back "
            "and confirm they say that. Editing them opens version "
            f"{ra.version + 1}."
        ),
        "risks_accepted": len(accepted),
        "requirements_made_applicable": applied["made_applicable"],
        "reopened": applied["reopened"],
        "reopened_note": (
            "An accepted risk names requirements that had been ruled out. The "
            "old justifications were cleared — resolve the contradiction "
            "before the file is frozen."
            if applied["reopened"]
            else None
        ),
        "still_undetermined": applied["still_undetermined"],
        "still_undetermined_note": (
            "No accepted risk named these Part I requirements. They are NOT "
            "ruled out — they are unanswered, and each still counts as a gap. "
            "Decide each one with update_requirement(); marking one "
            "not_applicable needs a justification an auditor would accept."
        ),
        "part_ii_still_open": part_ii_open,
        "part_ii_note": (
            "Annex I Part II applies to every in-scope product regardless of "
            "the risk assessment — its chapeau is unconditional, so these are "
            "recorded as applicable from the start rather than waiting to be "
            "marked. Confirming an assessment does not answer them; each still "
            "needs evidence."
        ),
        "next": (
            "list_requirements(filter='gaps') for what is now open, then "
            "attach_evidence() as you implement. The technical file's Annex "
            "VII(3) section now has a confirmed assessment to cite."
        ),
        "disclaimer": _DISCLAIMER,
    }


def get_risk_assessment(
    *,
    product_id: str,
    actor_id: str = "",
    include_rejected: bool = True,
    verbose: bool = False,
) -> dict:
    """The assessment as it stands, with staleness derived."""
    state = _load(product_id)
    _member(state, actor_id)
    ra = state.risk_assessment
    summary = _assessment_view(state, verbose=verbose)
    if ra is None:
        return {"ok": True, "assessment": summary, "risks": [], "disclaimer": _DISCLAIMER}

    risks = [
        r
        for r in ra.risks
        if include_rejected or r.status != RiskStatus.REJECTED
    ]
    return {
        "ok": True,
        "assessment": summary,
        "scope": {
            "method": ra.method,
            "intended_purpose": ra.intended_purpose,
            "foreseeable_misuse": ra.foreseeable_misuse,
            "conditions_of_use": ra.conditions_of_use,
            "support_duration_note": ra.support_duration_note,
            "scope_note": ra.scope_note,
        },
        # Surfaced beside the scope, not inside it: 13(3) asks for these *in
        # addition to* the scope, and an agent that cannot see they are empty
        # will not know to fill them until confirming is refused.
        "how_applied": {
            "annex_i_part_i_1": ra.part_i_1_approach,
            "annex_i_part_ii": ra.part_ii_approach,
        },
        "risks": [_risk_view(r, verbose=verbose) for r in risks],
        "disclaimer": _DISCLAIMER,
        "provenance": provenance(),
    }


_dispatch.register_mutating("start_risk_assessment", start_risk_assessment)
_dispatch.register_mutating("propose_risks", propose_risks)
_dispatch.register_mutating("decide_risk", decide_risk)
_dispatch.register_mutating("confirm_risk_assessment", confirm_risk_assessment)
_dispatch.register_read("get_risk_assessment", get_risk_assessment)
