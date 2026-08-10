"""The Annex VII technical file, the Annex V declaration, and signing them.

The line this module must not cross: it assembles and reports, it never
certifies. `assemble_technical_file` is a **gap report** that happens to render
a document — the useful output is what is missing, not the prose. And
`generate_declaration_of_conformity` produces a *draft* that a human signs;
nothing here can make a product conformant, and where the product class
requires a notified body, only that body can assess conformity at all.

Two mechanics worth knowing:

**Freezing computes a content hash.** `finalize=true` snapshots the assembled
file and stores it hashed, because Annex VII is retained ten years and
"reproduce exactly what was declared on 14 September 2027" is a question that
gets asked. A signature binds to that hash, so a file edited afterwards no
longer matches its attestation and says so.

What that hash spans is the load-bearing part. Until 2026-08-10 it covered the
*shape* of the file — which slots were complete, how many requirements were
settled — and not what any requirement said. So an implementation note could be
rewritten after signature, from a claim that hardening was applied to a
statement that it was only partly applied, and nothing moved. `_narrative` is
now in the payload, and `HASH_PAYLOAD_VERSION` records which definition a given
signature was taken under so that widening it again is distinguishable from the
document having changed.

**A declaration is refused, not warned about, when a mandatory field is blank.**
`assemble_technical_file(finalize=True)` has always refused an incomplete file
because freezing one "produces a document that looks finished". The declaration
carries the legal weight — it is what CE marking rests on — so it gets the same
rule and no override. `record_release` has an override because shipping with
something outstanding is a decision a manufacturer may take; declaring
conformity over a blank Annex V field is not that kind of decision.

**`get_conformity_status` carries `qualifications`.** Everything else it returns
is a green tick, and an agent asked "where do we stand" composes its answer from
green ticks. The disclaimer does not help — it disclaims the conclusion rather
than correcting the inputs. `qualifications` names what is not established, so
the obvious summary cannot be wrong in a way the reader could not see.

**Segregation of duties is available and off by default.** In compliance the
person producing evidence frequently must not be the person attesting to it.
`sign_off(require_independent=true)` refuses a signer who was the subject's
last editor. Defaulting it on would block the solo maintainer this tool is
aimed at, so it is opt-in and surfaced rather than assumed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from cra.agents import dispatch as _dispatch
from cra.db import Attestation, Evidence, session_scope
from cra.deadlines import add_months
from cra.regulation import (
    doc_fields,
    provenance,
    requirements_for_part,
    technical_file_retention,
    technical_file_slots,
)
from cra.regulation import product_class as class_spec
from cra.schemas.enums import Applicability, EvidenceKind, RequirementStatus, Role
from cra.server import audit, entitlements, risk, statutory_export, store_backend
from cra.server.annex import _find, _is_gap, evidence_currency, latest_release
from cra.server.errors import InvalidState, NotFound
from cra.server.scoping import (
    _ENUM_TO_CLASS,
    _load,
    _member,
    _ui_settled,
    _years_between,
)

_DISCLAIMER = (
    "Assembled from what you have recorded. This is not a conformity "
    "assessment and cannot certify that the product is compliant; where your "
    "product class requires a notified body, only that body can assess "
    "conformity."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def retention_status(state) -> dict:
    """How long Article 13(13) requires this file to be kept. Derived, never stored.

    Ten years from placing on the market **or the support period, whichever is
    longer** — a rule, not the flat ten years this reported until 2026-08-09,
    which was short for any product supported beyond a decade.

    The clock runs from placing on the market, so a product still in
    development has not started one. That is `until: None` with a reason, not a
    date computed from today — the same discipline `deadlines` applies to a
    reporting clock whose anchor has not happened yet.

    The anchor is the *latest* release. Each version placed on the market
    carries its own ten years, and the file describes what currently ships, so
    the latest placing is the one that binds longest.
    """
    rule = technical_file_retention()
    releases = sorted(state.releases, key=lambda r: r.released_at)
    placed = releases[-1].released_at if releases else None
    support_end = state.support_period.end

    if placed is None:
        return {
            "anchor": rule["anchor"],
            "covers": rule["covers"],
            "until": None,
            "basis": "not_yet_placed_on_market",
            "note": (
                "The Article 13(13) period runs from placing on the market, "
                "which has not been recorded for this product."
            ),
        }

    floor = add_months(placed, rule["floor_years"] * 12)
    if support_end is not None and support_end > floor:
        until, basis = support_end, "support_period"
    else:
        until, basis = floor, "ten_years_from_placing_on_market"

    return {
        "anchor": rule["anchor"],
        "covers": rule["covers"],
        "until": until.isoformat(),
        "basis": basis,
        "placed_on_market": placed.isoformat(),
        "support_period_end": support_end.isoformat() if support_end else None,
    }


# A justification this short is not a judgement about quality — it is the length
# at which text stops being a sentence. `x`, `n/a` and `-` all pass the
# non-empty check that `update_requirement` applies, and an end-to-end run ruled
# two Annex I essential requirements out on exactly those.
#
# Deliberately not a refusal. No mechanical test can measure a reason, and a
# threshold that refused would be a substance test wearing a length costume —
# it would teach the next caller to pad to 25 characters and change nothing.
# What it does instead is make them visible at the two moments a person is
# definitely looking: the gap report, and the freeze.
_THIN_JUSTIFICATION_CHARS = 24


def thin_justifications(state) -> list[dict]:
    """Ruled-out requirements whose stated reason is too short to be one.

    Derived, never stored — the same discipline as `risk.staleness` and
    `evidence_currency`. Reported, never counted as a gap: the requirement *is*
    settled as far as the record goes, and pretending otherwise would be the
    tool substituting its own judgement for the manufacturer's. What it does is
    refuse to let the shortest ones disappear into a coverage count.
    """
    out = []
    for item in state.requirements:
        if item.applicability != Applicability.NOT_APPLICABLE:
            continue
        reason = (item.justification or "").strip()
        if len(reason) < _THIN_JUSTIFICATION_CHARS:
            out.append({
                "req_id": item.req_id,
                "justification": reason,
                "chars": len(reason),
            })
    return out


def _coverage(attestation, current_hash: Optional[str]) -> dict:
    """Whether a signature still covers what the document now says.

    Three answers, and the third is the one that had to be added. A signature
    binds to a digest, and on 2026-08-10 the payload that digest is taken over
    widened to include what each requirement actually says. Every hash moved.

    Comparing a signature taken under the old definition against a digest
    computed under the new one produces `False`, which reads as "the file
    changed after you signed it". Nothing changed — the measurement did. That is
    the inverse of the rule this codebase runs on: as an absence of knowledge
    must not read as knowledge of absence, a change in how we measure must not
    read as a change in what was measured.

      current       the hashes match; the signature covers what the file says now
      superseded    both under the same definition, and they differ: it changed
      incomparable  signed under an earlier definition, so this cannot be
                    determined here

    `covers_current_version` stays a boolean and stays false for `incomparable`,
    because we cannot show that it covers — which is a different claim from
    showing that it does not, and the `detail` says which.

    An incomparable signature is not evidence of tampering and must never be
    reported as such. The frozen body it was taken over is kept in `evidence`
    and copied to the statutory archive, so verifying one is a question for that
    artefact rather than for this table — which is also why no version-1 payload
    builder is kept alive here.
    """
    bound = attestation.subject_version_hash
    version = getattr(attestation, "hash_payload_version", None)

    if version is not None and version == HASH_PAYLOAD_VERSION:
        matches = bool(current_hash) and bound == current_hash
        return {
            "covers_current_version": matches,
            "coverage": "current" if matches else "superseded",
            "detail": (
                "The signature is bound to the document as it now stands."
                if matches
                else "The document changed after this was signed, so a fresh "
                "sign-off is required. That is what the hash is for."
            ),
        }

    return {
        "covers_current_version": False,
        "coverage": "incomparable",
        "detail": (
            "Signed when the content hash was computed over less of the file "
            "than it is now — the requirement and Annex II narrative was added "
            "to it on 2026-08-10. This does not mean the document changed, and "
            "it is not a sign of tampering; it means coverage cannot be "
            "determined from the hash alone. Re-sign to bind to the current "
            "definition, or verify against the frozen body kept in evidence."
        ),
    }


def _evidence_by_subject(db, product_id: str) -> dict[str, list[Evidence]]:
    out: dict[str, list[Evidence]] = {}
    rows = db.execute(
        select(Evidence).where(
            Evidence.product_id == product_id, Evidence.deleted_at.is_(None)
        )
    ).scalars()
    for e in rows:
        out.setdefault(e.subject_ref, []).append(e)
    return out


# The payload the technical-file hash is taken over. Bumped when what counts as
# the file's *content* changes, so a signature taken under an earlier definition
# can be recognised rather than silently compared against a new one.
HASH_PAYLOAD_VERSION = 2


def _narrative(state) -> dict:
    """What the file asserts about each requirement and Annex II item.

    Hashed, and this is the whole point of the function. Until 2026-08-10 the
    payload carried only *counts* — total, settled, gaps — so the digest moved
    when a requirement changed category and not when it changed meaning. An
    end-to-end run signed a file, rewrote an `implementation_note` from a claim
    that hardening flags were applied to a statement that they were only partly
    applied, and the hash did not move: `stale_signatures` stayed empty and the
    signature still reported as covering the current version.

    Annex VII(3) asks the file to record how each applicable requirement is
    implemented, and `implementation_note` is where that lives. So it is content,
    and so is the `justification` that rules a requirement out — the two fields a
    reader is most likely to revise quietly were the two the signature did not
    span.

    Sorted by id, and every field rendered even when empty: a dict that omits
    blank values hashes the same whether a note was never written or was emptied.
    """
    return {
        "requirements": [
            {
                "req_id": i.req_id,
                "applicability": str(i.applicability),
                "status": str(i.status),
                "justification": i.justification or "",
                "implementation_note": i.implementation_note or "",
                "risk_basis": sorted(i.risk_basis or []),
                "evidence_ids": sorted(i.evidence_ids or []),
            }
            for i in sorted(state.requirements, key=lambda x: x.req_id)
        ],
        "user_information": [
            {
                "item_id": i.item_id,
                "provided": bool(i.provided),
                "not_applicable": bool(i.not_applicable),
                "justification": i.justification or "",
                "location": i.location or "",
                "note": i.note or "",
            }
            for i in sorted(state.user_information, key=lambda x: x.item_id)
        ],
    }


def _slot_view(
    slot, state, by_subject: dict[str, list[Evidence]], currency: dict | None = None
) -> dict:
    """One Annex VII section: what it needs, what we have, what is missing."""
    evidence = list(by_subject.get(f"technical_file:{slot.id}", []))
    sourced_from: list[str] = []

    # Some slots are fed by requirement work rather than by direct attachment.
    for req_id in slot.auto_from:
        for e in by_subject.get(f"requirement:{req_id}", []):
            evidence.append(e)
            sourced_from.append(req_id)

    view = {
        "slot": slot.id,
        "anchor": slot.anchor,
        "title": slot.title,
        "needs": list(slot.needs),
        "optional": slot.optional,
        "evidence_ids": [e.id for e in evidence],
        "sourced_from_requirements": sorted(set(sourced_from)),
    }
    if slot.note:
        view["note"] = slot.note

    # Annex VII(3) wants the Article 13(2) assessment itself. Checked before
    # requirement coverage because coverage answers a different question:
    # "which requirements did we settle" is not "what did we assess", and this
    # slot used to report complete on the second alone.
    assessment_ok = True
    if slot.requires_risk_assessment:
        ra = state.risk_assessment
        stale = risk.staleness(state)
        assessment_ok = bool(ra and ra.content_hash) and not stale
        view["risk_assessment"] = {
            "present": bool(ra),
            "confirmed": bool(ra and ra.content_hash),
            "version": ra.version if ra else None,
            "content_hash": ra.content_hash if ra else None,
            "evidence_id": ra.evidence_id if ra else None,
            "stale_reasons": stale,
        }
        if not (ra and ra.content_hash):
            view["risk_assessment"]["missing"] = (
                "No confirmed Article 13(2) risk assessment. Annex VII(3) "
                "requires it, and every Part I applicability decision is "
                "supposed to rest on it. start_risk_assessment(product_id)."
            )

    if slot.auto_from_part:
        reqs = requirements_for_part(slot.auto_from_part)
        wanted = {r.id for r in reqs}
        items = [i for i in state.requirements if i.req_id in wanted]
        currency = currency or {}
        gaps = [i.req_id for i in items if _is_gap(i, currency.get(i.req_id))]
        # Reported separately from `gaps` so the reason a requirement is
        # unsettled is legible: 'evidenced against an old release' and
        # 'never evidenced' both block the file, and they need different work.
        stale = [
            i.req_id
            for i in items
            if (currency.get(i.req_id) or {}).get("state") == "stale"
        ]
        unversioned = [
            i.req_id
            for i in items
            if (currency.get(i.req_id) or {}).get("state") == "unversioned"
        ]
        unbased = [
            i.req_id
            for i in items
            if i.applicability == Applicability.APPLICABLE and not i.risk_basis
        ]
        view["requirement_coverage"] = {
            "total": len(items),
            "settled": len(items) - len(gaps),
            "gaps": gaps,
            "evidenced_against_earlier_release": stale,
            "evidence_without_a_release": unversioned,
            # Not a gap — a requirement can be applicable for reasons the
            # assessment did not enumerate. But an auditor reading Annex VII(3)
            # asks what each determination rested on, so it is worth surfacing.
            "applicable_without_risk_basis": unbased,
        }
        view["complete"] = bool(items) and not gaps and assessment_ok
        if not view["complete"]:
            reasons = []
            if not assessment_ok:
                reasons.append(
                    "no confirmed Article 13(2) risk assessment"
                    if not (state.risk_assessment and state.risk_assessment.content_hash)
                    else "the confirmed risk assessment is stale"
                )
            if gaps:
                reasons.append(f"{len(gaps)} requirement(s) unsettled")
            if not items:
                reasons.append("no requirements seeded")
            view["missing"] = "; ".join(reasons)
    elif slot.satisfied_by == "user_information":
        # tf.1 is not *only* Annex II — it also wants the general description,
        # the software versions and, for hardware, photographs. So the slot
        # keeps needing its own evidence and additionally reports item-level
        # Annex II coverage. Before this, the whole annex was one line in
        # `needs`, satisfied by attaching a document and hoping it said the
        # right things.
        items = list(state.user_information)
        unsettled = [i.item_id for i in items if not _ui_settled(i)]
        view["annex_ii_coverage"] = {
            "total": len(items),
            "settled": len(items) - len(unsettled),
            "unsettled": unsettled,
            "not_applicable": [i.item_id for i in items if i.not_applicable],
        }
        view["complete"] = bool(evidence) and bool(items) and not unsettled
        if not view["complete"]:
            reasons = []
            if not evidence:
                reasons.append(
                    "no general description attached — use attach_evidence("
                    f"subject_ref='technical_file:{slot.id}', ...)"
                )
            if not items:
                reasons.append(
                    "no Annex II checklist seeded; run classify_product(in_scope=true)"
                )
            elif unsettled:
                reasons.append(
                    f"{len(unsettled)} Annex II item(s) unsettled — "
                    "list_user_information(filter='gaps')"
                )
            view["missing"] = "; ".join(reasons)
    elif slot.satisfied_by == "support_period":
        sp = state.support_period
        # Both halves, because Annex VII(4) is *the information taken into
        # account*, not the date. A slot that completed on an end date alone
        # would report the section filled while the thing the section is for —
        # the reasoning — was still missing, which is the specific way a
        # technical file ends up looking finished and not being.
        has_dates = bool(sp.end and sp.start)
        has_reasoning = bool((sp.rationale or "").strip())
        view["complete"] = has_dates and has_reasoning
        view["support_period"] = {
            "start": sp.start.isoformat() if sp.start else None,
            "end": sp.end.isoformat() if sp.end else None,
            "years": (
                round(_years_between(sp.start, sp.end), 2)
                if sp.start and sp.end
                else None
            ),
            "expected_use_years": sp.expected_use_years,
            "published_url": sp.published_url,
            "determined_at": sp.determined_at.isoformat() if sp.determined_at else None,
        }
        # Evidence attached by hand still counts for the *record*, but not for
        # completion: it is what people had to do before the tool could hold
        # this, and it stays visible rather than being quietly ignored.
        if not view["complete"]:
            missing = []
            if not has_dates:
                missing.append("no support period recorded")
            elif not has_reasoning:
                missing.append(
                    "a period is recorded but not the information it was based "
                    "on, which is what Annex VII(4) actually asks for"
                )
            view["missing"] = (
                "; ".join(missing)
                + ". Use set_support_period(end=..., rationale=...)."
            )
    elif slot.satisfied_by == "declaration_of_conformity":
        view["complete"] = bool(state.conformity_declaration_hash)
        # Deferred, not missing. The declaration is drawn up *against* the
        # technical documentation and a copy is then placed in the file, so
        # this slot is empty by construction the first time round. Counting it
        # as a blocker would deadlock: the file could not be frozen without the
        # declaration, and the declaration must not rest on an unfrozen file.
        view["deferred"] = not view["complete"]
        if not view["complete"]:
            view["missing"] = (
                "Filled last, by design: freeze the file, draw up the "
                "declaration against it, then re-freeze so this section "
                "contains a copy."
            )
    else:
        view["complete"] = bool(evidence)
        if not evidence:
            view["missing"] = (
                f"Nothing attached. Use attach_evidence(subject_ref="
                f"'technical_file:{slot.id}', ...)."
            )
    return view


def assemble_technical_file(
    *,
    product_id: str,
    actor_id: str = "",
    finalize: bool = False,
) -> dict:
    """Annex VII, slot by slot, with the gaps named. Optionally freeze it."""
    state = _load(product_id)
    _member(state, actor_id, minimum=Role.MAINTAINER if finalize else Role.VIEWER)

    if finalize:
        # The gap report is the working view; the freeze is the legal act a
        # signature later binds to. Refuse before any of the assembly work.
        entitlements.require(
            actor_id,
            entitlements.CONFORMITY,
            what="Freezing this version of the technical file would have produced a signable document.",
            # The owner's plan, not the caller's. Without `product_id` this
            # asked whether *whoever happened to run it* was covered, which is
            # the loophole `plan_for_product` exists to close — it would answer
            # differently for two members of the same product depending only on
            # which of them made the call.
            product_id=product_id,
        )

    if state.classification.in_scope is not True:
        raise InvalidState(
            "this product is not recorded as in scope, so there is no Annex "
            "VII file to assemble. Run classify_product(in_scope=true) first."
        )

    with session_scope() as db:
        by_subject = _evidence_by_subject(db, product_id)

    currency = evidence_currency(state, by_subject)
    slots = [
        _slot_view(s, state, by_subject, currency) for s in technical_file_slots()
    ]
    missing = [
        s
        for s in slots
        if not s["complete"] and not s["optional"] and not s.get("deferred")
    ]
    deferred = [s for s in slots if s.get("deferred")]

    release = latest_release(state)
    retention = retention_status(state)
    thin = thin_justifications(state)

    # The hashed payload is *content only*. `assembled_at` used to live in here,
    # which meant the digest changed on every call even when nothing about the
    # file had — and since an attestation binds to a hash, any re-assembly
    # instantly reported every prior signature as stale. That made
    # `stale_signatures` noise rather than a signal, and it undermines the
    # evidence-currency work this now sits beside: staleness has to mean the
    # file moved, not that somebody looked at it twice.
    #
    # The timestamp is still returned, right next to the hash — see `result`.
    payload = {
        # Which definition of "content" this digest was taken over. Without it,
        # widening the payload later is indistinguishable from the file having
        # changed, and every existing signature reads as superseded on deploy.
        "payload_version": HASH_PAYLOAD_VERSION,
        "product_id": product_id,
        "product_name": state.name,
        "product_class": state.classification.product_class,
        "conformity_route": state.classification.conformity_route,
        # Which release this file describes. Annex I attaches to the product as
        # placed on the market, so a technical file that does not say which
        # version it documents is ambiguous about the only thing that matters.
        "release": release.version if release else None,
        "released_at": release.released_at.isoformat() if release else None,
        "slots": slots,
        # What each requirement and Annex II item actually says, not just how
        # many of them are settled. See `_narrative`.
        "narrative": _narrative(state),
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    digest = hashlib.sha256(body.encode()).hexdigest()
    assembled_at = _now().isoformat()

    result = {
        "ok": True,
        "product_id": product_id,
        # "complete" means every section that *can* be filled now is filled.
        # The declaration slot is reported separately in `deferred_slots`.
        "complete": not missing,
        "slots": slots,
        "missing_slots": [
            {"slot": s["slot"], "anchor": s["anchor"], "title": s["title"]}
            for s in missing
        ],
        "deferred_slots": [
            {"slot": s["slot"], "anchor": s["anchor"], "why": s["missing"]}
            for s in deferred
        ],
        # Reported, never counted as a gap. The requirement *is* settled as far
        # as the record goes, and treating a short reason as no reason would be
        # the tool substituting its judgement for the manufacturer's. What this
        # refuses to do is let the shortest ones vanish into a coverage count —
        # an end-to-end run ruled two Annex I essential requirements out on "x"
        # and "n/a", and nothing downstream mentioned it again.
        "thin_justifications": thin,
        "content_hash": digest,
        # Beside the hash rather than inside it. A hash on its own says what the
        # file was and not when it was read, and the printed gap report is the
        # artefact that leaves the company — but folding the timestamp into the
        # digest made the digest useless for the one job it has, which is
        # telling you whether the file changed.
        "assembled_at": assembled_at,
        "release": release.version if release else None,
        "finalized": False,
        "retention": retention,
        "disclaimer": _DISCLAIMER,
        "provenance": provenance(),
    }

    # What this note says had to change when evidence stopped being gated. It
    # used to say the open sections meant "not recorded here" rather than "not
    # done", on the premise that this account could not record evidence at all.
    # That premise became false, and leaving the sentence would have been worse
    # than deleting it: it would excuse real gaps.
    #
    # What is still true without CONFORMITY is narrower and worth saying — this
    # is a working view, not the legal act. The gaps are real.
    #
    # Conditioned on the **owner's** plan, like the `finalize` gate above and
    # unlike this check before 2026-08-09. Asking the caller's plan meant two
    # members of one product read different notes on the same report.
    if not entitlements.plan_for_product(product_id, fallback_user_id=actor_id).covers(
        entitlements.CONFORMITY
    ):
        result["coverage_note"] = (
            "This plan does not include freezing or signing, so this is a "
            "working view of the file rather than a version anyone has "
            "attested to. The open sections are real gaps in what has been "
            "recorded — nothing here is a compliance conclusion about your "
            "product either way."
        )

    if finalize and thin:
        result["review_before_this_is_relied_on"] = (
            f"{len(thin)} requirement(s) are ruled out on a justification of "
            f"under {_THIN_JUSTIFICATION_CHARS} characters: "
            + ", ".join(f"{j['req_id']} ({j['justification']!r})" for j in thin[:6])
            + ". This file is frozen with them in it — that is your call to make "
            "— but an auditor reads the justification rather than the flag, and "
            "these are the ones they will stop on."
        )

    if not finalize:
        result["next"] = (
            f"{len(missing)} section(s) still open. Fill them, then call "
            "assemble_technical_file(finalize=true) to freeze a version you "
            "can sign."
            if missing
            else (
                "Every section that can be filled now has content. "
                "assemble_technical_file(finalize=true) freezes this version, "
                "then generate_declaration_of_conformity() draws up the "
                "declaration against it — re-freeze afterwards so Annex VII(7) "
                "holds a copy."
                if deferred
                else (
                    "Every mandatory section has content. "
                    "assemble_technical_file(finalize=true) freezes this version."
                )
            )
        )
        return result

    if missing:
        # Refusing here is the point of the flag: a frozen file with holes is
        # a document that looks finished, and the freeze is what a signature
        # later binds to.
        raise InvalidState(
            "cannot finalize with "
            f"{len(missing)} mandatory section(s) empty: "
            f"{', '.join(s['slot'] for s in missing)}. Freezing an incomplete "
            "file produces a document that looks finished — fill them, or "
            "record why they are empty as evidence against the slot."
        )


    def _apply(state, db):
        snapshot = Evidence(
            product_id=product_id,
            subject_ref="technical_file:assembled",
            title=f"Annex VII technical file — {state.name}",
            kind=EvidenceKind.DOCUMENT.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=digest,
            source_ref=f"cra-mcp assemble_technical_file finalize=true",
            added_by_user_id=actor_id or None,
        )
        db.add(snapshot)
        db.flush()
        snapshot_id = snapshot.id
        # Same transaction as the artefact. S3 cannot be atomic with Postgres,
        # so the intent is made durable where atomicity is available and the
        # upload is reconciled afterwards — there is no path that freezes a
        # file with no export row. See `statutory_export`.
        statutory_export.record(
            db,
            product_id=product_id,
            kind=statutory_export.TECHNICAL_FILE,
            payload={"content_hash": digest, "evidence_id": snapshot_id, "file": payload},
            retention=retention,
            digest=digest,
        )
        audit.record(
            db,
            product_id=product_id,
            subject_type="technical_file",
            subject_id=snapshot_id,
            op="finalize_technical_file",
            accountable_user_id=actor_id or None,
            rationale=f"Annex VII frozen at {digest[:12]}",
            payload={"slots": len(slots)},
            after_hash=digest,
        )

        # The snapshot row, its audit event and the hash on the blob are one
        # transaction now. Before, a failure between them left a product
        # claiming a frozen technical file whose snapshot did not exist — or a
        # snapshot with nothing pointing at it.
        state.technical_file_hash = digest
        state.technical_file_evidence_id = snapshot_id
        state.technical_file_finalized_at = _now()
        return state, snapshot_id

    snapshot_id = store_backend.mutate(product_id, _apply)

    result.update(
        finalized=True,
        evidence_id=snapshot_id,
        next=(
            "Frozen. Now generate_declaration_of_conformity() — it will bind "
            "to this hash. Re-freeze afterwards so Annex VII(7) holds a copy "
            "of the declaration, then sign_off() the complete version."
            if deferred
            else (
                "Frozen and complete. sign_off(subject='technical_file') to "
                "attest to this version — the signature binds to this content "
                "hash, so any later edit stops matching it."
            )
        ),
    )
    return result


# ---- Declaration of Conformity ----------------------------------------------


def generate_declaration_of_conformity(
    *,
    product_id: str,
    actor_id: str = "",
    product_identification: Optional[str] = None,
    standards_applied: Optional[str] = None,
    notified_body: Optional[str] = None,
) -> dict:
    """Draft the Annex V declaration. A draft — a human signs it."""
    state = _load(product_id)
    _member(state, actor_id, minimum=Role.MAINTAINER)

    if state.economic_operator_role == "open_source_steward":
        raise InvalidState(
            "an open-source steward does not issue an EU Declaration of "
            "Conformity — the steward regime under Article 24 carries a "
            "different, lighter obligation set. This tool is not applicable "
            "to this product."
        )
    if state.classification.in_scope is not True:
        raise InvalidState(
            "classify the product in scope before drafting a declaration."
        )
    if not state.technical_file_hash:
        raise InvalidState(
            "no finalized technical file. Annex V(6) and the declaration as a "
            "whole rest on it, so run assemble_technical_file(finalize=true) "
            "first — a declaration signed against a file that can still change "
            "means nothing."
        )

    spec = class_spec(_ENUM_TO_CLASS.get(state.classification.product_class, "default"))
    if spec.notified_body_required and not notified_body:
        raise InvalidState(
            f"this product is {spec.id}, so Annex V(7) requires the notified "
            "body's name and number, the procedure performed, and the "
            "certificate. Pass notified_body='...'. Without a notified body "
            "the declaration cannot be issued at all."
        )

    values: dict[str, str] = {}
    missing: list[dict] = []
    for f in doc_fields():
        if f.source == "fixed":
            values[f.id] = f.text
        elif f.source == "product":
            values[f.id] = product_identification or state.name
        elif f.source == "submitter":
            if state.submitter.legal_name:
                values[f.id] = state.submitter.legal_name
            else:
                missing.append({"field": f.id, "anchor": f.anchor, "title": f.title})
        elif f.source == "technical_file":
            if standards_applied:
                values[f.id] = standards_applied
            else:
                missing.append({"field": f.id, "anchor": f.anchor, "title": f.title})
        elif f.source == "manual":
            if notified_body:
                values[f.id] = notified_body
            elif f.required_when_notified_body and not spec.notified_body_required:
                # Annex V(7) is conditional. Where the class permits
                # self-assessment there is no notified body, so the field is
                # genuinely not applicable — and saying so beats leaving it
                # blank, because a blank rendered as "MISSING" reads as an
                # omission the signer should fix.
                values[f.id] = (
                    f"Not applicable — {spec.id} does not require a notified "
                    "body, provided the conformity route relied on is actually "
                    "available to this product."
                )
        elif f.source == "attestation":
            values[f.id] = "— to be completed on signature —"

    # Derived from `values`, not accumulated alongside it. The two used to be
    # built separately and disagreed: a `manual` field with no value and no
    # requirement was rendered "⚠️ MISSING" in the document while being absent
    # from `missing_fields`, so the tool's summary and its own document said
    # different things. Deriving makes them agree by construction.
    missing = [
        {"field": f.id, "anchor": f.anchor, "title": f.title}
        for f in doc_fields()
        if not values.get(f.id)
    ]

    lines = [
        "# EU Declaration of Conformity",
        "",
        "_Draft. Not signed, and not a conformity assessment._",
        "",
    ]
    for f in doc_fields():
        v = values.get(f.id)
        lines.append(f"**{f.anchor} — {f.title}**")
        lines.append(v if v else "⚠️ MISSING")
        lines.append("")
    markdown = "\n".join(lines)

    body = json.dumps(
        {
            "fields": values,
            "technical_file_hash": state.technical_file_hash,
            "drafted_at": _now().isoformat(),
        },
        indent=2,
        sort_keys=True,
    )
    digest = hashlib.sha256(body.encode()).hexdigest()

    def _apply(state, db):
        row = Evidence(
            product_id=product_id,
            subject_ref="technical_file:tf.7",
            title=f"EU Declaration of Conformity (draft) — {state.name}",
            kind=EvidenceKind.DOCUMENT.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=digest,
            source_ref="cra-mcp generate_declaration_of_conformity",
            added_by_user_id=actor_id or None,
        )
        db.add(row)
        db.flush()
        evidence_id = row.id
        statutory_export.record(
            db,
            product_id=product_id,
            kind=statutory_export.DECLARATION,
            payload={"content_hash": digest, "evidence_id": evidence_id, "body": body},
            retention=retention_status(state),
            digest=digest,
        )
        audit.record(
            db,
            product_id=product_id,
            subject_type="declaration_of_conformity",
            subject_id=evidence_id,
            op="generate_declaration_of_conformity",
            accountable_user_id=actor_id or None,
            payload={
                "technical_file_hash": state.technical_file_hash,
                "missing_fields": [m["field"] for m in missing],
            },
            after_hash=digest,
        )

        state.conformity_declaration_hash = digest
        state.conformity_declaration_evidence_id = evidence_id
        state.conformity_declaration_missing = [m["field"] for m in missing]
        return state, evidence_id

    evidence_id = store_backend.mutate(product_id, _apply)

    return {
        "ok": True,
        "draft": True,
        "evidence_id": evidence_id,
        "content_hash": digest,
        "technical_file_hash": state.technical_file_hash,
        "missing_fields": missing,
        "markdown": markdown,
        "next": (
            "Fill the missing fields, then sign_off(subject='declaration') "
            "with the name and function of the person taking responsibility. "
            "Affixing the CE marking is a separate act you perform yourself."
        ),
        "disclaimer": _DISCLAIMER,
    }


# ---- the simplified declaration (Article 13(20)) --------------------------------


def _valid_public_url(value: str) -> Optional[str]:
    """Why the address is validated in shape and never fetched.

    Article 13(20) wants "the exact internet address at which the full EU
    declaration of conformity can be accessed", so a placeholder or a relative
    path fails the paragraph outright and is worth refusing. Whether the page
    at that address actually holds the declaration is a different question,
    and one this tool must not pretend to answer: fetching a user-supplied URL
    server-side is an SSRF surface, and a 200 response would prove only that
    something is served there.

    Same discipline as `disclosure_policy_url`, which the coverage page already
    says is stored and never fetched. The tool keeps the address with the
    record; standing behind what is published there is the manufacturer's.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return "could not be parsed as a URL"
    if parsed.scheme not in ("https", "http"):
        return "must be an absolute http(s) URL"
    if not parsed.netloc or "." not in parsed.netloc:
        return "has no host — an intranet name or a bare path is not an address a user can reach"
    return None


def _simplified(state, url: str, spec) -> tuple[str, dict]:
    """The Annex V fields that carry over, plus the address 13(20) requires.

    The CRA gives no template for the simplified form — unlike the Radio
    Equipment Directive, which specifies one. 13(20) says only that it must
    contain the exact internet address of the full declaration. So this stays
    deliberately short: the identifying fields a reader needs to know *which*
    declaration is being pointed at, the statement of conformity, and the
    address. Inventing further structure would give it an authority the
    regulation does not.
    """
    fields = {f.id: f for f in doc_fields()}
    values = {
        "product": state.name,
        "manufacturer": state.submitter.legal_name,
        "full_declaration_url": url.strip(),
        "technical_file_hash": state.technical_file_hash,
        "full_declaration_hash": state.conformity_declaration_hash,
    }
    lines = [
        "# Simplified EU Declaration of Conformity",
        "",
        "_Article 13(20). Provided in place of a full copy; the full "
        "declaration is at the address below._",
        "",
        f"**{fields['doc.1'].anchor} — Product**",
        state.name,
        "",
        f"**{fields['doc.2'].anchor} — Manufacturer**",
        state.submitter.legal_name or "⚠️ MISSING",
        "",
        f"**{fields['doc.5'].anchor} — Statement of conformity**",
        fields["doc.5"].text,
        "",
        "**Article 13(20) — Full declaration**",
        f"The full EU Declaration of Conformity is available at: {url.strip()}",
        "",
    ]
    return "\n".join(lines), values


def generate_simplified_declaration(
    *,
    product_id: str,
    actor_id: str = "",
    full_declaration_url: str,
) -> dict:
    """The Article 13(20) short form, pointing at where the full one is published.

    Refuses without a well-formed address, because an address-less simplified
    declaration does not satisfy the paragraph — the address is the entire
    reason the short form is permitted.
    """
    state = _load(product_id)
    _member(state, actor_id, minimum=Role.MAINTAINER)

    if state.economic_operator_role == "open_source_steward":
        raise InvalidState(
            "an open-source steward does not issue an EU Declaration of "
            "Conformity, simplified or otherwise — Article 24 is a different, "
            "lighter regime."
        )
    if not state.conformity_declaration_hash:
        raise InvalidState(
            "there is no full declaration to point at yet. 13(20) permits the "
            "short form *instead of a copy of the full one*, so the full one "
            "has to exist first: generate_declaration_of_conformity()."
        )
    if not full_declaration_url or not full_declaration_url.strip():
        raise InvalidState(
            "full_declaration_url is required. Article 13(20) says the "
            "simplified declaration shall contain the exact internet address "
            "at which the full declaration can be accessed — without it there "
            "is no simplified declaration, only a shorter one that does not "
            "comply. Publish the full declaration somewhere durable and pass "
            "that address."
        )
    problem = _valid_public_url(full_declaration_url)
    if problem:
        raise InvalidState(
            f"full_declaration_url {problem}. 13(20) asks for the *exact* "
            "internet address at which the full declaration can be accessed, "
            "which a reader has to be able to type."
        )

    spec = class_spec(_ENUM_TO_CLASS.get(state.classification.product_class, "default"))
    markdown, values = _simplified(state, full_declaration_url, spec)
    body = json.dumps(
        {"fields": values, "form": "simplified", "article": "13(20)"},
        indent=2,
        sort_keys=True,
    )
    digest = hashlib.sha256(body.encode()).hexdigest()

    def _apply(state, db):
        row = Evidence(
            product_id=product_id,
            subject_ref="technical_file:tf.7",
            title=f"Simplified EU Declaration of Conformity — {state.name}",
            kind=EvidenceKind.DOCUMENT.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=digest,
            source_ref="cra-mcp generate_simplified_declaration",
            applies_to_version=(
                state.releases[-1].version if state.releases else None
            ),
            added_by_user_id=actor_id or None,
        )
        db.add(row)
        db.flush()
        evidence_id = row.id
        statutory_export.record(
            db,
            product_id=product_id,
            kind=statutory_export.SIMPLIFIED_DECLARATION,
            payload={"content_hash": digest, "evidence_id": evidence_id, "body": body},
            retention=retention_status(state),
            digest=digest,
        )
        # The address is part of the record, not just the rendered document:
        # 13(20) makes it a required element, so it has to survive the
        # markdown being thrown away.
        state.conformity_declaration_url = full_declaration_url.strip()
        audit.record(
            db,
            product_id=product_id,
            subject_type="declaration_of_conformity",
            subject_id=evidence_id,
            op="generate_simplified_declaration",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            payload={
                "form": "simplified",
                "full_declaration_url": full_declaration_url.strip(),
                "points_at_hash": state.conformity_declaration_hash,
            },
            after_hash=digest,
        )
        return state, evidence_id

    evidence_id = store_backend.mutate(product_id, _apply)

    out = {
        "ok": True,
        "form": "simplified",
        "evidence_id": evidence_id,
        "content_hash": digest,
        "full_declaration_url": full_declaration_url.strip(),
        "points_at_declaration_hash": state.conformity_declaration_hash,
        "markdown": markdown,
        "address_not_checked": (
            "The address is recorded exactly as given and is never fetched. "
            "This tool cannot confirm that the full declaration is published "
            "there, that it stays there, or that it is the version this points "
            "at — keeping it reachable is yours."
        ),
        "next": (
            "Ship this with the product in place of a full copy. If the full "
            "declaration is re-issued, its hash changes and this short form "
            "points at a superseded version — regenerate both."
        ),
        "disclaimer": _DISCLAIMER,
    }
    if not state.submitter.legal_name:
        out["missing_fields"] = [
            {"field": "doc.2", "anchor": "Annex V(2)", "title": "Manufacturer"}
        ]
        out["care"] = (
            "The manufacturer's name is empty, so the short form does not "
            "identify who is declaring. set_submitter_profile(legal_name=...)."
        )
    return out


# ---- sign-off ----------------------------------------------------------------

_SUBJECTS = {
    "technical_file": ("technical_file_hash", "technical_file"),
    "declaration": ("conformity_declaration_hash", "declaration_of_conformity"),
}


def sign_off(
    *,
    product_id: str,
    actor_id: str = "",
    subject: str = "technical_file",
    signer_name: str,
    signer_role: str,
    statement: str,
    require_independent: bool = False,
) -> dict:
    """Attest to a specific frozen version. Binds to its content hash."""
    if subject not in _SUBJECTS:
        raise InvalidState(f"subject must be one of {sorted(_SUBJECTS)}")
    attr, subject_type = _SUBJECTS[subject]

    state = _load(product_id)
    _member(state, actor_id, minimum=Role.OWNER)

    version_hash = getattr(state, attr, None)
    if not version_hash:
        raise InvalidState(
            f"there is no frozen {subject.replace('_', ' ')} to sign. A "
            "signature against a document that can still change is worthless."
        )
    if not statement.strip() or not signer_name.strip() or not signer_role.strip():
        raise InvalidState(
            "signer_name, signer_role and statement are all required — the "
            "declaration names a person taking responsibility, not an account."
        )

    # The declaration signed with holes in it until 2026-08-09. An end-to-end
    # run drew one up, was told in the same response that Annex V(2) — the
    # manufacturer's name and address — could not be filled, signed it, and got
    # a clean confirmation that said nothing about it.
    #
    # `assemble_technical_file(finalize=True)` has refused an incomplete file
    # from the start, on the stated grounds that freezing one "produces a
    # document that looks finished". The declaration is the document that
    # carries the legal weight — it is what CE marking rests on — so it has the
    # stronger claim to the same rule, not a weaker one.
    #
    # No override. `record_release` has one because shipping with something
    # outstanding is a decision a manufacturer is entitled to make; declaring
    # conformity on a document with a mandatory field blank is not the same kind
    # of act, and Annex V lists what a declaration contains rather than what it
    # should usually contain.
    if subject == "declaration" and state.conformity_declaration_missing:
        fields = ", ".join(state.conformity_declaration_missing)
        raise InvalidState(
            f"this declaration is missing {len(state.conformity_declaration_missing)} "
            f"mandatory Annex V field(s): {fields}. Signing it would put a named "
            "person's statement of responsibility against a document with blanks "
            "in it, kept for ten years. Fill them — "
            "generate_declaration_of_conformity() again with the missing "
            "arguments, or set_submitter_profile() for the manufacturer's "
            "details — and the redraft will supersede this one."
        )

    with session_scope() as db:
        existing = db.execute(
            select(Attestation).where(
                Attestation.product_id == product_id,
                Attestation.subject_type == subject_type,
                Attestation.subject_version_hash == version_hash,
            )
        ).scalars().first()
        if existing is not None:
            raise InvalidState(
                f"this version was already signed by {existing.signer_name} on "
                f"{existing.signed_at.date().isoformat()}."
            )

        if require_independent:
            last_editor = _last_editor(db, product_id, subject_type)
            if last_editor and last_editor == actor_id:
                raise InvalidState(
                    "segregation of duties: you are the last person to have "
                    "changed this, so you cannot also attest to it. Have "
                    "another owner sign, or call again without "
                    "require_independent if your organisation does not "
                    "separate these roles."
                )

        row = Attestation(
            product_id=product_id,
            subject_type=subject_type,
            subject_id=getattr(state, f"{subject}_evidence_id", None)
            if subject == "technical_file"
            else state.conformity_declaration_evidence_id,
            subject_version_hash=version_hash,
            # The declaration's hash is taken over its own rendered body rather
            # than the technical-file payload, so it is unversioned by this
            # scheme; recording the version anyway keeps every row comparable on
            # the same terms and costs nothing.
            hash_payload_version=HASH_PAYLOAD_VERSION,
            signer_user_id=actor_id or "unknown",
            signer_name=signer_name.strip(),
            signer_role=signer_role.strip(),
            statement=statement.strip(),
            signed_at=_now(),
        )
        db.add(row)
        db.flush()
        attestation_id = row.id
        statutory_export.record(
            db,
            product_id=product_id,
            kind=statutory_export.SIGN_OFF,
            payload={
                "attestation_id": attestation_id,
                "subject_type": subject_type,
                "subject_version_hash": version_hash,
                "signer_name": signer_name.strip(),
                "signer_role": signer_role.strip(),
                "statement": statement.strip(),
                "signed_at": row.signed_at.isoformat(),
            },
            retention=retention_status(state),
            digest=version_hash,
        )

        audit.record(
            db,
            product_id=product_id,
            subject_type=subject_type,
            subject_id=attestation_id,
            op="sign_off",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=statement.strip()[:500],
            payload={
                "signer_name": signer_name.strip(),
                "signer_role": signer_role.strip(),
                "independent": require_independent,
            },
            before_hash=version_hash,
        )

    return {
        "ok": True,
        "attestation_id": attestation_id,
        "subject": subject,
        "bound_to_hash": version_hash,
        "signer": signer_name.strip(),
        "note": (
            "Bound to this exact version. If the document changes, the "
            "signature no longer covers it and a fresh sign-off is required — "
            "which is the whole point of the hash."
        ),
        "disclaimer": _DISCLAIMER,
    }


def _last_editor(db, product_id: str, subject_type: str) -> Optional[str]:
    row = db.execute(
        select(Evidence)
        .where(
            Evidence.product_id == product_id,
            Evidence.subject_ref.like("technical_file:%"),
        )
        .order_by(Evidence.collected_at.desc())
        .limit(1)
    ).scalars().first()
    return row.added_by_user_id if row else None


def get_conformity_status(*, product_id: str, actor_id: str = "") -> dict:
    """Where this product stands on the 2027 half: file, declaration, signatures."""
    state = _load(product_id)
    _member(state, actor_id)

    with session_scope() as db:
        rows = list(
            db.execute(
                select(Attestation).where(Attestation.product_id == product_id)
            ).scalars()
        )
        attestations = [
            {
                "subject_type": a.subject_type,
                "signer_name": a.signer_name,
                "signer_role": a.signer_role,
                "signed_at": a.signed_at.isoformat(),
                "bound_to_hash": a.subject_version_hash,
                **_coverage(
                    a,
                    state.technical_file_hash
                    if a.subject_type == "technical_file"
                    else state.conformity_declaration_hash,
                ),
            }
            for a in rows
        ]

    settled = sum(
        1
        for i in state.requirements
        if i.applicability == Applicability.NOT_APPLICABLE
        or i.status in (RequirementStatus.IMPLEMENTED, RequirementStatus.VERIFIED)
    )

    # Everything above this line is a green tick, and an agent asked "where do
    # we stand" composes its answer from green ticks. The disclaimer underneath
    # is true and does not help: it disclaims the conclusion rather than
    # correcting the inputs, and a reader who has just been shown 22/22 settled,
    # a frozen file and a signature will summarise it as "you are done".
    #
    # An end-to-end run did exactly that, and said so: "the strongest
    # honest-seeming summary is 'you're done' — I would have sent that, and it
    # is false." What was absent was not a conclusion but three facts.
    #
    # So this list exists to carry the things that would make the obvious
    # summary wrong. It is deliberately phrased as what is *not* established,
    # never as a verdict.
    qualifications: list[dict] = []

    if state.conformity_declaration_missing:
        qualifications.append({
            "about": "declaration_of_conformity",
            "detail": (
                f"{len(state.conformity_declaration_missing)} mandatory Annex V "
                f"field(s) are blank: "
                f"{', '.join(state.conformity_declaration_missing)}."
            ),
        })

    unbased = [
        i.req_id
        for i in state.requirements
        if i.applicability == Applicability.APPLICABLE and not i.risk_basis
    ]
    if unbased:
        qualifications.append({
            "about": "requirements",
            "detail": (
                f"{len(unbased)} requirement(s) counted as settled are marked "
                "applicable with no risk from the Article 13(2) assessment "
                "behind them. Not a gap — a requirement can apply for reasons "
                "the assessment did not enumerate — but Annex VII(3) asks what "
                "each determination rested on."
            ),
            "requirements": unbased,
        })

    if not state.releases:
        qualifications.append({
            "about": "evidence",
            "detail": (
                "No release has been recorded, so no evidence on this product "
                "is tied to a version. Annex I attaches to the product as "
                "placed on the market, and nothing here yet says which build "
                "any of it describes."
            ),
        })

    return {
        "ok": True,
        "product_id": product_id,
        "in_scope": state.classification.in_scope,
        "product_class": state.classification.product_class,
        "conformity_route": state.classification.conformity_route,
        "requirements": {"total": len(state.requirements), "settled": settled},
        "technical_file": {
            "finalized": bool(state.technical_file_hash),
            "content_hash": state.technical_file_hash,
            "finalized_at": (
                state.technical_file_finalized_at.isoformat()
                if state.technical_file_finalized_at
                else None
            ),
        },
        "declaration_of_conformity": {
            "drafted": bool(state.conformity_declaration_hash),
            "content_hash": state.conformity_declaration_hash,
            "missing_fields": list(state.conformity_declaration_missing),
        },
        "attestations": attestations,
        # Kept meaning what the word says: the document moved after it was
        # signed. A signature that merely predates a change in how the hash is
        # computed is listed separately — calling it stale would assert an edit
        # nobody made.
        "stale_signatures": [
            a for a in attestations if a["coverage"] == "superseded"
        ],
        "unverifiable_signatures": [
            a for a in attestations if a["coverage"] == "incomparable"
        ],
        "qualifications": qualifications,
        "disclaimer": _DISCLAIMER,
    }


_dispatch.register_mutating("assemble_technical_file", assemble_technical_file)
_dispatch.register_mutating(
    "generate_declaration_of_conformity", generate_declaration_of_conformity
)
_dispatch.register_mutating(
    "generate_simplified_declaration", generate_simplified_declaration
)
_dispatch.register_mutating("sign_off", sign_off)
_dispatch.register_read("get_conformity_status", get_conformity_status)
