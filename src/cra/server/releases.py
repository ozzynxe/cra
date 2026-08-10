"""Releases, and the Annex I Pt I(2)(a) gate that guards them.

Annex I Pt I(2)(a) bars *making available on the market* a product with known
exploitable vulnerabilities. Every word of that is about an instant — the
moment a particular version goes out — and until this module existed the tool
could only describe the present. `scan_advisories` says what is true today; the
requirement is about the day you shipped.

So a release is two things at once here. It is the anchor evidence hangs off
(`annex.evidence_currency`: a test report is a claim about one build, not a
timeless fact), and it is the moment the I(2)(a) determination is made and
frozen.

**The gate refuses, but it always has a way through.** Two families of
condition stop a release, and one `accepted_rationale` waives all of them
together — because shipping anyway is a decision a manufacturer is entitled to
make, and the tool's job is to make sure it is made out loud. That is the
`dismiss_advisory` shape: you may proceed, the price is saying why, and what
you said is kept.

*The scan* — no scan has ever run, the last one could not reach its feeds, open
candidates remain, or it is too old to stand behind. These are the I(2)(a)
determination itself.

*The vulnerabilities* — a confirmed, actively exploited one with no remediation
recorded. Separate from the candidate count because confirming a candidate
*closes* it, so until 2026-08-09 the way to clear an exploited advisory out of
this gate was to agree that the product was affected. An end-to-end run did
exactly that and shipped, with an unfiled 24-hour Article 14 clock running and
the frozen position recording `exploited_open: 0`.

*The record* — no confirmed Article 13(2) risk assessment, an assessment gone
stale, missing 13(3) Part I(1)/Part II statements, or Annex I requirements
still unsettled. These are not about known vulnerabilities; they are here
because **placing on the market is the moment working state becomes the record
an authority may ask for**, and checking it at the transition is better than
keeping everything indefinitely against the chance it is needed. `_is_gap` is
reused rather than reimplemented, so "settled" means here exactly what it means
in the technical file.

One escape hatch rather than eight on purpose. Separate flags would let someone
silence the conditions one at a time until nothing was being asserted at all.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from cra.agents import dispatch as _dispatch
from cra.db import Evidence, session_scope
from cra.schemas import Release, ReleaseGate
from cra.schemas.enums import EvidenceKind, Lifecycle, Role
from cra.server import advisories, audit, risk, statutory_export, store_backend
from cra.server.annex import _is_gap
from cra.server.errors import InvalidState
from cra.server.scoping import _load, _member
from cra.server.timestamps import parse_ts_utc

log = logging.getLogger(__name__)

# The Annex I requirement this gate is a determination about.
I2A = "annex_i.i.2.a"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _max_scan_age_days() -> float:
    """How stale a scan may be and still back a release determination.

    Seven days by default. This is a freshness bound, not a security threshold:
    a scan from three weeks ago says almost nothing about a build going out
    today, and letting one satisfy the gate would make the whole check theatre.

    Like every other limit here it is waivable with a rationale rather than
    absolute, because "we scanned nine days ago and nothing has changed since"
    is a perfectly good answer that the tool is in no position to evaluate.
    """
    try:
        return float(os.environ.get("CRA_RELEASE_SCAN_MAX_AGE_DAYS", "7"))
    except ValueError:
        return 7.0


def _parse_ts(value: Optional[str], *, field: str) -> Optional[datetime]:
    return parse_ts_utc(value, field=field, what="a market placement")


def _conformity_blockers(state) -> list[dict]:
    """What has to be settled *before* a version is placed on the market.

    Placing on the market is the moment the record stops being working state
    and becomes the thing an authority may ask for, so it is the right place to
    check the record is actually there — rather than keeping everything
    indefinitely on the chance that it is needed later.

    These do not refuse a release outright. They are blockers in the same sense
    as the scan ones: one `accepted_rationale` waives all of them together, and
    the reasoning lands on the frozen determination and the audit row. Refusing
    outright would be stricter than the regulation — Annex I Pt I(2)(a) is
    about known exploitable vulnerabilities specifically, not about the whole
    of Part I being finished — and this tool reports gaps rather than blocking
    work.
    """
    out: list[dict] = []
    ra = state.risk_assessment

    if not (ra and ra.content_hash):
        out.append(
            {
                "blocker": "no_confirmed_risk_assessment",
                "detail": (
                    "Annex I Pt I applies *on the basis of* the Article 13(2) "
                    "risk assessment, so releasing without a confirmed one "
                    "leaves every applicability decision resting on nothing. "
                    "start_risk_assessment(), then confirm_risk_assessment()."
                ),
            }
        )
    else:
        stale = risk.staleness(state)
        if stale:
            out.append(
                {
                    "blocker": "risk_assessment_stale",
                    "detail": (
                        "The confirmed assessment no longer describes this "
                        "product: "
                        + "; ".join(s.get("reason", str(s)) for s in stale)
                        + ". Article 13(3) requires it kept current."
                    ),
                    "stale_reasons": stale,
                }
            )
        # Only reachable for assessments confirmed before these became
        # mandatory — `confirm_risk_assessment` has required both since.
        # Kept because a legacy assessment is exactly the one nobody rechecks.
        if not ra.part_i_1_approach.strip() or not ra.part_ii_approach.strip():
            out.append(
                {
                    "blocker": "missing_13_3_statements",
                    "detail": (
                        "Article 13(3) asks the assessment to indicate how "
                        "Annex I Pt I(1) and the Part II vulnerability "
                        "handling requirements are applied. Neither falls out "
                        "of the per-risk determinations, and Annex VII(3) "
                        "cites the frozen assessment — so all of 13(3) has to "
                        "be in it, not two thirds."
                    ),
                }
            )

    unsettled = [i.req_id for i in state.requirements if _is_gap(i)]
    if unsettled:
        shown = ", ".join(unsettled[:6]) + ("…" if len(unsettled) > 6 else "")
        out.append(
            {
                "blocker": "requirements_unsettled",
                "detail": (
                    f"{len(unsettled)} Annex I requirement(s) are neither "
                    "settled nor ruled out with a justification: "
                    f"{shown}. An undetermined requirement is a gap, not a "
                    "to-do — it reaches an auditor as something nobody "
                    "considered."
                ),
                "requirements": unsettled,
            }
        )

    return out


def _exploited_blocker(vulns) -> Optional[dict]:
    """A confirmed, actively exploited vulnerability with no fix recorded.

    The gate used to count only open *candidates*, and confirming a candidate
    closes it. So the way to clear an exploited advisory out of the gate was to
    confirm it — to agree the product really is affected. An end-to-end run did
    exactly that and shipped, with an unfiled 24-hour Article 14 clock running
    and the frozen determination recording `exploited_open: 0`.

    Annex I Pt I(2)(a) bars placing a product on the market with a known
    exploitable vulnerability. A confirmed actively exploited one is the
    strongest instance of that there is, and it was the one case the gate did
    not see.
    """
    if not vulns:
        return None
    named = ", ".join(
        (v.identifier or v.summary or v.id)[:60] for v in vulns[:5]
    ) + ("…" if len(vulns) > 5 else "")
    return {
        "blocker": "exploited_vulnerability_unremediated",
        "detail": (
            f"{len(vulns)} confirmed, actively exploited vulnerability(ies) "
            f"with no remediation recorded: {named}. Annex I Pt I(2)(a) bars "
            "placing a product on the market with a known exploitable "
            "vulnerability, and a confirmed exploited one is the clearest case "
            "of it. Record what fixes it — update_vulnerability with "
            "remediation_ref or corrective_measure_available_at — or say why "
            "you are shipping anyway."
        ),
        "vulnerability_ids": [v.id for v in vulns],
    }


def _scan_build_blocker(scan, version: str) -> Optional[dict]:
    """Did the scan behind this release actually check this build?

    The seven-day bound is a *time* check. A major version recorded minutes
    after the last one passes it while resting on the previous build's component
    list — which an end-to-end run did: 1.0.0 and then 2.0.0, no new SBOM, no
    new scan, and 2.0.0's frozen Annex I Pt I(2)(a) position carrying 1.0.0's
    evidence with nothing said about it.

    Annex I attaches to the product *as placed on the market*, and this is the
    one requirement specifically about that moment. Everything else in this
    codebase already treats evidence as a claim about one build —
    `evidence_currency` moved thirteen requirements to "evidenced against an
    earlier release" the instant the version moved. A scan is evidence too, and
    it was the only kind that crossed a version boundary silently.

    Unknown is not a match. A scan whose SBOM carried no version cannot show it
    covered this one, and saying so is the whole point.
    """
    if scan is None:
        return None                      # `never_scanned` already covers it
    scanned = getattr(scan, "sbom_applies_to_version", None)
    if scanned is None or scanned == version:
        # Unknown is not a mismatch. A bill of materials carrying no version
        # cannot show it describes this build, and it cannot show it describes a
        # different one either — so it is reported and not blocked, exactly as
        # `evidence_currency` reports `unversioned` without counting it a gap.
        # Blocking on an absence would also make the gate fire on the ordinary
        # case of an untagged SBOM, and a gate that fires on the ordinary case
        # teaches people to reach for the override.
        return None
    return {
        "blocker": "scan_covers_a_different_build",
        "detail": (
            f"The last scan ran against the component list recorded for "
            f"{scanned!r}, not {version!r}. Annex I Pt I(2)(a) is about the "
            "product as placed on the market, so a determination for this "
            "release cannot rest on a different build's components. "
            f"record_sbom(version={version!r}) with what this build ships, then "
            "scan_advisories()."
        ),
        "scanned_build": scanned,
        "releasing": version,
    }


def _blockers(
    state, scan, open_count: int, exploited_open: int, released_at: datetime,
    exploited_vulns=(), version: str = "",
) -> list[dict]:
    """What stands between this release and a clean I(2)(a) determination.

    Returned as data rather than raised so every reason travels together. Being
    told about the open candidates, fixing them, and only then being told the
    scan is also too old is the interaction that teaches people to reach
    straight for the override.

    Conformity blockers are computed first and unconditionally, so a product
    that has never been scanned still hears about its missing risk assessment
    in the same breath. The scan checks short-circuit among themselves — there
    is nothing to say about the age of a scan that never ran — but that must
    not swallow the rest.

    The exploited-vulnerability check is outside the scan short-circuit for the
    same reason: a confirmed exploited vulnerability is a fact about the
    product, not about whether a scan happened, and a product that has never
    been scanned must still hear about it.
    """
    out: list[dict] = _conformity_blockers(state)
    exploited = _exploited_blocker(list(exploited_vulns))
    if exploited:
        out.append(exploited)
    build = _scan_build_blocker(scan, version) if version else None
    if build:
        out.append(build)
    if scan is None:
        out.append(
            {
                "blocker": "never_scanned",
                "detail": (
                    "No advisory scan has ever run for this product, so there "
                    "is nothing behind a claim that it ships without known "
                    "exploitable vulnerabilities. Run scan_advisories()."
                ),
            }
        )
        return out

    if not scan.sources_ok:
        out.append(
            {
                "blocker": "scan_incomplete",
                "detail": (
                    "The last scan could not reach one of its feeds, so it "
                    "found nothing for a reason that has nothing to do with "
                    "your product. A failed fetch and a clean result are the "
                    "same zero. Re-run scan_advisories()."
                ),
            }
        )

    age_days = (released_at - scan.ran_at).total_seconds() / 86400.0
    limit = _max_scan_age_days()
    if age_days > limit:
        out.append(
            {
                "blocker": "scan_too_old",
                "detail": (
                    f"The last scan ran {age_days:.1f} days before this release "
                    f"date, over the {limit:g}-day bound. Feeds move daily; a "
                    "determination resting on an old scan is not one an auditor "
                    "would accept."
                ),
            }
        )

    if open_count:
        out.append(
            {
                "blocker": "open_candidates",
                "detail": (
                    f"{open_count} advisory candidate(s) are still unresolved"
                    + (f", {exploited_open} of them actively exploited" if exploited_open else "")
                    + ". Each needs an exploitability determination — confirm "
                    "it, or dismiss it with a VEX justification. Working a "
                    "candidate to a disposition *is* the Art 3(41) judgement "
                    "this requirement asks for."
                ),
            }
        )
    return out


def _open_candidate_view(open_count: int, scan_view) -> Optional[int]:
    """`None` where nothing was ever looked for, rather than `0`.

    A product that has never been scanned has no open candidates, so the honest
    count is nought and the honest report is not. Zero beside a null `last_scan`
    reads as "none found" — good news — when it means "never looked", and it is
    the one number in a release response a summarising agent will repeat.

    Same rule as EPSS, where a missing score is unscored and never low, and as
    `scan_incomplete`, which exists because a failed fetch and a clean result
    are the same zero.
    """
    return open_count if scan_view is not None else None


def record_release(
    *,
    product_id: str,
    actor_id: str = "",
    version: str,
    released_at: Optional[str] = None,
    source_ref: str = "",
    notes: str = "",
    accepted_rationale: str = "",
) -> dict:
    """Record a version as placed on the market, with its I(2)(a) determination.

    Refuses if the record cannot support the claim: the advisory picture (no
    scan, a scan that could not reach its feeds, one older than seven days,
    unresolved candidates) or the file behind it (no confirmed Article 13(2)
    assessment, a stale one, missing 13(3) statements, unsettled Annex I
    requirements). `accepted_rationale` overrides all of them together and is
    kept on the record: shipping anyway is allowed, shipping anyway quietly is
    not.
    """
    if not version.strip():
        raise InvalidState(
            "version is required — it is what evidence is tied to. Use whatever "
            "identifier you actually ship under; it is stored verbatim and "
            "never parsed."
        )
    version = version.strip()
    when = _parse_ts(released_at, field="released_at") or _now()

    with session_scope() as db:
        scan = advisories.latest_scan(db, product_id)
        open_count, exploited_open = advisories.open_candidate_counts(db, product_id)
        # Local import: `reporting` and this module would otherwise cycle, the
        # same reason `advisories` imports it this way.
        from cra.server import reporting  # noqa: WPS433

        exploited_vulns = reporting.unremediated_exploited(db, product_id)
        exploited_vuln_ids = [v.id for v in exploited_vulns]
        scan_view = (
            {
                "ran_at": scan.ran_at.isoformat(),
                "sources_ok": scan.sources_ok,
                "components_checked": scan.components_checked,
                "findings": scan.findings,
                "exploited": scan.exploited,
                # Which build's component list this scan checked. In the frozen
                # determination this is the difference between "we checked what
                # we shipped" and "we checked something else" — and a waived
                # release has to carry that distinction into the artefact, not
                # only into the refusal it overrode.
                "sbom_applies_to_version": getattr(
                    scan, "sbom_applies_to_version", None
                ),
            }
            if scan
            else None
        )
        scan_at = scan.ran_at if scan else None
        scan_sources_ok = bool(scan and scan.sources_ok)

    # Read for the gate only. `_apply` re-reads under `FOR UPDATE`, so the
    # *write* is consistent even where this copy went a moment stale — and the
    # scan blockers above are already computed outside the lock for the same
    # reason. A gate that reports and can be waived is not a place to add a
    # lock; the last-owner and plan-cap guards are, and they live inside `fn`.
    state = _load(product_id)
    _member(state, actor_id, minimum=Role.MAINTAINER)

    blockers = _blockers(
        state, scan, open_count, exploited_open, when,
        exploited_vulns=exploited_vulns, version=version,
    )
    if blockers and not accepted_rationale.strip():
        return {
            "ok": False,
            "code": "release_gate_blocked",
            "version": version,
            "blockers": blockers,
            "last_scan": scan_view,
            "what_this_means": (
                "Annex I Pt I(2)(a) bars placing a product on the market with a "
                "known exploitable vulnerability. Nothing here says your product "
                "has one — it says the record cannot currently support the "
                "statement that it does not."
            ),
            "next": (
                "Resolve the blockers above, or record the release anyway with "
                "accepted_rationale=... explaining why shipping is defensible. "
                "That reasoning is kept with the determination and is what an "
                "auditor would read."
            ),
        }

    age_days = (
        (when - scan_at).total_seconds() / 86400.0 if scan_at is not None else None
    )

    def _apply(state, db):
        _member(state, actor_id, minimum=Role.MAINTAINER)
        if state.classification.in_scope is not True:
            raise InvalidState(
                "this product is not recorded as in scope, so there is no Annex "
                "I determination to make. Run classify_product(in_scope=true)."
            )
        if any(r.version == version for r in state.releases):
            raise InvalidState(
                f"release {version!r} is already recorded. Versions are the "
                "anchor evidence hangs off, so one cannot be recorded twice."
            )

        determination = {
            "requirement": I2A,
            "requirement_text": (
                "Annex I Part I(2)(a) — made available on the market without "
                "known exploitable vulnerabilities."
            ),
            "product_id": product_id,
            "release": version,
            "released_at": when.isoformat(),
            "source_ref": source_ref,
            "scan": scan_view,
            "scan_age_days": round(age_days, 2) if age_days is not None else None,
            # Null where nothing was looked for. This is the artefact an
            # authority reads in ten years; `0` there is a claim.
            "open_candidates": _open_candidate_view(open_count, scan_view),
            "exploited_open": exploited_open,
            "blockers_accepted": blockers,
            "accepted_rationale": accepted_rationale.strip(),
            "determined_by": actor_id or None,
            "determined_at": _now().isoformat(),
            "caveat": (
                "A record of the exploitability position at the moment of "
                "placing on the market. It is not a statement that the product "
                "has no exploitable vulnerabilities — only that these feeds "
                "knew of none unresolved on this date, or that the ones "
                "outstanding were accepted for the stated reason."
            ),
        }
        body = json.dumps(determination, indent=2, sort_keys=True)
        digest = hashlib.sha256(body.encode()).hexdigest()

        row = Evidence(
            product_id=product_id,
            subject_ref=f"requirement:{I2A}",
            title=f"Annex I Pt I(2)(a) determination for release {version}",
            kind=EvidenceKind.DOCUMENT.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=digest,
            source_ref=source_ref or f"cra-mcp record_release {version}",
            applies_to_version=version,
            added_by_user_id=actor_id or None,
        )
        db.add(row)
        db.flush()
        # The release anchors the Article 13(13) retention clock, so it is part
        # of the record rather than only a pointer into it.
        statutory_export.record(
            db,
            product_id=product_id,
            kind=statutory_export.RELEASE,
            payload={
                "version": version,
                "released_at": when.isoformat(),
                "determination_sha256": digest,
                "evidence_id": row.id,
                "source_ref": source_ref,
                "blockers_accepted": blockers,
                "accepted_rationale": accepted_rationale,
            },
            digest=digest,
        )

        release = Release(
            version=version,
            released_at=when,
            source_ref=source_ref,
            notes=notes,
            recorded_at=_now(),
            recorded_by=actor_id or "",
            gate=ReleaseGate(
                scan_at=scan_at,
                scan_sources_ok=scan_sources_ok,
                scan_age_days=round(age_days, 2) if age_days is not None else None,
                open_candidates=_open_candidate_view(open_count, scan_view),
                exploited_open=exploited_open,
                exploited_vulnerabilities=len(exploited_vuln_ids),
                exploited_vulnerability_ids=exploited_vuln_ids,
                accepted_rationale=accepted_rationale.strip(),
                evidence_id=row.id,
            ),
        )
        state.releases.append(release)
        # The first and only writer of `lifecycle` in this codebase. Placing a
        # product on the market is what moves it, and `risk.staleness` exempts
        # this one transition so it does not demand a re-assessment mid-ship.
        if state.lifecycle == Lifecycle.IN_DEVELOPMENT:
            # `.value`, not the member. The blob schema sets
            # `use_enum_values=True`, which coerces on *validation* and not on
            # attribute assignment — so storing the member leaves an enum
            # object in a field every other writer keeps as a string.
            state.lifecycle = Lifecycle.PLACED_ON_MARKET.value

        item = next((i for i in state.requirements if i.req_id == I2A), None)
        if item is not None:
            item.evidence_ids.append(row.id)
            item.last_edited_by = actor_id or None
            item.last_edited_at = _now()

        audit.record(
            db,
            product_id=product_id,
            subject_type="release",
            subject_id=version,
            op="record_release",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=(accepted_rationale.strip() or f"Release {version}")[:500],
            payload={
                "version": version,
                "released_at": when.isoformat(),
                "open_candidates": open_count,
                "exploited_open": exploited_open,
                "blockers_accepted": [b["blocker"] for b in blockers],
                "evidence_id": row.id,
            },
            after_hash=digest,
        )
        return state, (row.id, digest, state.lifecycle)

    evidence_id, digest, lifecycle = store_backend.mutate(product_id, _apply)

    scanned_build = getattr(scan, "sbom_applies_to_version", None) if scan else None
    versioning = (
        f"Evidence attached from now on ties to {version} by default; anything "
        "evidenced only against earlier releases now reports as stale."
    )
    out = {
        "ok": True,
        "version": version,
        "released_at": when.isoformat(),
        "lifecycle": lifecycle,
        "determination_evidence_id": evidence_id,
        "determination_sha256": digest,
        # Null rather than 0 where nothing was ever looked for — see
        # `_open_candidate_view`.
        "open_candidates": _open_candidate_view(open_count, scan_view),
        "last_scan": scan_view,
        "not_retroactive": (
            "Candidates found after today do not make this release "
            "non-conformant. I(2)(a) is a statement about the moment of placing "
            "on the market; what happens afterwards is Article 13(8) and Annex "
            "I Pt II(2) — handle it, and report it if it turns out to be "
            "actively exploited."
        ),
    }
    if scan is not None and scanned_build is None:
        out["scan_build_unknown"] = (
            "The bill of materials behind this scan carries no version, so "
            f"nothing here shows it describes {version} rather than an earlier "
            "build. Not a finding either way — it is what is not established. "
            f"record_sbom(version={version!r}) before the next release and the "
            "determination can say which build it checked."
        )
    if scan_view is None:
        out["open_candidates_note"] = (
            "Null, not zero. No scan has ever run for this product, so nothing "
            "has been looked for — and a count of nought would read as 'none "
            "found' when what it means is 'never looked'."
        )

    if not blockers:
        out["note"] = (
            f"Release {version} recorded, with the Annex I Pt I(2)(a) position "
            f"frozen as evidence against it. {versioning}"
        )
        return out

    # The override, said in the headline rather than underneath it.
    #
    # Every field below already existed and the response was still relayed as a
    # clean release: an end-to-end run shipped past three blockers on the word
    # "fine" and reported it exactly as it would a clean one. The qualification
    # was there — `accepted_despite`, `accepted_rationale`, `care` — but it sat
    # three keys under a `note` that announced the I(2)(a) position had been
    # frozen as evidence, which is the sentence a summarising agent carries out.
    # What is frozen when blockers are waived is the waiver.
    codes = [b["blocker"] for b in blockers]
    out["note"] = (
        f"Release {version} recorded over {len(blockers)} unresolved "
        f"blocker(s) — {', '.join(codes)} — on the rationale "
        f"{accepted_rationale.strip()!r}. What is frozen against this release "
        "is that position: the blockers, and the reason given for shipping "
        "anyway. It is not a determination that the product ships without "
        f"known exploitable vulnerabilities. {versioning}"
    )
    out["accepted_despite"] = codes
    # The same objects the refusal returned, so nothing a caller was told when
    # it was refused is dropped from the record of it going through.
    out["blockers_accepted"] = blockers
    out["accepted_rationale"] = accepted_rationale.strip()
    out["care"] = (
        f"This release was recorded over {len(blockers)} blocker(s) on the "
        f"stated reason {accepted_rationale.strip()!r}. That reasoning is on "
        "the determination and in the audit trail, and it is what an auditor "
        "reads after an incident — not this response. If it would not carry "
        "the decision then, record a fuller one now."
    )
    # `not_retroactive` is about what turns up *later*. Left unqualified above
    # an accepted blocker it reads as cover for what is outstanding *today*,
    # which is the opposite of what Art 13(8) and Annex I Pt II(2) say.
    out["not_retroactive"] = (
        "This is about what turns up later, and it does not soften the "
        f"blocker(s) above, which were outstanding on {when.date().isoformat()}"
        ". " + out["not_retroactive"]
    )
    return out


def list_releases(*, product_id: str, actor_id: str = "") -> dict:
    """Versions placed on the market, oldest first, with their I(2)(a) position."""
    state = _load(product_id)
    _member(state, actor_id)

    items = [
        {
            "version": r.version,
            "released_at": r.released_at.isoformat() if r.released_at else None,
            "source_ref": r.source_ref,
            "notes": r.notes,
            "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
            "recorded_by": r.recorded_by,
            "i2a": {
                "scan_at": r.gate.scan_at.isoformat() if r.gate.scan_at else None,
                "scan_sources_ok": r.gate.scan_sources_ok,
                "scan_age_days": r.gate.scan_age_days,
                "open_candidates_at_release": r.gate.open_candidates,
                "exploited_open_at_release": r.gate.exploited_open,
                # Confirmed vulnerabilities, not candidates. This block used to
                # report only the candidate counts, so a release made with a
                # confirmed exploited vulnerability outstanding read as
                # `exploited_open_at_release: 0` — and this is the artefact an
                # auditor reads.
                "exploited_vulnerabilities_at_release": r.gate.exploited_vulnerabilities,
                "exploited_vulnerability_ids": list(r.gate.exploited_vulnerability_ids),
                "accepted_rationale": r.gate.accepted_rationale,
                "evidence_id": r.gate.evidence_id,
            },
        }
        for r in state.releases
    ]
    return {
        "ok": True,
        "count": len(items),
        "current": items[-1]["version"] if items else None,
        "releases": items,
        "note": (
            "Ordered by when they were recorded, not by version string. "
            "Versions are yours and are never parsed — semver, dates and build "
            "numbers are all fine, and a tool that sorted them would eventually "
            "call the wrong one current."
        )
        if items
        else (
            "No releases recorded. Until there is one, evidence has no version "
            "to be current against and reports as unversioned rather than "
            "stale."
        ),
    }


_dispatch.register_read("list_releases", list_releases)
_dispatch.register_mutating("record_release", record_release)
