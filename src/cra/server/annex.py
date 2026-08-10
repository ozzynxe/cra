"""Working the Annex I checklist, and attaching evidence to things.

This is the half of the product that gets used between incidents. Reporting
answers Article 14 when something happens; the requirement work is the ongoing
obligation, and it is where most of a team's compliance effort actually goes.

Two rules that are not conveniences:

**`not_applicable` demands a justification.** An auditor reads the
justification, not the flag. A requirement dismissed with no reasoning is the
single most common finding in a thin technical file, so the tool refuses it —
and refuses to *keep* one if the applicability is later changed back and forth.

**Evidence is hashed rows, never free text.** Coauthor's `CompletenessItem`
carried an `evidence: str`, which is exactly what an auditor rejects. Here
`evidence_ids` point at `evidence` rows with a sha256 and a `source_ref`, so
"we tested this" is backed by an artifact rather than an assertion.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from cra.agents import dispatch as _dispatch
from cra.db import Evidence, ReportingObligation, Vulnerability, session_scope
from cra.regulation import provenance, requirements
from cra.schemas.enums import (
    Applicability,
    EvidenceKind,
    RequirementStatus,
    Role,
)
from cra.server import audit, store_backend
from cra.server.artifact_limits import check_artifact_size, check_product_total
from cra.server.errors import InvalidState, NotFound
from cra.server.scoping import _load, _member

_CATALOGUE = {r.id: r for r in requirements()}

# What an `attach_evidence` subject_ref may point at, and how to check it
# exists. Polymorphic on purpose: one attachment tool beats four near-identical
# ones, and the agent does not have to learn which noun takes which verb.
_SUBJECT_KINDS = (
    "requirement",
    "vuln",
    "obligation",
    "risk",
    "technical_file",
    # Annex II. The artefact a *user* receives, which is a different
    # audience from everything else here — the technical file is for
    # authorities, this is what ships beside the product.
    "user_info",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _find(state, req_id: str):
    for item in state.requirements:
        if item.req_id == req_id:
            return item
    raise NotFound(
        f"no requirement {req_id!r} on this product. If the checklist is "
        "empty, run classify_product(in_scope=true) — the Annex I "
        "requirements are seeded when a product is found to be in scope."
    )


def _view(item, *, verbose: bool = False, currency: Optional[dict] = None) -> dict:
    cat = _CATALOGUE.get(item.req_id)
    out = {
        "req_id": item.req_id,
        "anchor": item.title,
        "applicability": item.applicability,
        "status": item.status,
        "evidence_count": len(item.evidence_ids),
        # Team visibility rather than locking: an arriving agent can see the
        # requirement was touched four minutes ago and route around it.
        "last_edited_by": item.last_edited_by,
        "last_edited_at": item.last_edited_at.isoformat() if item.last_edited_at else None,
    }
    if item.applicability == Applicability.NOT_APPLICABLE:
        out["justification"] = item.justification
    if item.risk_basis:
        out["risk_basis"] = list(item.risk_basis)
    # Only when it says something. On a product with no releases every
    # requirement would otherwise carry an "unversioned" that means nothing yet.
    if currency:
        out["evidence_currency"] = currency
    if verbose:
        out["summary"] = item.text
        out["implementation_note"] = item.implementation_note
        out["evidence_ids"] = list(item.evidence_ids)
        out["citation"] = item.eli_ref
        if cat and cat.evidence_hint:
            out["evidence_hint"] = cat.evidence_hint
    return out


def latest_release(state):
    """The release the product is currently on, or None.

    The last entry, not the highest — `version` is the manufacturer's own
    string and is not orderable. Semver, a date, a build number and an internal
    codename are all legitimate, and a tool that sorted them would eventually
    sort one wrongly and declare the wrong release current. Arrival order is
    the only sequence that is always true.
    """
    return state.releases[-1] if getattr(state, "releases", None) else None


# The three answers to "is this evidence about what we ship now".
CURRENT = "current"
STALE = "stale"
UNVERSIONED = "unversioned"


def evidence_currency(state, by_subject: dict) -> dict[str, dict]:
    """Per requirement: whether its evidence describes the current release.

    Derived, never stored — the same discipline as `risk.staleness` and
    `deadlines.obligation_state`. A persisted `stale` flag would need something
    to flip it, and the something would eventually not run, leaving a
    requirement evidenced against a two-year-old build looking current. The
    whole point is that this cannot silently stop being true.

    Annex I requirements attach to the product *as placed on the market*, so a
    test report is a claim about one build. Three verdicts:

      current      some evidence is tied to the latest release
      stale        evidence exists, all of it tied to superseded releases
      unversioned  some evidence carries no version at all

    **`unversioned` is not `stale`, and the difference is deliberate.** Every
    evidence row written before `applies_to_version` existed is NULL, as is
    anything attached before a product records its first release. Calling those
    stale would turn every existing requirement into a gap the moment someone
    records a release, and would assert something nobody checked — the
    absence-of-knowledge-as-knowledge-of-absence trap this codebase closes
    everywhere else. Unversioned evidence is reported, and reported as
    unversioned, and does not block a technical file.

    Returns `{}` when the product has no releases: without one there is nothing
    for evidence to be current *against*, and an empty result means every
    caller's `.get(req_id)` is None and nothing changes.
    """
    release = latest_release(state)
    if release is None:
        return {}

    out: dict[str, dict] = {}
    for item in state.requirements:
        rows = by_subject.get(f"requirement:{item.req_id}") or []
        if not rows:
            continue
        versions = {getattr(r, "applies_to_version", None) for r in rows}
        if release.version in versions:
            verdict = CURRENT
        elif None in versions:
            verdict = UNVERSIONED
        else:
            verdict = STALE
        entry = {"state": verdict, "current_release": release.version}
        if verdict == STALE:
            seen = sorted(v for v in versions if v)
            entry["evidenced_against"] = seen
            entry["detail"] = (
                f"evidence covers {', '.join(seen)} but the product is now on "
                f"{release.version}; Annex I attaches to the product as placed "
                "on the market, so this needs re-evidencing against the "
                "current release"
            )
        elif verdict == UNVERSIONED:
            entry["detail"] = (
                "some evidence carries no release, so it cannot be tied to "
                f"{release.version}. Not counted as a gap — attach with "
                "applies_to_version to make the claim specific"
            )
        out[item.req_id] = entry
    return out


def _currency_for(product_id: str, state) -> dict[str, dict]:
    """`evidence_currency`, fetching the evidence rows it needs.

    Short-circuits to `{}` before touching the database when the product has no
    releases. That is not just an optimisation: it keeps `list_requirements` a
    zero-query call for every product that has never recorded one, which is the
    state every product starts in and what the unit-test fixtures use.
    """
    if not latest_release(state):
        return {}
    with session_scope() as db:
        rows = db.execute(
            select(Evidence).where(
                Evidence.product_id == product_id,
                Evidence.deleted_at.is_(None),
                Evidence.subject_ref.like("requirement:%"),
            )
        ).scalars()
        by_subject: dict[str, list] = {}
        for e in rows:
            by_subject.setdefault(e.subject_ref, []).append(e)
        return evidence_currency(state, by_subject)


def _is_gap(item, currency: Optional[dict] = None) -> bool:
    """A requirement that would leave a hole in the technical file.

    `undetermined` counts: an unanswered requirement is a gap, and treating it
    as merely "not yet done" is how a file reaches an auditor with a third of
    it unconsidered.

    `currency` is `evidence_currency`'s entry for this requirement, and is
    optional so this stays a pure function of the item wherever no release
    context is at hand. Where it is supplied, evidence that only covers a
    superseded release is a gap: a requirement verified against a build nobody
    ships is not evidence about the product on the market.
    """
    if item.applicability == Applicability.NOT_APPLICABLE:
        return not item.justification.strip()
    if item.applicability == Applicability.UNDETERMINED:
        return True
    if (
        item.status in (RequirementStatus.IMPLEMENTED, RequirementStatus.VERIFIED)
        and item.evidence_ids
        and (currency or {}).get("state") == STALE
    ):
        return True
    return item.status not in (
        RequirementStatus.IMPLEMENTED,
        RequirementStatus.VERIFIED,
    ) or not item.evidence_ids


def list_requirements(
    *,
    product_id: str,
    actor_id: str = "",
    filter: str = "all",
    verbose: bool = False,
) -> dict:
    """The Annex I checklist. `filter` is all | gaps | part_i | part_ii."""
    state = _load(product_id)
    _member(state, actor_id)

    items = list(state.requirements)
    if not items:
        return {
            "ok": True,
            "requirements": [],
            "count": 0,
            "note": (
                "No checklist yet. Annex I requirements are seeded when the "
                "product is classified in scope — run classify_product()."
            ),
            "provenance": provenance(),
        }

    currency = _currency_for(product_id, state)

    if filter == "gaps":
        items = [i for i in items if _is_gap(i, currency.get(i.req_id))]
    elif filter in ("part_i", "part_ii"):
        wanted = {r.id for r in requirements() if r.part == filter}
        items = [i for i in items if i.req_id in wanted]
    elif filter != "all":
        raise InvalidState(
            "filter must be one of all, gaps, part_i, part_ii"
        )

    all_gaps = [i for i in state.requirements if _is_gap(i, currency.get(i.req_id))]
    stale = [k for k, v in currency.items() if v["state"] == STALE]
    unversioned = [k for k, v in currency.items() if v["state"] == UNVERSIONED]
    release = latest_release(state)

    out = {
        "ok": True,
        "filter": filter,
        "count": len(items),
        "requirements": [
            _view(i, verbose=verbose, currency=currency.get(i.req_id)) for i in items
        ],
        "gaps_total": len(all_gaps),
        "next": (
            f"{len(all_gaps)} requirement(s) would leave a hole in the "
            "technical file. list_requirements(filter='gaps') shows them."
            if all_gaps
            else "No gaps. assemble_technical_file() to see the Annex VII view."
        ),
        "provenance": provenance(),
    }
    if release:
        out["current_release"] = release.version
        out["evidence_stale"] = stale
        out["evidence_unversioned"] = unversioned
        if stale:
            out["stale_note"] = (
                f"{len(stale)} requirement(s) are evidenced only against earlier "
                f"releases and count as gaps: Annex I attaches to the product as "
                f"placed on the market, so evidence for {release.version} has to "
                "be about {release.version}. Re-attach with "
                "applies_to_version, or re-verify."
            ).replace("{release.version}", release.version)
        if unversioned:
            out["unversioned_note"] = (
                f"{len(unversioned)} requirement(s) have evidence with no "
                "release recorded on it. Not counted as gaps — the tool does "
                "not know which build they describe, and guessing would be "
                "worse than saying so."
            )
    return out


def update_requirement(
    *,
    product_id: str,
    actor_id: str = "",
    req_id: str,
    applicability: Optional[str] = None,
    justification: Optional[str] = None,
    status: Optional[str] = None,
    implementation_note: Optional[str] = None,
) -> dict:
    """Record how one Annex I requirement applies, and where it has got to."""
    def _apply(state, db):
        # Validation, mutation and the audit row inside one lock. Raising
        # from here — an unknown status, nothing to update — rolls the
        # audit insert back with the change it was describing.
        _member(state, actor_id, minimum=Role.EDITOR)
        item = _find(state, req_id)
        changed: dict = {}

        if applicability is not None:
            try:
                new_app = Applicability(applicability)
            except ValueError as e:
                raise InvalidState(
                    f"applicability must be one of {[a.value for a in Applicability]}"
            ) from e
            item.applicability = new_app
            changed["applicability"] = new_app.value

        if justification is not None:
            item.justification = justification.strip()
            changed["justification"] = item.justification

        # Checked after both assignments so it catches "set not_applicable now,
        # justify later" as well as a bare flag flip — and so that switching *back*
        # to applicable does not leave a stale justification behind.
        if item.applicability == Applicability.NOT_APPLICABLE and not item.justification:
            raise InvalidState(
                f"{req_id} cannot be marked not_applicable without a "
                "justification. An auditor reads the justification, not the flag — "
                "say why this requirement does not apply to this product."
            )
        # Annex I Part I applies on the basis of the risk assessment. If an
        # accepted risk says this requirement is in play, ruling it out here would
        # leave the technical file contradicting itself — Annex VII(3) holds both
        # the assessment and the checklist derived from it.
        if item.applicability == Applicability.NOT_APPLICABLE and item.risk_basis:
            raise InvalidState(
                f"{req_id} cannot be marked not_applicable while the confirmed "
                f"risk assessment says it applies (risks: "
                f"{', '.join(item.risk_basis)}). Either the risk analysis is wrong "
                "— revisit it with decide_risk() and confirm a new version — or "
                "the requirement applies. Recording both would put a "
                "contradiction into Annex VII(3)."
            )
        if item.applicability == Applicability.APPLICABLE and item.justification:
            item.justification = ""
            changed["justification"] = ""

        if status is not None:
            try:
                item.status = RequirementStatus(status)
            except ValueError as e:
                raise InvalidState(
                    f"status must be one of {[s.value for s in RequirementStatus]}"
            ) from e
            changed["status"] = item.status

        if implementation_note is not None:
            item.implementation_note = implementation_note
            changed["implementation_note"] = implementation_note

        if not changed:
            raise InvalidState("nothing to update — pass at least one field")

        item.last_edited_by = actor_id or None
        item.last_edited_at = _now()
        item.last_reviewed_at = _now()
        audit.record(
            db,
            product_id=product_id,
            subject_type="requirement",
            subject_id=req_id,
            op="update_requirement",
            accountable_user_id=actor_id or None,
            rationale=(item.justification or item.implementation_note or "")[:500],
            payload=changed,
        )
        return state, item

    item = store_backend.mutate(product_id, _apply)

    result = {"ok": True, "requirement": _view(item, verbose=True)}
    if _is_gap(item):
        result["still_a_gap"] = (
            "Marked applicable but not yet implemented and verified with "
            "evidence attached. attach_evidence(subject_ref="
            f"'requirement:{req_id}', ...) when you have an artifact."
        )
    return result


# ---- evidence ----------------------------------------------------------------


def _validate_subject(db, product_id: str, state, subject_ref: str) -> None:
    """Refuse an attachment to something that does not exist.

    Evidence filed against a typo'd reference is invisible: it is in the
    database, it is not in the technical file, and nobody finds out until an
    auditor asks for the artifact.
    """
    kind, _, key = subject_ref.partition(":")
    if not key or kind not in _SUBJECT_KINDS:
        raise InvalidState(
            f"subject_ref must be '<kind>:<id>' with kind in {list(_SUBJECT_KINDS)}, "
            f"e.g. 'requirement:annex_i.i.2.a' — got {subject_ref!r}"
        )
    if kind == "requirement":
        _find(state, key)
    elif kind == "vuln":
        row = db.get(Vulnerability, key)
        if row is None or row.product_id != product_id:
            raise NotFound(f"no vulnerability {key!r} on this product")
    elif kind == "obligation":
        row = db.get(ReportingObligation, key)
        if row is None or row.product_id != product_id:
            raise NotFound(f"no obligation {key!r} on this product")
    elif kind == "risk":
        # `risk` was an accepted kind with no branch here, so evidence could be
        # filed against a risk that did not exist — invisible in exactly the way
        # this function exists to prevent.
        ra = state.risk_assessment
        if ra is None or not any(r.risk_id == key for r in ra.risks):
            raise NotFound(
                f"no risk {key!r} on this product's assessment. "
                "get_risk_assessment() lists them with their ids."
            )
    elif kind == "user_info":
        if not any(i.item_id == key for i in state.user_information):
            raise NotFound(
                f"no Annex II item {key!r} on this product. "
                "list_user_information() shows them with their ids."
            )


def attach_evidence(
    *,
    product_id: str,
    actor_id: str = "",
    subject_ref: str,
    title: str,
    body: Optional[str] = None,
    kind: str = EvidenceKind.DOCUMENT.value,
    source_ref: Optional[str] = None,
    content_type: str = "text/plain",
    applies_to_version: Optional[str] = None,
) -> dict:
    """Attach a hashed artifact to a requirement, vulnerability or obligation.

    One tool for every attachment point — `subject_ref` is
    `requirement:annex_i.i.2.a`, `vuln:<id>`, `obligation:<id>`, `risk:<id>` or
    `technical_file:<slot>`.

    `applies_to_version` is the release this artifact is a claim about. Annex I
    attaches to the product *as placed on the market*, so a test report proves
    something about one build and not about the product forever. Omit it and it
    defaults to the latest recorded release — you are almost always evidencing
    what you have now — and the reply says which version it used. Pass one
    explicitly when back-filling evidence for an older release. Before the
    first release there is nothing to default to and the evidence is recorded
    as unversioned, which reads as unversioned rather than as stale.
    """
    try:
        evidence_kind = EvidenceKind(kind)
    except ValueError as e:
        raise InvalidState(
            f"kind must be one of {[k.value for k in EvidenceKind]}"
        ) from e
    if not (body or "").strip():
        raise InvalidState(
            "body is required — evidence is stored by value and hashed. A "
            "reference with no artifact behind it evidences nothing in ten "
            "years, which is how long the technical file is retained."
        )
    if not source_ref:
        raise InvalidState(
            "source_ref is required: where this came from — a git SHA, a CI "
            "run URL, or a tool name and version. Provenance is what makes it "
            "evidence rather than an assertion."
        )

    size = len(body.encode())
    check_artifact_size(size, what="This artifact")

    digest = hashlib.sha256(body.encode()).hexdigest()

    def _apply(state, db):
        _member(state, actor_id, minimum=Role.EDITOR)
        _validate_subject(db, product_id, state, subject_ref)
        # Inside the lock: a total read before it can be stale by the time it
        # is acted on, and two concurrent attachments would each see room.
        check_product_total(db, product_id, size)
        release = latest_release(state)
        # Resolved inside the lock so the default cannot be read from a release
        # list that a concurrent `record_release` has already moved on from.
        version = applies_to_version or (release.version if release else None)
        if applies_to_version and release is not None:
            known = {r.version for r in state.releases}
            if applies_to_version not in known:
                raise InvalidState(
                    f"no release {applies_to_version!r} on this product — "
                    f"recorded releases are {sorted(known)}. Evidence pointing "
                    "at a release that does not exist would look versioned and "
                    "be unverifiable. record_release() first, or omit the "
                    "argument to tie it to the current release."
                )
        row = Evidence(
            product_id=product_id,
            subject_ref=subject_ref,
            title=title,
            kind=evidence_kind.value,
            inline_body=body,
            content_type=content_type,
            size_bytes=size,
            sha256=digest,
            source_ref=source_ref,
            applies_to_version=version,
            added_by_user_id=actor_id or None,
        )
        db.add(row)
        # Flushed, not committed: the id is needed to link the blob below, and
        # the original ordering — insert the row, then link it in a second
        # transaction — is what left evidence attached to nothing when the
        # second write failed. Inside the lock both land or neither does, so
        # the id can be used immediately and the ordering comment retires.
        db.flush()
        evidence_id = row.id

        audit.record(
            db,
            product_id=product_id,
            subject_type="evidence",
            subject_id=evidence_id,
            op="attach_evidence",
            accountable_user_id=actor_id or None,
            rationale=title[:500],
            payload={
                "subject_ref": subject_ref,
                "kind": evidence_kind.value,
                "applies_to_version": version,
            },
            after_hash=digest,
        )

        # Link it into the blob so `list_requirements` and the technical file
        # see it without a join.
        if subject_ref.startswith("requirement:"):
            item = _find(state, subject_ref.split(":", 1)[1])
            item.evidence_ids.append(evidence_id)
            item.last_edited_by = actor_id or None
            item.last_edited_at = _now()
        elif subject_ref.startswith("user_info:"):
            key = subject_ref.split(":", 1)[1]
            ui = next(
                (i for i in state.user_information if i.item_id == key), None
            )
            if ui is not None:
                ui.evidence_ids.append(evidence_id)
                ui.last_edited_by = actor_id or None
                ui.last_edited_at = _now()

        return state, (evidence_id, version)

    evidence_id, version = store_backend.mutate(product_id, _apply)

    out = {
        "ok": True,
        "evidence_id": evidence_id,
        "sha256": digest,
        "subject_ref": subject_ref,
        "applies_to_version": version,
        "note": (
            "Stored by value and hashed. If the artifact changes, attach the "
            "new version rather than editing this one — the hash is what ties "
            "a sign-off to what was actually reviewed."
        ),
    }
    # Say which release it was tied to, always. A default that is never stated
    # is an inference, and an inference about which build a piece of evidence
    # describes is exactly the thing this column exists to stop.
    if version and not applies_to_version:
        out["version_note"] = (
            f"Tied to release {version}, the latest recorded. Pass "
            "applies_to_version explicitly if this evidences an earlier one."
        )
    elif version is None:
        out["version_note"] = (
            "Recorded without a release, because none has been recorded for "
            "this product yet. It will show as unversioned rather than stale — "
            "record_release() and re-attach to make the claim specific."
        )
    return out


def list_evidence(
    *,
    product_id: str,
    actor_id: str = "",
    subject_ref: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """Evidence on file, optionally for one subject."""
    state = _load(product_id)
    _member(state, actor_id)
    limit = max(1, min(int(limit), 200))

    q = select(Evidence).where(
        Evidence.product_id == product_id, Evidence.deleted_at.is_(None)
    )
    if subject_ref:
        q = q.where(Evidence.subject_ref == subject_ref)

    with session_scope() as db:
        rows = list(
            db.execute(q.order_by(Evidence.collected_at.desc()).limit(limit)).scalars()
        )
        items = [
            {
                "evidence_id": e.id,
                "subject_ref": e.subject_ref,
                "title": e.title,
                "kind": e.kind,
                "sha256": e.sha256,
                "source_ref": e.source_ref,
                "size_bytes": e.size_bytes,
                "collected_at": e.collected_at.isoformat(),
                "added_by_user_id": e.added_by_user_id,
            }
            for e in rows
        ]
    return {"ok": True, "count": len(items), "evidence": items}


_dispatch.register_read("list_requirements", list_requirements)
_dispatch.register_read("list_evidence", list_evidence)
_dispatch.register_mutating("update_requirement", update_requirement)
_dispatch.register_mutating("attach_evidence", attach_evidence)
