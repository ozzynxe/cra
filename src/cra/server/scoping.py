"""Classification, SBOM, membership, and reading the trail.

Classification is the tool with the sharpest failure mode in this repo. Class
membership decides whether a **notified body** is required, so telling someone
their product is `default` when it is Annex III class II is the most expensive
single error the server could make — and it is an error the user has no way to
notice, because the tool would be confirming what they already believed.

Three consequences run through this module:

- Nothing is inferred from a product name. `classify_product` records a
  decision the human made; it does not make one. Called with no class, it
  returns the catalogue as a decision aid and writes nothing.
- Every classification carries `rationale`, and a classification without one is
  refused. The rationale is what a human re-checks and what an auditor reads.
- The catalogue's provenance rides along on every response, because the
  entries have not been reconciled against EUR-Lex — see `cra.regulation`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from cra.agents import dispatch as _dispatch
from cra.db import AuditEvent, Evidence, session_scope
from cra.regulation import (
    out_of_scope_hints,
    product_classes,
    provenance,
    requirements,
    user_information,
)
# Aliased: `classify_product` takes a `product_class` argument, and importing
# the catalogue lookup under its own name would let the parameter shadow it.
from cra.regulation import product_class as class_spec
from cra.deadlines import add_months
from cra.regulation import eurlex
from cra.schemas import RequirementItem, SupportPeriod, UserInfoItem
from cra.schemas.enums import (
    Applicability,
    ConformityRoute,
    EvidenceKind,
    ProductClass,
    RequirementStatus,
    Role,
    role_at_least,
)
from cra.server import audit, entitlements, store_backend
from cra.server.timestamps import parse_ts_utc
from cra.server.artifact_limits import check_artifact_size, check_product_total
from cra.server.errors import InvalidState, NotFound, PermissionDenied

# The catalogue ids are Annex-shaped; `ProductClass` is the stored enum. They
# are deliberately separate vocabularies, so the mapping is explicit.
_CLASS_TO_ENUM = {
    "default": ProductClass.DEFAULT,
    "important_class_i": ProductClass.IMPORTANT_CLASS_I,
    "important_class_ii": ProductClass.IMPORTANT_CLASS_II,
    "critical": ProductClass.CRITICAL,
}
_ENUM_TO_CLASS = {v.value: k for k, v in _CLASS_TO_ENUM.items()}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(product_id: str):
    try:
        return store_backend.get_backend().load_state(product_id)
    except FileNotFoundError as e:
        raise NotFound(f"no product {product_id!r}") from e


def _member(state, actor_id: str, *, minimum: Role = Role.VIEWER):
    if not actor_id:
        return None
    info = state.members.get(actor_id)
    if info is None:
        raise NotFound(f"no product {state.product_id!r} for this user")
    if not role_at_least(info.role, minimum):
        raise PermissionDenied(
            f"this needs {minimum.value} or above; you are {info.role}"
        )
    return info


# ---- classification ----------------------------------------------------------


def _decision_aid() -> dict:
    return {
        "ok": True,
        "recorded": False,
        "how_to_decide": (
            "Work through these with the user, in order: (1) is the product "
            "in scope at all — see out_of_scope; (2) does it match an Annex "
            "III or Annex IV category below; (3) if none match, it is "
            "'default'. Match on what the product *is*, not what it is called. "
            "When two categories arguably fit, take the higher class and say "
            "why — under-classifying is the expensive direction."
        ),
        "classes": [
            {
                "product_class": c.id,
                "title": c.title,
                "anchor": c.anchor,
                "conformity_route": c.conformity_route,
                "notified_body_required": c.notified_body_required,
                "description": c.description,
                "categories": list(c.categories),
            }
            for c in product_classes()
        ],
        "out_of_scope": list(out_of_scope_hints()),
        "then": (
            "Call classify_product(product_class=..., in_scope=..., "
            "rationale='...') to record the decision. The rationale is "
            "mandatory — it is what a human re-checks and what an auditor "
            "reads."
        ),
        "provenance": provenance(),
    }


def classify_product(
    *,
    product_id: str,
    actor_id: str = "",
    product_class: Optional[str] = None,
    in_scope: Optional[bool] = None,
    annex_iii_category: Optional[str] = None,
    rationale: str = "",
) -> dict:
    """Record an indicative classification, or return the decision aid.

    Called without `product_class` this writes nothing and returns the
    catalogue — exploring the question should be free, committing to an answer
    should not.
    """
    if product_class is None:
        return _decision_aid()

    key = _ENUM_TO_CLASS.get(product_class, product_class)
    try:
        spec = class_spec(key)
    except KeyError as e:
        raise InvalidState(
            f"product_class must be one of {sorted(_CLASS_TO_ENUM)}, not "
            f"{product_class!r} — call classify_product() with no arguments "
            "for the category lists."
        ) from e

    if not rationale.strip():
        raise InvalidState(
            "rationale is required. A classification with no reasoning cannot "
            "be checked by a human or defended to an auditor, so it is worse "
            "than no classification — it looks settled."
        )

    now = _now()

    def _apply(state, db):
        # Inside the lock: the membership check, the mutation and the audit row
        # commit together or not at all. Raising here — a non-member, a bad
        # enum — rolls back everything, including the audit insert describing
        # a change that did not happen.
        _member(state, actor_id, minimum=Role.MAINTAINER)

        previous = state.classification.product_class
        state.classification.product_class = _CLASS_TO_ENUM[key]
        state.classification.conformity_route = ConformityRoute(spec.conformity_route)
        state.classification.annex_iii_category = annex_iii_category
        state.classification.rationale = rationale.strip()
        state.classification.classified_at = now
        state.classification.classified_by = actor_id or None
        if in_scope is not None:
            state.classification.in_scope = bool(in_scope)

        seeded = _seed_requirements(state) if state.classification.in_scope else 0
        seeded_ui = (
            _seed_user_information(state) if state.classification.in_scope else 0
        )
        audit.record(
            db,
            product_id=product_id,
            subject_type="classification",
            op="classify_product",
            accountable_user_id=actor_id or None,
            rationale=rationale.strip()[:500],
            payload={
                "from": previous,
                "to": key,
                "in_scope": state.classification.in_scope,
                "annex_iii_category": annex_iii_category,
                "requirements_seeded": seeded,
                "annex_ii_items_seeded": seeded_ui,
            },
        )
        return state, (state.classification.in_scope, seeded, seeded_ui)

    in_scope_now, seeded, seeded_ui = store_backend.mutate(product_id, _apply)

    return {
        "ok": True,
        "recorded": True,
        "indicative": True,
        "product_class": key,
        "in_scope": in_scope_now,
        "conformity_route": spec.conformity_route,
        "notified_body_required": spec.notified_body_required,
        "what_this_means": spec.description,
        "anchor": spec.anchor,
        "citation": eurlex.citation_url(eurlex.CRA_CELEX),
        "requirements_seeded": seeded,
        "next": (
            (
                "start_risk_assessment(product_id) before working the "
                "checklist. Annex I Part I applies on the basis of the Article "
                "13(2) risk assessment, so answering requirements first "
                "produces determinations resting on nothing — and Annex VII(3) "
                "needs the assessment itself, not just the checklist."
            )
            if in_scope_now
            else "Out of scope — nothing further is required under the CRA."
        ),
        "caveat": (
            "Indicative only. This records the classification you supplied and "
            "its consequences; it is not a determination, and where a notified "
            "body is required only that body can assess conformity."
        ),
        "provenance": provenance(),
    }


def _seed_requirements(state) -> int:
    """Populate `requirements[]` from the Annex I catalogue, idempotently.

    Existing entries are left untouched — re-classifying a product must not
    discard evidence someone has already attached. Only genuinely new
    requirement ids are added, which is also how a catalogue update reaches an
    existing product.
    """
    have = {r.req_id for r in state.requirements}
    added = 0
    for req in requirements():
        if req.id in have:
            continue
        state.requirements.append(
            RequirementItem(
                req_id=req.id,
                title=req.anchor,
                text=req.summary,
                celex_ref=eurlex.CRA_CELEX,
                eli_ref=eurlex.citation_url(eurlex.CRA_CELEX),
                # Part II is applicable by law and the catalogue says so: its
                # chapeau reads "Manufacturers of products with digital elements
                # shall:" — unconditional, unqualified by the risk assessment and
                # not by "where applicable", unlike Part I(2).
                #
                # Seeded undetermined until 2026-08-10, which left the user to
                # hand-mark as applicable eight requirements the tool had just
                # told them were applicable by law. Eight calls is the small
                # cost; the corrosive one is that it teaches `undetermined` to
                # read as noise to be cleared rather than as a real gap — the
                # exact reading the release gate's wording works against. Same
                # shape as the Annex II fix: the catalogue already knew.
                applicability=(
                    Applicability.APPLICABLE
                    if req.part == "part_ii"
                    else Applicability.UNDETERMINED
                ),
                status=RequirementStatus.NOT_STARTED,
            )
        )
        added += 1
    return added


def _seed_user_information(state) -> int:
    """Populate `user_information[]` from the Annex II catalogue, idempotently.

    Same contract as `_seed_requirements`: existing entries are untouched, so
    re-classifying never discards work, and a catalogue addition reaches an
    existing product the next time it is classified.
    """
    have = {i.item_id for i in state.user_information}
    added = 0
    for item in user_information():
        if item.id in have:
            continue
        state.user_information.append(
            UserInfoItem(item_id=item.id, anchor=item.anchor, text=item.summary)
        )
        added += 1
    return added


# ---- Annex II — information and instructions to the user -----------------------


def _user_info_view(item, spec=None) -> dict:
    out = {
        "item_id": item.item_id,
        "anchor": item.anchor,
        "summary": item.text,
        "provided": item.provided,
        "not_applicable": item.not_applicable,
        "settled": _ui_settled(item),
    }
    if item.location:
        out["location"] = item.location
    if item.not_applicable:
        out["justification"] = item.justification
    if item.note:
        out["note"] = item.note
    if item.evidence_ids:
        out["evidence_count"] = len(item.evidence_ids)
    if spec is not None:
        if spec.conditional:
            out["conditional"] = True
            out["condition"] = spec.condition
        if spec.evidence_hint:
            out["evidence_hint"] = spec.evidence_hint
        if spec.also_required_by:
            out["also_required_by"] = spec.also_required_by
    return out


def _ui_settled(item) -> bool:
    """Provided, or ruled out with a reason. An unjustified `not_applicable` is
    not settled — the same rule Annex I applies, and it matters more here
    because four items are conditional and ruling one out is routine."""
    if item.not_applicable:
        return bool(item.justification.strip())
    return item.provided


def list_user_information(*, product_id: str, actor_id: str = "", filter: str = "all") -> dict:
    """The Annex II checklist. `filter` is all | gaps | conditional."""
    allowed = ("all", "gaps", "conditional")
    if filter not in allowed:
        raise InvalidState(f"filter must be one of {list(allowed)}")

    state = _load(product_id)
    _member(state, actor_id)
    specs = {s.id: s for s in user_information()}

    if not state.user_information:
        return {
            "ok": True,
            "items": [],
            "count": 0,
            "note": (
                "No Annex II checklist yet. It is seeded when the product is "
                "classified in scope — run classify_product()."
            ),
            "provenance": provenance(),
        }

    items = list(state.user_information)
    if filter == "gaps":
        items = [i for i in items if not _ui_settled(i)]
    elif filter == "conditional":
        items = [i for i in items if (specs.get(i.item_id) and specs[i.item_id].conditional)]

    gaps = [i for i in state.user_information if not _ui_settled(i)]
    return {
        "ok": True,
        "filter": filter,
        "count": len(items),
        "items": [_user_info_view(i, specs.get(i.item_id)) for i in items],
        "gaps_total": len(gaps),
        "what_this_is": (
            "Article 13(18): the product must be *accompanied by* this "
            "information, in paper or electronic form, in a language its users "
            "and market surveillance authorities can easily understand, and "
            "kept available for ten years or the support period, whichever is "
            "longer. It is what ships beside the product — not the technical "
            "file, which is for authorities."
        ),
        "next": (
            f"{len(gaps)} item(s) unsettled. Each is either provided — say "
            "where a user finds it — or ruled out with a justification."
            if gaps
            else "Every item is settled. Annex VII(1) reports this coverage."
        ),
        "provenance": provenance(),
    }


def update_user_information(
    *,
    product_id: str,
    actor_id: str = "",
    item_id: str,
    provided: Optional[bool] = None,
    not_applicable: Optional[bool] = None,
    justification: Optional[str] = None,
    location: Optional[str] = None,
    note: Optional[str] = None,
) -> dict:
    """Record whether an Annex II item accompanies the product, and where.

    `not_applicable` needs a justification. Four of the fifteen items are
    conditional in the annex's own words, which makes ruling one out routine —
    and that is exactly why the reasoning is required, or "where applicable"
    becomes a way to empty the annex.
    """
    specs = {s.id: s for s in user_information()}
    if item_id not in specs:
        raise InvalidState(
            f"no Annex II item {item_id!r}. list_user_information() shows them; "
            f"ids look like {user_information()[0].id!r}."
        )

    def _apply(state, db):
        _member(state, actor_id, minimum=Role.EDITOR)
        item = next(
            (i for i in state.user_information if i.item_id == item_id), None
        )
        if item is None:
            raise NotFound(
                f"no Annex II checklist on this product. Run "
                f"classify_product(in_scope=true) to seed it."
            )

        changed: dict = {}
        if provided is not None:
            item.provided = bool(provided)
            changed["provided"] = item.provided
            if provided:
                # Mutually exclusive: an item cannot both accompany the product
                # and not apply to it. Clearing rather than refusing, because
                # the caller has just stated the newer fact.
                item.not_applicable = False
                item.justification = ""
        if not_applicable is not None:
            # Eleven of the fifteen Annex II items are stated unconditionally.
            # There is no lawful basis for ruling those out, so this refuses
            # rather than asking for a reason — a reason cannot make a required
            # item optional, and asking for one implies it can.
            #
            # An end-to-end run emptied the entire annex with the phrase "where
            # applicable", including the manufacturer's name and address and the
            # vulnerability reporting contact. The tool already knew which four
            # are conditional — `list_user_information` will say so on request —
            # and did not consult that when the ruling-out arrived.
            if not_applicable and not specs[item_id].conditional:
                raise InvalidState(
                    f"{specs[item_id].anchor} is stated unconditionally in "
                    f"Annex II, so it cannot be ruled out — {specs[item_id].summary} "
                    "Four of the fifteen items are qualified in the annex's own "
                    "words and those can be ruled out with a justification — "
                    "list_user_information(filter='conditional') names them. "
                    "This is not one of them."
                )
            item.not_applicable = bool(not_applicable)
            changed["not_applicable"] = item.not_applicable
            if not_applicable:
                item.provided = False
        if justification is not None:
            item.justification = justification.strip()
            changed["justification"] = item.justification
        if location is not None:
            item.location = location.strip()
            changed["location"] = item.location
        if note is not None:
            item.note = note.strip()
            changed["note"] = item.note

        if not changed:
            raise InvalidState(
                "nothing to change — pass provided, not_applicable, "
                "justification, location or note."
            )
        if item.not_applicable and not item.justification.strip():
            raise InvalidState(
                f"{specs[item_id].anchor} cannot be ruled out without a "
                "justification. "
                + (
                    f"The annex qualifies this item — {specs[item_id].condition} "
                    "— so ruling it out may well be right, and that is exactly "
                    "why the reason has to be on the record."
                    if specs[item_id].conditional
                    else "Annex II's chapeau says the product shall *at "
                    "minimum* be accompanied by these, so an unexplained "
                    "exclusion is the finding an auditor starts with."
                )
            )
        if item.provided and not item.location.strip():
            # Not refused: "provided" is true or it is not, and the tool should
            # not withhold a true statement over a missing pointer. Flagged,
            # because an auditor's next question is always where.
            changed["_no_location"] = True

        item.last_edited_by = actor_id or None
        item.last_edited_at = _now()

        audit.record(
            db,
            product_id=product_id,
            subject_type="user_information",
            subject_id=item_id,
            op="update_user_information",
            accountable_user_id=actor_id or None,
            rationale=(item.justification or item.location or "")[:500],
            payload={k: v for k, v in changed.items() if not k.startswith("_")},
        )
        return state, (_user_info_view(item, specs[item_id]), "_no_location" in changed)

    view, no_location = store_backend.mutate(product_id, _apply)
    out = {"ok": True, "item": view, "provenance": provenance()}
    if no_location:
        out["where"] = (
            "Recorded as provided, with no location. Article 13(18) is about "
            "what a user actually receives, so the useful record says where "
            "they find it — a page, a manual section, a URL. "
            "update_user_information(location=...)."
        )
    if not _ui_settled_from_view(view):
        out["still_a_gap"] = (
            "Not settled yet: an item is either provided, or ruled out with a "
            "justification."
        )
    return out


def _ui_settled_from_view(view: dict) -> bool:
    return bool(view.get("settled"))


def get_applicable_csirt(*, product_id: str, actor_id: str = "") -> dict:
    """Where reports go, and why this is not a lookup we can answer for you."""
    state = _load(product_id)
    _member(state, actor_id)
    states = state.submitter.member_states_available
    return {
        "ok": True,
        "rule": (
            "Article 14 reports go to the CSIRT designated as coordinator of "
            "the Member State where the manufacturer has its main "
            "establishment, and to ENISA, via the Single Reporting Platform. "
            "The platform routes on the registration details, so you do not "
            "choose a recipient per report."
        ),
        "member_states_recorded": states,
        "main_establishment": None,
        "action": (
            "Confirm your main establishment when you register on the SRP; "
            "that registration is what determines routing. Record the Member "
            "States where the product is available with "
            "set_submitter_profile(member_states_available=[...]) — it is an "
            "obligatory report field."
        )
        if not states
        else (
            "Member States recorded. The SRP still routes on your registered "
            "main establishment, not on this list."
        ),
    }


# ---- support period ----------------------------------------------------------

# Article 13(8), third subparagraph. Not a policy of ours: "the support period
# shall be at least five years."
_FLOOR_YEARS = 5
_DAYS_PER_YEAR = 365.2425


def _years_between(start: datetime, end: datetime) -> float:
    """Approximate span, **for display only**.

    Never use this to decide whether the floor is met — see `_meets_months`.
    Averaging over the Gregorian year (365.2425 days) makes exactly five
    calendar years come out at 4.9994: 2026-01-01 to 2031-01-01 is 1826 days
    and five average years is 1826.21. Deciding a legal threshold on that
    refuses a lawful period for a reason nobody could explain to a user.
    """
    return (end - start).total_seconds() / 86400.0 / _DAYS_PER_YEAR


def _meets_months(start: datetime, end: datetime, months: int) -> bool:
    """Does `end` fall on or after `start` plus `months` calendar months?

    Calendar arithmetic, reusing `deadlines.add_months` — the same reasoning it
    already documents for "one month" on the Article 14 final report: a legal
    period is measured in calendar units, and converting it to elapsed days
    gets it wrong by exactly enough to matter at the boundary.
    """
    return end >= add_months(start, months)


def set_support_period(
    *,
    product_id: str,
    actor_id: str = "",
    end: str,
    start: Optional[str] = None,
    rationale: str,
    expected_use_years: Optional[float] = None,
    published_url: Optional[str] = None,
) -> dict:
    """Record the Article 13(8) support period, and what it was based on.

    `rationale` is required because half of 13(8) is the reasoning, not the
    date: the paragraph puts *the information taken into account* in the
    technical documentation, and Annex VII(4) is that section. A date with no
    reasoning fills a slot without meeting the obligation.

    Shorter than five years is refused unless `expected_use_years` says the
    product is expected to be in use for less — the paragraph's only exception,
    and one that has to be claimed rather than backed into.
    """
    if not rationale.strip():
        raise InvalidState(
            "rationale is required. Article 13(8) puts the information taken "
            "into account in determining the support period into the technical "
            "documentation — reasonable user expectations, the nature of the "
            "product, comparable products, the support periods of integrated "
            "components. Annex VII(4) is that reasoning, so a date on its own "
            "leaves the section unmet even though it looks filled."
        )

    end_at = parse_ts_utc(end, field="end", what="a support period")
    start_at = parse_ts_utc(start, field="start", what="a support period") if start else None

    def _apply(state, db):
        _member(state, actor_id, minimum=Role.MAINTAINER)

        # Default the start to when the product was first placed on the market,
        # which is what 13(8) runs from — and is now a fact the tool holds
        # rather than a question it has to ask.
        anchor = start_at
        inferred_from = None
        # Placed only: 13(8) runs from placing on the market, and a build
        # nobody shipped is not that.
        from cra.server import annex as _annex  # local: annex imports this module

        placed = _annex.placed_releases(state)
        if anchor is None and placed:
            first = min(placed, key=lambda r: r.released_at)
            anchor, inferred_from = first.released_at, first.version
        if anchor is None:
            raise InvalidState(
                "start is required: the support period runs from placing on "
                "the market, and no version of this product has been placed on "
                "the market to take that date from. Either "
                "place_on_market(version=...) first, or pass start=... "
                "explicitly. A recorded build is not a placing — that is what "
                "the two calls are for."
            )
        if end_at <= anchor:
            raise InvalidState(
                f"the support period ends ({end_at.date()}) before or when it "
                f"starts ({anchor.date()})."
            )

        span = _years_between(anchor, end_at)
        # Whether the 13(8) exception is actually being relied on. Not the same
        # question as whether `expected_use_years` was supplied: passing it on a
        # period that clears the floor is legitimate context, and reading the
        # argument as the answer once put "Under five years" on a seven-year
        # period. Only the floor test decides this.
        short_of_floor = not _meets_months(anchor, end_at, _FLOOR_YEARS * 12)
        if short_of_floor:
            if expected_use_years is None:
                raise InvalidState(
                    f"that is a support period of {span:.1f} years. Article "
                    "13(8) requires at least five, with one exception: where "
                    "the product is expected to be in use for less than five "
                    "years, the period corresponds to the expected use time. "
                    "If that is your case, say so with "
                    "expected_use_years=... and the reasoning behind it — the "
                    "exception has to be claimed, not arrived at by choosing a "
                    "nearer date."
                )
            if expected_use_years >= _FLOOR_YEARS:
                raise InvalidState(
                    f"expected_use_years={expected_use_years:g} is not under "
                    "five, so the exception in Article 13(8) does not apply "
                    f"and the floor of five years stands against your "
                    f"{span:.1f}-year period."
                )
            if not _meets_months(anchor, end_at, round(expected_use_years * 12)):
                raise InvalidState(
                    f"the period is {span:.1f} years but the product is "
                    f"expected to be in use for {expected_use_years:g}. "
                    "13(8) says the period *corresponds to* the expected use "
                    "time — supporting it for less than you expect it to be "
                    "used is the gap the exception exists to close, not a use "
                    "of the exception."
                )

        before = state.support_period.model_dump(mode="json")
        state.support_period = SupportPeriod(
            start=anchor,
            end=end_at,
            rationale=rationale.strip(),
            published_url=published_url,
            expected_use_years=expected_use_years,
            determined_at=_now(),
            determined_by=actor_id or None,
        )
        audit.record(
            db,
            product_id=product_id,
            subject_type="support_period",
            subject_id=product_id,
            op="set_support_period",
            accountable_user_id=actor_id or None,
            actor_kind="human",
            rationale=rationale.strip()[:500],
            payload={
                "start": anchor.isoformat(),
                "end": end_at.isoformat(),
                "years": round(span, 2),
                "expected_use_years": expected_use_years,
                "previous": before,
            },
        )
        return state, (span, inferred_from, short_of_floor)

    span, inferred_from, short_of_floor = store_backend.mutate(product_id, _apply)

    out = {
        "ok": True,
        "start": None,
        "end": end_at.isoformat(),
        "years": round(span, 2),
        "satisfies": "annex_vii.tf.4",
        "note": (
            "Recorded against Annex VII(4), which wants the reasoning and not "
            "only the date. The technical file now fills this section from the "
            "record rather than from an attached document."
        ),
    }
    state = _load(product_id)
    out["start"] = state.support_period.start.isoformat()
    if inferred_from:
        out["start_inferred_from_release"] = inferred_from
        out["start_note"] = (
            f"Start taken from release {inferred_from}, the earliest recorded — "
            "Article 13(8) runs the period from placing on the market. Pass "
            "start=... if that is not the right anchor."
        )
    if short_of_floor:
        out["short_period_basis"] = (
            f"Under five years, on the stated basis that the product is "
            f"expected to be in use for {expected_use_years:g}. That claim is "
            "in the technical file and the audit trail; it is the thing an "
            "auditor will test, not the date."
        )
    elif expected_use_years is not None:
        # Said rather than left silent: the caller passed the argument, and an
        # agent that hears nothing back about it has no way to tell whether the
        # exception was taken. This is the sentence that says it was not.
        out["expected_use_recorded"] = (
            f"Expected use of {expected_use_years:g} years is recorded as part "
            f"of the reasoning. The period meets the five-year floor on its "
            "own, so the Article 13(8) exception is not being relied on and "
            "nothing here claims it."
        )
    if not published_url:
        out["also"] = (
            "Article 13(19) wants the end date clear to buyers at the time of "
            "purchase. Record where you publish it with published_url=... — "
            "the tool cannot check that a page says what you think it says, "
            "but it can keep the address with the determination."
        )
    return out


# ---- SBOM --------------------------------------------------------------------

_SBOM_FORMATS = ("cyclonedx", "spdx")


def record_sbom(
    *,
    product_id: str,
    actor_id: str = "",
    sbom: str,
    sbom_format: str = "cyclonedx",
    component_count: Optional[int] = None,
    source_ref: Optional[str] = None,
    version: Optional[str] = None,
) -> dict:
    """Attach a software bill of materials as evidence for Annex I Pt II(1).

    Stored hashed and by value. An SBOM referenced by URL evidences nothing in
    ten years' time, which is how long the technical file is retained.
    """
    fmt = sbom_format.strip().lower()
    if fmt not in _SBOM_FORMATS:
        raise InvalidState(
            f"sbom_format must be one of {list(_SBOM_FORMATS)} — Annex I Pt "
            "II(1) requires a commonly used machine-readable format."
        )
    if not sbom.strip():
        raise InvalidState("sbom is empty")

    body = sbom
    size = len(body.encode())
    # Same ceiling as any other stored artifact, and the same reason: this is
    # kept by value for the statutory period and lands in an Object Lock backup
    # that cannot be pruned for a decade. An SBOM for a large product is a few
    # hundred kilobytes; anything near the limit is a build tree, not a bill of
    # materials.
    check_artifact_size(size, what="This SBOM")
    digest = hashlib.sha256(body.encode()).hexdigest()

    def _apply(state, db):
        check_product_total(db, product_id, size)
        # Inside the lock now, with everything else. This used to open a bare
        # `session_scope` and write no state at all, which had two costs: the
        # evidence insert and its audit row were not one transaction, and the
        # id was never linked into the blob — so `_is_gap` kept reporting
        # annex_i.ii.1 as a gap after a perfectly good SBOM upload, while
        # `_slot_view` picked the same evidence up through `by_subject`. The
        # two disagreed about one requirement.
        _member(state, actor_id, minimum=Role.EDITOR)

        # Which build this bill of materials describes.
        #
        # A caller's `version` is taken at face value even when no release by
        # that name exists yet, because that is the ordinary order of work:
        # record the SBOM for the build you are about to ship, scan it, then
        # record the release. Until 2026-08-10 an unknown version fell back to
        # the latest *existing* release, so an SBOM explicitly labelled 2.0.0
        # was filed as evidence for 1.0.0 — which the comment that used to sit
        # here correctly called worse than leaving it untagged, while the code
        # beneath it did exactly that. `record_build` stores versions verbatim
        # and never parses them, so there is nothing to validate against anyway.
        #
        # With no `version`, the SBOM describes what currently ships.
        from cra.server import annex  # local: annex imports this module

        # The *build*, not the last placing. An SBOM describes an artefact,
        # and the one you just scanned is usually the one you just built —
        # which may not have been placed on the market yet.
        release = annex.latest_build(state)
        applies_to = version or (release.version if release else None)

        evidence = Evidence(
            product_id=product_id,
            subject_ref="requirement:annex_i.ii.1",
            title=f"SBOM ({fmt}){f' — {version}' if version else ''}",
            kind=EvidenceKind.SBOM.value,
            inline_body=body,
            content_type="application/json",
            size_bytes=len(body.encode()),
            sha256=digest,
            source_ref=source_ref,
            applies_to_version=applies_to,
            added_by_user_id=actor_id or None,
        )
        db.add(evidence)
        db.flush()
        audit.record(
            db,
            product_id=product_id,
            subject_type="evidence",
            subject_id=evidence.id,
            op="record_sbom",
            accountable_user_id=actor_id or None,
            rationale=f"SBOM recorded for {version or 'current build'}",
            payload={
                "format": fmt,
                "component_count": component_count,
                "source_ref": source_ref,
                "applies_to_version": applies_to,
            },
            after_hash=digest,
        )

        # Defensively: the checklist is seeded by `classify_product(in_scope=
        # true)` and this tool does not require it, so a product can legitimately
        # record an SBOM with no requirements to link to. Missing is fine;
        # raising here would refuse a valid upload over a bookkeeping detail.
        item = next(
            (i for i in state.requirements if i.req_id == "annex_i.ii.1"), None
        )
        if item is not None and evidence.id not in item.evidence_ids:
            item.evidence_ids.append(evidence.id)
            item.last_edited_by = actor_id or None
            item.last_edited_at = _now()

        return state, (evidence.id, applies_to, item is not None)

    evidence_id, applies_to, linked = store_backend.mutate(product_id, _apply)

    out = {
        "ok": True,
        "evidence_id": evidence_id,
        "sha256": digest,
        "format": fmt,
        "satisfies": "annex_i.ii.1",
        "applies_to_version": applies_to,
        "note": (
            "Recorded against Annex I Pt II(1). The SBOM must cover at least "
            "the top-level dependencies; re-record it when the dependency set "
            "changes, since the obligation attaches to what you ship."
        ),
    }
    if not linked:
        out["not_linked"] = (
            "Stored, but there is no Annex I checklist on this product to "
            "attach it to yet. Run classify_product(in_scope=true) and record "
            "it again so annex_i.ii.1 stops reading as a gap."
        )
    return out


# ---- membership --------------------------------------------------------------


def add_member(
    *,
    product_id: str,
    actor_id: str = "",
    email: str = "",
    user_id: str = "",
    role: str = Role.EDITOR.value,
) -> dict:
    """Add a teammate by email so their own agent can work this product.

    Attribution is the point. Each developer connects with their own token, so
    the audit trail can say who was accountable rather than only that an agent
    did something — which is why the answer to "we need two people on this" is
    never "share a token".

    `email` is the way in. `user_id` still works for callers that already hold
    one, but nothing can look one up, so it was unusable in practice.

    An address with no account yet gets an invitation instead, applied the
    moment they verify. Either way the answer is the same: whether a stranger
    has an account here is not something an invitation form should reveal.
    """
    try:
        new_role = Role(role)
    except ValueError as e:
        raise InvalidState(
            f"role must be one of {[r.value for r in Role]}, not {role!r}"
        ) from e

    state = _load(product_id)
    _member(state, actor_id, minimum=Role.OWNER)

    invited_email = ""
    if email:
        from cra.server import invitations

        invited_email = invitations.normalise(email)
        resolved = invitations.user_id_for(invited_email)
        if resolved is None:
            entitlements.require_room_for_member(
                actor_id, current=len(state.members), product_id=product_id
            )
            invitations.invite(
                product_id=product_id,
                email=invited_email,
                role=new_role.value,
                invited_by=actor_id or None,
                product_name=state.name,
            )
            return {
                "ok": True,
                "invited": invited_email,
                "role": new_role.value,
                "pending": True,
                "next": (
                    f"{invited_email} has no account here yet, so they have been "
                    "emailed an invitation. They join this product automatically "
                    "when they sign up."
                ),
            }
        user_id = resolved
    if not user_id:
        raise InvalidState("add_member needs an email address.")

    from cra.schemas import MemberInfo

    def _apply(state, db):
        # The checks above ran on a copy read before the lock; these are the
        # authoritative ones. Two owners adding the last seat a plan allows
        # would otherwise both pass the cap check and both write.
        _member(state, actor_id, minimum=Role.OWNER)
        if user_id in state.members:
            raise InvalidState(f"{invited_email or user_id} is already a member")
        entitlements.require_room_for_member(
            actor_id, current=len(state.members), product_id=product_id
        )
        state.members[user_id] = MemberInfo(
            role=new_role, user_id=user_id, joined_at=_now()
        )
        audit.record(
            db,
            product_id=product_id,
            subject_type="membership",
            subject_id=user_id,
            op="add_member",
            accountable_user_id=actor_id or None,
            payload={"user_id": user_id, "role": new_role.value},
        )
        # The count has to come back from inside the lock: `state` in the
        # enclosing scope is the pre-lock copy and was never mutated.
        return state, len(state.members)

    members_now = store_backend.mutate(product_id, _apply)

    return {
        "ok": True,
        "user_id": user_id,
        "role": new_role.value,
        "members": members_now,
        "note": (
            "They will also receive deadline alerts for this product — "
            "reporting clocks are the team's problem, not the owner's alone."
        ),
    }


def remove_member(*, product_id: str, actor_id: str = "", user_id: str) -> dict:
    def _apply(state, db):
        # The last-owner check has to run under the lock. Read outside it, two
        # concurrent removals each see two owners and both proceed, leaving a
        # product nobody is accountable for — which is the one state this
        # check exists to prevent.
        _member(state, actor_id, minimum=Role.OWNER)

        info = state.members.get(user_id)
        if info is None:
            raise NotFound(f"{user_id} is not a member")
        if info.role == Role.OWNER and sum(
            1 for m in state.members.values() if m.role == Role.OWNER
        ) == 1:
            raise InvalidState(
                "that is the only owner. A product nobody is accountable for is "
                "not a compliance artifact — add another owner first."
            )

        del state.members[user_id]
        audit.record(
            db,
            product_id=product_id,
            subject_type="membership",
            subject_id=user_id,
            op="remove_member",
            accountable_user_id=actor_id or None,
            payload={"user_id": user_id, "was_role": info.role},
        )
        return state, len(state.members)

    remaining = store_backend.mutate(product_id, _apply)
    return {"ok": True, "user_id": user_id, "members": remaining}


# ---- reading the trail -------------------------------------------------------


def get_recent_activity(
    *,
    product_id: str,
    actor_id: str = "",
    limit: int = 30,
    since: Optional[str] = None,
) -> dict:
    """What has changed on this product, and who is accountable for it.

    The "what did my teammates' agents do while I was away" read. Sourced from
    `audit_events`, which is the trail an auditor reads — so this shows the
    same history, not a friendlier parallel feed that could disagree with it.
    """
    state = _load(product_id)
    _member(state, actor_id)

    limit = max(1, min(int(limit), 200))
    q = select(AuditEvent).where(AuditEvent.product_id == product_id)
    if since:
        try:
            cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as e:
            raise InvalidState(f"since is not a valid ISO 8601 timestamp: {since!r}") from e
        if cutoff.tzinfo is None:
            raise InvalidState("since needs a timezone offset")
        q = q.where(AuditEvent.ts > cutoff)

    with session_scope() as db:
        rows = list(
            # `id` breaks the tie, and it is not decoration. `ts` defaults to
            # `func.now()`, which Postgres freezes at transaction start — so
            # every row written by one tool call shares a timestamp to the
            # microsecond. Ordering on `ts` alone leaves those rows in
            # arbitrary order, which is how "an incident was opened" can appear
            # above the vulnerability record that opened it. The sequence is
            # the only thing that knows what happened first.
            db.execute(
                q.order_by(AuditEvent.ts.desc(), AuditEvent.id.desc()).limit(limit)
            ).scalars()
        )
        events = [
            {
                "ts": e.ts.isoformat(),
                "op": e.op,
                "subject_type": e.subject_type,
                "subject_id": e.subject_id,
                "accountable_user_id": e.accountable_user_id,
                "actor_kind": e.actor_kind,
                "actor_model": e.actor_model,
                "rationale": e.rationale,
            }
            for e in rows
        ]

    return {
        "ok": True,
        "product_id": product_id,
        "count": len(events),
        "events": events,
        "note": (
            "Newest first, from the audit trail. Anything not listed here did "
            "not happen — every mutation writes its row in the same "
            "transaction as the change."
        ),
    }



_dispatch.register_mutating("classify_product", classify_product)
_dispatch.register_mutating("record_sbom", record_sbom)
_dispatch.register_mutating("set_support_period", set_support_period)
_dispatch.register_read("list_user_information", list_user_information)
_dispatch.register_mutating("update_user_information", update_user_information)
_dispatch.register_mutating("add_member", add_member)
_dispatch.register_mutating("remove_member", remove_member)
_dispatch.register_read("get_recent_activity", get_recent_activity)
_dispatch.register_read("get_applicable_csirt", get_applicable_csirt)
