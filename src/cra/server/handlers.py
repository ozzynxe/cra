"""The four base tools: overview, list, status, create.

Deliberately thin. Everything with domain weight lives in the module it belongs
to — `risk.py`, `annex.py`, `reporting.py`, `conformity.py` — and these are the
entry points an agent reaches for before it knows which of those it needs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import delete, select

from cra.agents import dispatch as _dispatch
from cra.buildinfo import server_identity
from cra.schemas import ComplianceState, EconomicOperatorRole, MemberInfo, Role
from cra.schemas.enums import Applicability, Lifecycle, RequirementStatus
from cra.server import entitlements, store_backend
from cra.server.errors import InvalidState, NotFound

# Dates fixed by Regulation (EU) 2024/2847. Surfaced on every status call so an
# agent never has to recall them.
REPORTING_OBLIGATIONS_START = datetime(2026, 9, 11, tzinfo=timezone.utc)
FULL_APPLICATION = datetime(2027, 12, 11, tzinfo=timezone.utc)

_DISCLAIMER = (
    "Working aid, not a compliance determination. This tool helps you produce "
    "and track evidence; it cannot certify that a product is compliant, and it "
    "does not replace legal review or a notified body where your product class "
    "requires one."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(product_id: str) -> ComplianceState:
    try:
        return store_backend.get_backend().load_state(product_id)
    except FileNotFoundError as e:
        raise NotFound(f"no product {product_id!r}") from e


def cra_overview(*, product_id: str = "", actor_id: str = "") -> dict:
    """Orientation. Cheap, no state read."""
    now = _now()
    return {
        "ok": True,
        "what_this_is": (
            "Helps you produce and maintain the artifacts the EU Cyber "
            "Resilience Act requires: scope classification, Annex I "
            "requirements with evidence, vulnerability and incident records "
            "with their reporting clocks, and the Annex VII technical file."
        ),
        "not_this": (
            "Not a regulation lookup service. For verbatim CRA text, use a "
            "regulation-text server."
        ),
        "key_dates": {
            "reporting_obligations_start": REPORTING_OBLIGATIONS_START.date().isoformat(),
            "days_until_reporting_starts": (REPORTING_OBLIGATIONS_START - now).days,
            "full_application": FULL_APPLICATION.date().isoformat(),
        },
        "reporting_clocks": {
            "early_warning": "within 24h of becoming aware",
            "notification": "within 72h",
            "final_report": "14 days (exploited vulnerability) / 1 month (severe incident)",
        },
        "start_here": (
            "list_products() to see what's tracked, then "
            "get_compliance_status(product_id) for the state of one. "
            "create_product() if it isn't tracked yet."
        ),
        # Delivered here because this is the orientation call every session
        # makes first, and because a tool *result* is fetched live while a
        # client's tool list is cached from session start. It is the only
        # place a caller can find out that its own menu is out of date.
        "server": server_identity(),
        # Same reasoning: an agent should be able to see the ceiling before it
        # walks into one. Finding out a tool is not covered by failing to call
        # it wastes a turn and reads like a bug.
        "plan": entitlements.describe(actor_id),
        "disclaimer": _DISCLAIMER,
    }


def _member_product_ids(actor_id: str) -> Optional[list[str]]:
    """Product ids this user is on, from the index rather than the blobs.

    `product_members` exists precisely so this question does not require
    deserialising every product in the store, and `store_pg` already mirrors
    membership into it on save. Returns None when there is no database (the
    file backend in dev), where the caller falls back to scanning.
    """
    try:
        from cra.db import ProductMember, session_scope

        with session_scope() as db:
            return [
                m.product_id
                for m in db.execute(
                    select(ProductMember).where(ProductMember.user_id == actor_id)
                ).scalars()
            ]
    except Exception:  # noqa: BLE001 — dev file store, or no DATABASE_URL
        return None


def list_products(*, product_id: str = "", actor_id: str = "") -> dict:
    backend = store_backend.get_backend()

    # The console's first page. Scanning every blob in the store and filtering
    # in Python is the wrong shape however few rows it currently touches.
    pids = _member_product_ids(actor_id) if actor_id else None
    if pids is None:
        pids = list(backend.list_sessions())

    out = []
    for pid in pids:
        try:
            s = backend.load_state(pid)
        except Exception:  # noqa: BLE001 — a corrupt blob shouldn't hide the rest
            continue
        # Kept even when the index chose the ids: the blob is the source of
        # truth for membership, the index is a mirror of it, and a stale mirror
        # must never widen access.
        if actor_id and actor_id not in s.members:
            continue
        out.append(
            {
                "product_id": s.product_id,
                "name": s.name,
                "lifecycle": s.lifecycle,
                "product_class": s.classification.product_class,
            }
        )
    return {"ok": True, "products": out, "count": len(out)}


def create_product(
    *,
    product_id: str = "",
    actor_id: str = "",
    name: str,
    description: str = "",
    intended_use: str = "",
    economic_operator_role: Optional[str] = None,
) -> dict:
    now = _now()
    entitlements.require_room_for_product(actor_id)
    # Assumed rather than defaulted silently. The role decides which
    # obligations exist at all — Annex I binds manufacturers and nobody
    # else — and a parameter that quietly says `manufacturer` is why almost
    # every product in the store claims to be one whether or not anyone
    # chose it. The assumption is still made, because refusing to create a
    # product until the question is answered is worse; what changes is that
    # the reply says so.
    assumed_role = economic_operator_role is None
    try:
        role = EconomicOperatorRole(
            economic_operator_role or EconomicOperatorRole.MANUFACTURER.value
        )
    except ValueError as e:
        # An enum ValueError enveloped as `internal_error` tells the model
        # nothing it can act on, and this is a value it has to choose.
        raise InvalidState(
            f"economic_operator_role must be one of "
            f"{[r.value for r in EconomicOperatorRole]}, not "
            f"{economic_operator_role!r}"
        ) from e

    # A plain UUID string, not a prefixed id: `products.id` and every column
    # that references it are typed UUID, so a "prod-…" id is unstorable — and
    # it fails as a query cast rather than an insert, which is worse.
    pid = product_id or str(uuid.uuid4())
    state = ComplianceState(
        product_id=pid,
        name=name,
        description=description,
        intended_use=intended_use,
        economic_operator_role=role,
        members=(
            {actor_id: MemberInfo(role=Role.OWNER, user_id=actor_id, joined_at=now)}
            if actor_id
            else {}
        ),
        created_at=now,
        updated_at=now,
    )
    store_backend.get_backend().save_state(state)
    out = {
        "ok": True,
        "product_id": pid,
        "name": name,
        "economic_operator_role": role.value,
        "next": (
            "Classification is undetermined. Run classify_product() to find out "
            "whether the CRA applies and which product class you're in — that "
            "decides your conformity route."
        ),
        "disclaimer": _DISCLAIMER,
    }
    if assumed_role:
        out["role_assumed"] = (
            "No economic_operator_role was given, so this product is recorded "
            "as `manufacturer` — the most common case and the heaviest "
            "obligation set. Ask the user, because it decides which duties "
            "exist at all: Annex I binds manufacturers (Article 13(1)), an "
            "importer verifies someone else's compliance (Article 19), a "
            "distributor checks the CE marking (Article 20), and an "
            "open-source steward has no Annex I obligation whatever (Article "
            "24). Correct it with set_economic_operator_role(role=..., "
            "rationale=...) — nothing is lost by changing it later."
        )
    return out


def get_compliance_status(*, product_id: str, actor_id: str = "") -> dict:
    from cra.server import reporting  # local: avoids an import cycle at module load
    from cra.server.scoping import obligation_view as _obligation  # same reason

    s = _load(product_id)
    # Membership gate. This read returns unreported exploited-vulnerability
    # details, which are among the most sensitive data a vendor holds — a
    # product id is not a capability. `actor_id` is empty only on the legacy
    # static party mounts, where there is no user to check, which `_member`
    # handles. Via the shared helper rather than inline: one idiom is what
    # lets `test_membership_sweep` find a handler that forgot.
    from cra.server.scoping import _member  # local: scoping imports this

    _member(s, actor_id)
    now = _now()
    reqs = s.requirements
    open_obligations = reporting.open_obligation_views(product_id)
    deadlines: dict = {
        "days_until_reporting_starts": (REPORTING_OBLIGATIONS_START - now).days,
        "days_until_full_application": (FULL_APPLICATION - now).days,
    }
    if open_obligations is None:
        # Never render this as "nothing due" — see open_obligation_views.
        deadlines["open_obligations"] = None
        deadlines["unavailable"] = (
            "No database configured, so reporting deadlines cannot be read. "
            "This does not mean nothing is due."
        )
    else:
        deadlines["open_obligations"] = open_obligations
        deadlines["open_count"] = len(open_obligations)
        if not open_obligations:
            deadlines["scope"] = _no_clocks_note(s, reqs)

    return {
        "ok": True,
        "product_id": s.product_id,
        "name": s.name,
        # Deadlines lead: one call should surface anything urgent without the
        # agent having to ask a second question.
        "deadlines": deadlines,
        "classification": {
            "product_class": s.classification.product_class,
            "in_scope": s.classification.in_scope,
            "conformity_route": s.classification.conformity_route,
            "rationale": s.classification.rationale,
        },
        "economic_operator_role": s.economic_operator_role,
        "lifecycle": s.lifecycle,
        # Unasked, like the deadlines above it. A support period that ended
        # last month changes which duties are live, and finding that out
        # requires knowing to ask — which is exactly the kind of thing this
        # call exists to remove.
        "support_period": _support_period_view(s),
        # Sits above requirements because it is what they rest on: Annex I Part
        # I applies on the basis of the Article 13(2) assessment.
        "risk_assessment": risk._assessment_view(s),
        "requirements": {
            # Before the counts, not after them: an agent composing "where
            # do we stand" reads this block top-down, and 22 outstanding
            # requirements mean something different when they are not
            # yours.
            "annex_i": _obligation(s),
            "total": len(reqs),
            "by_status": _count_by(reqs, "status"),
            "by_applicability": _count_by(reqs, "applicability"),
        },
        # Named, not only numbered. Same defect as #38 on `get_recent_activity`:
        # a UUID answers which account and not which colleague, and this is the
        # response an agent reads when asked who else is on a product.
        "members": _member_views(s),
        "disclaimer": _DISCLAIMER,
    }


def delete_product(
    *,
    product_id: str,
    actor_id: str = "",
    confirm_name: str,
) -> dict:
    """Delete a product that was never placed on the market.

    Until now nothing could be deleted at all, and `Lifecycle.WITHDRAWN` was
    unreachable — so a free account's first product was permanent, and someone
    trying the tool spent their single allocation on a test they could never
    clear. That is a trap at the exact moment a new user is deciding whether
    this is worth using.

    **The line is placing on the market, and it is the regulation's own.**
    Article 13(13) keeps the technical documentation and the EU declaration at
    the disposal of authorities "for at least 10 years after the product with
    digital elements has been placed on the market or for the support period,
    whichever is longer". The clock starts at placing; a product in development
    has no retention obligation at all. So before that moment there is nothing
    to keep, and after it there is nothing we may delete.

    Refused also where anything reached the statutory archive, which is a
    separate and stronger reason: those objects are under Object Lock for ten
    years and cannot be removed, so deleting the rows that point at them would
    leave the archive holding artefacts nothing can explain. In practice the two
    conditions coincide — every writer of that archive requires CONFORMITY, and
    the accounts this exists for are on the free plan.

    `confirm_name` must match the product name exactly. Not ceremony: this is
    reached through an agent, and a typed name is a thing the user has to
    supply rather than something a model can infer from context.
    """
    from cra.db import Attestation, AuditEvent, Product, StatutoryExport, session_scope
    from cra.server.annex import placed_releases

    # Through the shared helper, not an inline check. `test_membership_sweep`
    # objected to the hand-rolled version and was right to: a second idiom for
    # one invariant is what makes a missing check invisible, which is the
    # reason three handlers were converged onto this helper earlier today.
    # Owner only — deleting is not maintainer work.
    from cra.server.scoping import _member

    s = _load(product_id)
    _member(s, actor_id, minimum=Role.OWNER)

    # Checked after membership, so a non-member cannot learn a product's name by
    # guessing at it, and before anything else, so a wrong name costs nothing.
    if (confirm_name or "").strip() != s.name:
        raise InvalidState(
            f"confirm_name does not match. This product is named {s.name!r}, "
            "and deleting it is not reversible — so the name has to be typed "
            "rather than inferred. Ask the user for it."
        )

    placed = placed_releases(s)
    if placed or s.lifecycle != Lifecycle.IN_DEVELOPMENT.value:
        versions = ", ".join(r.version for r in placed) or s.lifecycle
        raise InvalidState(
            f"{s.name!r} has been placed on the market ({versions}) and cannot "
            "be deleted. Article 13(13) keeps the technical documentation and "
            "the EU declaration at the disposal of market surveillance "
            "authorities for at least ten years from that moment, or the "
            "support period if longer — and that duty is yours, not this "
            "service's, so removing our copy would not discharge it. Deletion "
            "is available up to the point of placing on the market and not "
            "after it."
        )

    with session_scope() as db:
        exported = db.execute(
            select(StatutoryExport).where(StatutoryExport.product_id == product_id)
        ).scalars().first()
        if exported is not None:
            raise InvalidState(
                f"{s.name!r} has artefacts in the statutory archive, which is "
                "Object Lock storage that cannot be deleted for ten years. "
                "Removing the product would leave those objects with nothing "
                "to explain them. This normally means a technical file was "
                "frozen, a declaration drawn up, or a sign-off recorded."
            )

        # Explicitly, because neither carries a foreign key to `products` — the
        # record of who decided what is built to outlive the product. That is
        # the right default and the wrong one here: keeping an audit trail
        # describing a product the owner has deleted is a trail nothing can be
        # reconciled against, and Article 13(13) names the technical
        # documentation and the declaration, not audit rows.
        db.execute(delete(AuditEvent).where(AuditEvent.product_id == product_id))
        db.execute(delete(Attestation).where(Attestation.product_id == product_id))
        db.execute(delete(Product).where(Product.id == product_id))

    return {
        "ok": True,
        "deleted": product_id,
        "name": s.name,
        "note": (
            f"{s.name!r} is gone from this service, with its requirements, "
            "evidence, risk assessment, advisory candidates, scans, members "
            "and audit trail. It was never placed on the market, so no Article "
            "13(13) retention duty had started and nothing of it reached the "
            "statutory archive."
        ),
        # Said because it is true and because the alternative is a "deleted"
        # that quietly means something narrower. The privacy page makes the
        # same statement.
        "backups": (
            "Nightly disaster-recovery snapshots still contain it until they "
            "expire, which is 90 days at most. Those are not readable by "
            "anyone using this service and are not used to restore individual "
            "records."
        ),
    }


def _member_views(s) -> list[dict]:
    """Members with a readable label where one can be resolved.

    Best-effort by design: the blob is the source of truth for *membership*, and
    the `users` row only supplies the label. A database that cannot be reached
    must degrade to the ids rather than fail the whole status read, which is the
    call an agent makes first in any conversation.
    """
    rows = [{"user_id": uid, "role": m.role} for uid, m in s.members.items()]
    try:
        from cra.db import session_scope
        from cra.server.scoping import _actor_labels

        with session_scope() as db:
            names = _actor_labels(db, {r["user_id"] for r in rows})
    except Exception:  # noqa: BLE001 — dev file store, or no DATABASE_URL
        return rows
    for r in rows:
        label = names.get(r["user_id"])
        if label:
            r["name"] = label
    return rows


def _no_clocks_note(s, reqs) -> str:
    """Say what an empty obligation list is about, and what it is not about.

    `open_obligations: []` beside `open_count: 0` is true and narrow: no
    Article 14 clock is running. But `deadlines` leads this response by design,
    the key names carry no namespace, and an agent composing "what is
    outstanding?" from green fields has every reason to answer "nothing" —
    beside an unconfirmed assessment and two thirds of a checklist unstarted.

    Same family as the `unavailable` note directly above, which exists because
    an unreadable list must never render as nothing due. This is the other
    half: an *empty* list must never render as nothing outstanding. The
    difference is that the unreadable case is an absence of knowledge and this
    one is knowledge of a narrow absence, which is the harder of the two to
    write honestly — the zero is genuinely true, and that is exactly why it
    travels so well.

    The pointers are drawn from the same payload rather than recomputed. This
    is not a gap report and must not read as one: `assemble_technical_file` is
    the surface that answers completeness, and the note says so instead of
    growing a second, drifting definition of settled.
    """
    note = (
        "This counts Article 14 reporting clocks only — the 24-hour early "
        "warning, the 72-hour notification, the 14-day final report. Zero "
        "means no incident is currently being reported. It is not a statement "
        "about whether anything else is outstanding."
    )

    also: list[str] = []
    # `risk_assessment` is None until one is started — the `present: False`
    # case in `_assessment_view`. Unstarted and started-but-unconfirmed are
    # different sentences, and neither is a kind of the other.
    ra = s.risk_assessment
    if ra is None or not ra.risks:
        also.append("no Article 13(2) risk assessment has been started")
    elif not ra.confirmed_at:
        also.append("the Article 13(2) risk assessment is not confirmed")
    unsettled = sum(
        1 for r in reqs
        if r.applicability == Applicability.UNDETERMINED
        or r.status in (RequirementStatus.NOT_STARTED, RequirementStatus.IN_PROGRESS)
    )
    if unsettled:
        # Named for exactly what was measured. `_is_gap` — the technical file's
        # test — also counts a requirement with no evidence, or evidence
        # against a superseded release, so this number can only be lower than
        # the real one. A count that can understate must say what it counted,
        # or it becomes the reassuring figure in a note written to stop one.
        also.append(
            f"{unsettled} of {len(reqs)} Annex I requirements have no "
            "applicability decision or are unfinished (applicability and "
            "status only — the technical file also checks evidence)"
        )
    if not s.support_period.end:
        also.append("no Article 13(8) support period is recorded")

    if also:
        note += (
            " In this same response: " + "; ".join(also) + ". Read "
            "assemble_technical_file() for what is actually complete — it is "
            "the surface that answers that question."
        )
    return note


def _support_period_view(s) -> dict:
    """Where the product sits against its own Article 13(8) period.

    Derived from the recorded dates every time it is asked, never stored — the
    same rule as `risk.staleness` and `deadlines.obligation_state`. A stored
    "ended" flag needs something to flip it, and the something eventually does
    not run.

    `state` is deliberately a word and not a boolean. "Is it supported" has
    three answers here — not recorded, inside, ended — and the first is not a
    kind of "no".
    """
    sp = s.support_period
    if not sp.end:
        return {
            "state": "not_recorded",
            "why_it_matters": (
                "Article 13(8) requires a support period of at least five "
                "years, and Annex VII(4) requires the reasoning behind it. "
                "Neither is recorded, so the technical file cannot report that "
                "section as met. set_support_period(end=..., rationale=...)."
            ),
        }

    now = datetime.now(timezone.utc)
    end = sp.end if sp.end.tzinfo else sp.end.replace(tzinfo=timezone.utc)
    days = (end - now).total_seconds() / 86400.0
    out = {
        "state": "ended" if days < 0 else "active",
        "end": end.isoformat(),
        "start": sp.start.isoformat() if sp.start else None,
        "days_remaining": round(days, 1),
        "expected_use_years": sp.expected_use_years,
        "published_url": sp.published_url,
        "has_reasoning": bool((sp.rationale or "").strip()),
    }
    if days < 0:
        out["note"] = (
            f"The support period ended {abs(days):.0f} days ago. The Article "
            "13(8) vulnerability-handling duty ran for that period; Article "
            "13(9) still requires security updates already issued to remain "
            "available for ten years."
        )
    elif days <= 180:
        out["note"] = (
            f"{days:.0f} days left. Extending is a determination with its own "
            "reasoning, not a date change — set_support_period() again."
        )
    if not out["has_reasoning"]:
        out["incomplete"] = (
            "A date is recorded but not the information it was based on, which "
            "is the half Annex VII(4) actually asks for."
        )
    return out


def _count_by(items, attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        k = getattr(it, attr)
        out[k] = out.get(k, 0) + 1
    return out


# Importing for the registration side-effect, at the bottom so the import lands
# after this module's own handlers are defined. `dispatch._ensure_handlers_loaded`
# imports only this module, so anything not reached from here is invisible to
# the dispatcher.
from cra.server import (  # noqa: E402,F401
    export,
    advisories,
    annex,
    conformity,
    drafting,
    releases,
    reporting,
    risk,
    scoping,
    subscription,
)

_dispatch.register_read("cra_overview", cra_overview)
_dispatch.register_read("list_products", list_products)
_dispatch.register_read("get_compliance_status", get_compliance_status)
_dispatch.register_mutating("create_product", create_product)
_dispatch.register_mutating("delete_product", delete_product)
