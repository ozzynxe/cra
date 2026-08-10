"""What an account's plan covers, and what it does not.

`users.tier` existed on the schema long before anything read it. This is the
layer that gives it consequences.

## Where the line falls

A free account gets the work: classification, the Article 13(2) risk assessment
and every revision of it, the full Annex I and Annex II checklists with evidence
recorded against them, its SBOM scanned daily against OSV and CISA KEV, the
Article 14 clocks if something happens, and the Annex VII file as a gap report.

What it cannot do is the **legal act** — freeze the technical file, draw up the
Declaration of Conformity, sign off, record a release, or set the Article 13(8)
support period. `CONFORMITY` is the only paid feature.

Two structural properties follow, and both are load-bearing:

  * **`assemble_technical_file` was already built this way** — a gap report with
    an optional freeze. The gap report is the working view; the freeze is the
    act. The boundary is one the domain already had, not one imposed on it.
  * **The statutory archive is the only irreversible commitment here.**
    `statutory_export` is Object Lock, ten years, and cannot be reclaimed. Every
    path that writes to it is `CONFORMITY`, so nothing on the free plan can
    commit this service to a decade. A test pins that, and it is the one place
    where "which side of the line?" has a technical answer rather than a
    commercial one.

## Shadow mode

`CRA_ENTITLEMENTS_ENFORCED` defaults **off**, and a deployment opts in by
setting it. While it is off, every gate logs what it *would* have blocked and
lets the call through. `rate_limit.py` has the same arrangement for the same
reason: the failure mode of a wrong gate here is
locking somebody out of compliance work they may be legally obliged to do, and
that is not a thing to discover from a support email.

## What a refusal must not say

`UpgradeRequired` says what the tool would have done and that the plan does not
cover it. It must never imply a compliance conclusion. A free account that
cannot reach the reporting tools has not been told its product is fine — it has
been told this service is not tracking that for it, which is a different
sentence and the only honest one.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select

from cra.db import Product, ProductMember, User, session_scope
from cra.server.errors import TransitionError

log = logging.getLogger(__name__)

UNLIMITED = 1_000_000

# Feature names. Coarse on purpose: a taxonomy finer than the boundaries it
# describes is one that drifts from them.
EVIDENCE = "evidence"        # recording answers against Annex I requirements
CONFORMITY = "conformity"    # freezing the file, the DoC, sign-off
REASSESSMENT = "reassessment"  # risk assessment version 2 and beyond
REPORTING = "reporting"      # Article 14 clocks, incidents, ENISA drafts
ADVISORIES = "advisories"    # SBOM → OSV → KEV scanning, and its daily sweep

ALL_FEATURES = frozenset({EVIDENCE, CONFORMITY, REASSESSMENT, REPORTING, ADVISORIES})

# Everything except the legal act. See "Where the line falls" above — this is
# the whole ladder in one expression, and writing it as a subtraction rather
# than a list means a feature added to ALL_FEATURES is free by default. That is
# the right default now: the paid thing is placing a product on the market, and
# a new capability is presumed to be part of getting there unless someone
# decides otherwise.
FREE_FEATURES = ALL_FEATURES - {CONFORMITY}


@dataclass(frozen=True)
class Plan:
    name: str
    max_products: int
    max_members: int
    features: frozenset

    def covers(self, feature: str) -> bool:
        return feature in self.features


# The ladder. Amounts deliberately appear nowhere in this repository — they
# live in the payment provider and are read at render time, because a number in
# the source is a number that goes stale the first time it changes and is wrong
# on a page somebody is reading.
_LADDER: tuple[Plan, ...] = (
    Plan("free", max_products=1, max_members=UNLIMITED, features=FREE_FEATURES),
    Plan("solo", max_products=1, max_members=UNLIMITED, features=ALL_FEATURES),
    Plan("team", max_products=3, max_members=UNLIMITED, features=ALL_FEATURES),
    Plan("portfolio", max_products=10, max_members=UNLIMITED, features=ALL_FEATURES),
    # Everyone who held an account before entitlements existed. The site
    # promised notice before access changed; this is that promise, kept.
    Plan("founding", max_products=10, max_members=UNLIMITED, features=ALL_FEATURES),
    Plan("internal", max_products=UNLIMITED, max_members=UNLIMITED, features=ALL_FEATURES),
)

FREE = _LADDER[0]

# Plans that are granted rather than bought, and so have no paid-through date
# to fall off the end of. Defined once because it is consulted in two places —
# here and `billing.expire_stale_tier` — and two lists that must agree are one
# edit away from disagreeing. They did: `founding` was missing from this one,
# and a grandfathered account with a stale `tier_until` silently read as free.
GRANTS = frozenset({"free", "founding", "internal"})


def _limit(plan_name: str, field: str, default: int) -> int:
    """Env override, so a limit can move without a deploy."""
    raw = os.environ.get(f"CRA_PLAN_{plan_name.upper()}_{field.upper()}")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning("ignoring non-numeric CRA_PLAN_%s_%s=%r", plan_name.upper(), field.upper(), raw)
        return default


def plans() -> dict[str, Plan]:
    return {
        p.name: Plan(
            name=p.name,
            max_products=_limit(p.name, "max_products", p.max_products),
            max_members=_limit(p.name, "max_members", p.max_members),
            features=p.features,
        )
        for p in _LADDER
    }


def enforced() -> bool:
    """Off by default. See "Shadow mode" above."""
    raw = os.environ.get("CRA_ENTITLEMENTS_ENFORCED", "0").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def plan_for(user_id: Optional[str]) -> Plan:
    """The plan an account is on right now.

    An expired paid tier reads as free without needing anything to have run —
    `tier_until` is the paid-through date, and deriving from it beats a flag
    some sweeper was supposed to flip. Same reasoning as `deadlines` deriving
    obligation state rather than storing it.

    No user id means no account, which is the legacy static-bearer party tokens
    and internal calls. Those get the operator plan: they cannot be sold to,
    and refusing them would break the two-party POC mounts and the tests.
    """
    table = plans()
    if not user_id:
        return table["internal"]

    try:
        with session_scope() as db:
            user = db.get(User, user_id)
            if user is None:
                return table["free"]
            name = (user.tier or "free").strip().lower()
            until = user.tier_until
    except Exception:  # noqa: BLE001 — see below; this must not block work
        # If the tier cannot be read, the honest position is that we do not
        # know what plan this account is on — and "we could not check" must
        # not resolve to "free". The same rule the rest of this codebase runs
        # on: an absence of knowledge is not knowledge of absence.
        #
        # Concretely, the failure modes are a database outage and a deployment
        # with no database at all (CRA_STORE=file, dev). Refusing in either
        # case would lock somebody out of compliance work over a billing
        # lookup, which is a far worse outcome than an unbilled call.
        log.exception("could not read tier for %s; allowing rather than refusing", user_id)
        return table["internal"]

    plan = table.get(name)
    if plan is None:
        log.warning("user %s has unknown tier %r; treating as free", user_id, name)
        return table["free"]
    if plan.name not in GRANTS and until is not None and until < _now():
        log.info("user %s tier %s expired at %s; treating as free", user_id, name, until)
        return table["free"]
    return plan


def plan_for_product(product_id: str, *, fallback_user_id: Optional[str] = None) -> Plan:
    """The plan governing work on a product: its **owner's**.

    Entitlements used to be checked against whoever was calling, which made a
    team plan mean "you may add colleagues" rather than "your colleagues may
    work". Somebody paid for three products and unlimited members, added a
    teammate, and the teammate was refused by their own free tier — while the
    pricing page said "unlimited members", which a buyer reads as the opposite.

    The owner is always the payer: only an owner can add members, and products
    count against the owner's cap. So asking the owner's plan is both correct
    and closes no loophole a member could exploit.
    """
    try:
        with session_scope() as db:
            row = db.get(Product, product_id)
            owner = row.owner_user_id if row is not None else None
    except Exception:  # noqa: BLE001 — same fail-open rule as plan_for
        log.exception("could not read the owner of %s; allowing", product_id)
        return plans()["internal"]
    if not owner:
        return plan_for(fallback_user_id)
    return plan_for(owner)


def covered_product_ids(user_id: Optional[str], feature: str) -> tuple[list[str], list[str]]:
    """Split this user's products into (covered, not covered) for `feature`.

    For the tools that answer across everything someone is on. The uncovered
    list is returned rather than dropped: a shorter answer that does not say
    what it left out is the failure this codebase exists to avoid, and here it
    would read as "nothing is due".

    **Dormant since 2026-08-09, deliberately.** Both callers ask about
    `REPORTING` (`reporting.get_reporting_deadlines`, and the session-agnostic
    pre-check in `dispatch`), and `REPORTING` is now on the free plan — so no
    call can currently return a non-empty `blocked` list. The function is kept
    whole rather than simplified: it is correct behaviour with no gated feature
    pointed at it, the shadow-mode branch below records a real bug that was
    fixed here, and the first cross-product tool gated on `CONFORMITY` would
    have to rebuild all of it. A test asserts it still splits correctly when
    given a feature the plan lacks, so it cannot rot while unused.
    """
    if not user_id:
        return [], []
    try:
        with session_scope() as db:
            pids = [
                m.product_id
                for m in db.execute(
                    select(ProductMember).where(ProductMember.user_id == user_id)
                ).scalars()
            ]
    except Exception:  # noqa: BLE001
        log.exception("could not list products for %s; allowing", user_id)
        return [], []

    if not enforced():
        # Shadow mode filters nothing. This one is easy to get wrong because it
        # *returns data* rather than refusing a call: with the switch off and
        # the filter still applied, "what is due across everything I own" would
        # have answered "nothing" for every account on the free default. A test
        # caught it. Every other gate checks `enforced()`; so does this.
        return pids, []

    covered, blocked = [], []
    for pid in pids:
        (covered if plan_for_product(pid).covers(feature) else blocked).append(pid)
    return covered, blocked


class UpgradeRequired(TransitionError):
    """The account's plan does not cover this.

    A `TransitionError` so it travels the path every other domain refusal
    travels — `dispatch` envelopes it as `{ok: false, code: "upgrade_required"}`
    and the agent branches on the code rather than parsing prose.
    """

    code = "upgrade_required"


# How someone actually upgrades. This said "there is no self-serve checkout yet"
# for some time after checkout shipped, on every refusal the product emits —
# which is the sort of thing nobody notices because it reads as boilerplate.
_HOW = (
    "get_upgrade_link() returns a checkout link, or change plan at "
    "https://cra.skarp.app/pricing. Email cra@skarp.app if you would rather "
    "talk to someone."
)


def _refuse(plan: Plan, what: str) -> UpgradeRequired:
    return UpgradeRequired(
        f"{what} This is not covered by the '{plan.name}' plan. "
        f"Nothing about your product's compliance is implied by this — it means "
        f"this service is not tracking it for you. {_HOW}"
    )


def require(
    user_id: Optional[str],
    feature: str,
    *,
    what: str,
    product_id: Optional[str] = None,
) -> None:
    """Raise unless the governing plan covers `feature`.

    With a `product_id` the governing plan is the product owner's — see
    `plan_for_product`. Without one the caller's own plan applies, which is
    right for account-level things.

    `what` names the thing that would have happened, in the past conditional,
    so the message reads as an explanation rather than a scolding.
    """
    plan = plan_for_product(product_id, fallback_user_id=user_id) if product_id else plan_for(user_id)
    if plan.covers(feature):
        return
    if not enforced():
        log.info(
            "entitlements(shadow): would block feature=%s for user=%s on plan=%s",
            feature, user_id, plan.name,
        )
        return
    raise _refuse(plan, what)


def require_room_for_product(user_id: Optional[str]) -> None:
    """Raise unless the account may own another product."""
    plan = plan_for(user_id)
    if not user_id or plan.max_products >= UNLIMITED:
        return
    try:
        with session_scope() as db:
            owned = db.execute(
                select(func.count()).select_from(Product).where(Product.owner_user_id == user_id)
            ).scalar_one()
    except Exception:  # noqa: BLE001 — same rule as plan_for: allow, don't refuse
        log.exception("could not count products for %s; allowing", user_id)
        return
    if owned < plan.max_products:
        return
    if not enforced():
        log.info(
            "entitlements(shadow): would block product %d for user=%s on plan=%s",
            owned + 1, user_id, plan.name,
        )
        return
    raise UpgradeRequired(
        f"The '{plan.name}' plan covers {plan.max_products} product"
        f"{'' if plan.max_products == 1 else 's'} and you have {owned}. {_HOW}"
    )


def require_room_for_member(
    user_id: Optional[str], *, current: int, product_id: Optional[str] = None
) -> None:
    """Raise unless the product may gain another member.

    **Dormant since 2026-08-09**: every plan on the ladder is unlimited, so the
    early return below always fires. Kept rather than deleted because the check
    belongs at this seam if a seat cap ever returns, and because deleting it
    would take the reasoning below with it.

    Seats stopped being metered because a seat cap is wrong on its own terms
    here: an Article 14 clock runs for 24 hours, and a plan that permits exactly
    one login makes that person a single point of failure on a statutory
    deadline. Metering them also made the boundary fall on hiring rather than on
    anything to do with compliance.
    """
    plan = plan_for_product(product_id, fallback_user_id=user_id) if product_id else plan_for(user_id)
    if plan.max_members >= UNLIMITED:
        return
    if current < plan.max_members:
        return
    if not enforced():
        log.info(
            "entitlements(shadow): would block member %d for user=%s on plan=%s",
            current + 1, user_id, plan.name,
        )
        return
    raise UpgradeRequired(
        f"The '{plan.name}' plan covers {plan.max_members} member(s) and this "
        f"product already has {current}. Everyone who makes a compliance "
        f"decision should be in the audit trail under their own name, so this "
        f"is worth changing plan for rather than sharing a token. {_HOW}"
    )


def describe(user_id: Optional[str]) -> dict:
    """The plan block for `cra_overview` — the ceiling, before it is met."""
    plan = plan_for(user_id)
    missing = sorted(ALL_FEATURES - plan.features)
    return {
        "name": plan.name,
        "max_products": None if plan.max_products >= UNLIMITED else plan.max_products,
        "max_members": None if plan.max_members >= UNLIMITED else plan.max_members,
        "not_included": missing,
        "enforced": enforced(),
        "note": (
            None
            if not missing
            else (
                "Not included means this service is not tracking it for you. It "
                "says nothing about whether your product meets the requirement."
            )
        ),
    }
