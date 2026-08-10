"""The two tools that let somebody pay, and the web routes Stripe talks to.

There is no SPA and no dashboard, so upgrading has to be reachable from the
place the user already is: their agent. `get_upgrade_link` returns a hosted
Stripe Checkout URL and the agent hands it over; `manage_subscription` returns
a Customer Portal URL for changing or cancelling one.

Both are free and product-agnostic, deliberately. A paywall you cannot reach
from behind the paywall is a dead end, and this is the one thing a free account
must always be able to do.

## What these tools will not do

**They never take card details.** Nothing here accepts a number, and no tool
should ever be added that does — the whole point of handing over a Stripe URL
is that the card is typed into Stripe's page, on Stripe's origin, and this
service never sees it.

**They never claim the upgrade happened.** `get_upgrade_link` returns a link,
which is all it knows; access arrives when the webhook does. Reporting success
at link-creation time would be a lie a user could act on.
"""

from __future__ import annotations

import logging

from cra.agents import dispatch as _dispatch
from cra.db import User, session_scope
from cra.server import billing, entitlements
from cra.server.errors import InvalidState, NotFound

log = logging.getLogger(__name__)


def _user(actor_id: str) -> User:
    if not actor_id:
        raise InvalidState(
            "This connection has no user account behind it, so there is "
            "nothing to bill. Get a token from /access."
        )
    with session_scope() as db:
        user = db.get(User, actor_id)
        if user is None:
            raise NotFound("no account for this token")
        db.expunge(user)
        return user


def _plan_menu() -> list[dict]:
    """What is for sale, with what each plan lifts — not what it costs.

    Prices deliberately do not appear: they live in Stripe, and a number
    duplicated here would be wrong the first time one changed. The customer
    sees the price on the checkout page, from the system that charges it.
    """
    table = entitlements.plans()
    out = []
    for name, cadences in sorted(billing.sellable_plans().items()):
        plan = table[name]
        out.append(
            {
                "plan": name,
                "billed": cadences,
                "products": (
                    None if plan.max_products >= entitlements.UNLIMITED
                    else plan.max_products
                ),
                "members": (
                    None if plan.max_members >= entitlements.UNLIMITED
                    else plan.max_members
                ),
                "adds": sorted(plan.features - entitlements.FREE.features),
            }
        )
    return out


def get_upgrade_link(
    *,
    product_id: str = "",
    actor_id: str = "",
    plan: str = "",
    cadence: str = "monthly",
) -> dict:
    """Show the plans, or start a checkout for one."""
    current = entitlements.plan_for(actor_id)

    if not billing.is_billing_configured():
        # Not an error the model should retry — say what to do instead.
        return {
            "ok": True,
            "current_plan": current.name,
            "checkout_available": False,
            "how": (
                "Online checkout is not set up on this deployment. Email "
                "cra@skarp.app to change plan."
            ),
        }

    menu = _plan_menu()
    if not plan:
        return {
            "ok": True,
            "current_plan": current.name,
            "current_limits": entitlements.describe(actor_id),
            "plans": menu,
            "on_the_web": f"{billing.app_origin().rstrip('/')}/pricing",
            "next": (
                "Prices and plans are at the /pricing link above, and the user "
                "can subscribe there directly — prefer offering that. "
                "get_upgrade_link(plan=…) returns a checkout link instead if "
                "they would rather not leave this conversation."
            ),
        }

    user = _user(actor_id)
    try:
        result = billing.create_checkout_session(user, plan=plan, cadence=cadence)
    except ValueError as e:
        raise InvalidState(str(e)) from None
    except Exception as e:  # noqa: BLE001 — Stripe detail is not the user's problem
        log.exception("could not create a checkout session for %s", actor_id)
        raise InvalidState(
            "Stripe could not start a checkout just now. Try again shortly, or "
            "email cra@skarp.app."
        ) from e

    log.info("checkout started: user=%s plan=%s cadence=%s", actor_id, plan, cadence)
    return {
        "ok": True,
        "current_plan": current.name,
        "plan": plan,
        "cadence": cadence,
        "checkout_url": result.url,
        # Said plainly because the agent is about to relay this to a person:
        # the link is not the upgrade, and nothing here has changed yet.
        "note": (
            "Open this link to pay. Nothing has changed yet — the plan moves "
            "when Stripe confirms the payment, usually within a few seconds of "
            "completing checkout. Run cra_overview() afterwards to see it."
        ),
        # Say where this can be done without an agent in the loop. Someone who
        # is wary of a payment link an AI produced is right to be, and the
        # honest answer is that they never have to take one.
        "or_on_the_web": f"{billing.app_origin().rstrip('/')}/pricing",
        "give_the_user_the_link": True,
    }


def manage_subscription(*, product_id: str = "", actor_id: str = "") -> dict:
    """A Stripe Customer Portal link: invoices, card, cancellation."""
    current = entitlements.plan_for(actor_id)
    user = _user(actor_id)

    if not user.stripe_customer_id:
        return {
            "ok": True,
            "current_plan": current.name,
            "portal_url": None,
            "why": (
                f"This account is on '{current.name}' and has never been "
                "billed, so there is no subscription to manage. "
                "get_upgrade_link() starts one."
            ),
        }
    if not billing.is_billing_configured():
        raise InvalidState(
            "Billing is not configured on this deployment. Email "
            "cra@skarp.app."
        )

    try:
        url = billing.create_portal_session(user)
    except Exception as e:  # noqa: BLE001
        log.exception("could not create a portal session for %s", actor_id)
        raise InvalidState(
            "Stripe could not open the billing portal just now. Try again "
            "shortly, or email cra@skarp.app."
        ) from e

    return {
        "ok": True,
        "current_plan": current.name,
        "subscription_status": user.subscription_status,
        "portal_url": url,
        "note": (
            "Change the card, read invoices, or cancel here. A cancellation "
            "keeps the plan until the period you have already paid for ends."
        ),
        "give_the_user_the_link": True,
    }


_dispatch.register_read("get_upgrade_link", get_upgrade_link)
_dispatch.register_read("manage_subscription", manage_subscription)
