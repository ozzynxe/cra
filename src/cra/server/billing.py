"""Stripe checkout, customer portal, and the webhook that moves `users.tier`.

Carried over from Coauthor and **no longer verbatim**: that version sold one
`pro` tier, and this one sells a ladder (`server/entitlements.py`). Cherry-pick
across the two with care — the divergence is the plan name, which is now read
from Stripe metadata rather than hardcoded.

There is no SPA and no billing page to click a button on, so the entry point is
the agent:

  get_upgrade_link(plan="team")   → a hosted Stripe Checkout URL
                                          │
              user opens it and pays in a browser
                                          │
       Stripe POSTs /api/stripe/webhook (signature-verified)
                                          │
                       users.tier = the plan they bought

**The webhook is what grants access, not the redirect.** A customer who closes
the tab after paying has still paid; `/billing?checkout=success` is a courtesy
page and nothing more. Anything that reads the tier from the redirect would
grant on a URL a browser can be pointed at by hand.

Three events are handled idempotently — `processed_stripe_events` takes the
event id first, so a retry after a 5xx cannot re-run side effects. Everything
else 200-noops, because arguing with a webhook sender is a losing game:

  - checkout.session.completed         → first purchase
  - customer.subscription.updated      → status change, upgrade, downgrade
  - customer.subscription.deleted      → cancellation

`tier_until` is the paid-through date, and `entitlements.plan_for` derives a
lapsed plan from it rather than depending on a sweeper having run. So a
cancellation keeps the plan until the period ends and then simply stops being
true. `expire_stale_tier` persists that flip when something happens to call it;
nothing depends on it having been called.

**Money is not the trust boundary.** A plan name coming back from Stripe is
validated against the ladder before it becomes an access decision, and a
purchase whose plan cannot be identified grants nothing and logs loudly —
guessing would either short-change someone who paid more or hand out something
nobody bought.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cra.db import ProcessedStripeEvent, User, session_scope
from cra.server import entitlements

log = logging.getLogger(__name__)


# ---- env / config -----------------------------------------------------------


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def stripe_secret_key() -> str:
    """Server-side Stripe API key. `sk_test_...` or `sk_live_...`. Required for
    every API call we make to Stripe. Returns "" if unset (caller should 503)."""
    return _env("STRIPE_SECRET_KEY")


def webhook_signing_secret() -> str:
    """Whsec from the webhook endpoint config. Required to verify signatures."""
    return _env("STRIPE_WEBHOOK_SECRET")


CADENCES = ("monthly", "annual")


def price_id(plan: str, cadence: str) -> str:
    """`STRIPE_PRICE_TEAM_MONTHLY` and friends.

    One env var per (plan, cadence) rather than a price catalogue in code:
    prices live in Stripe, which is the only place they can be true. A plan
    with no price configured is simply not for sale — `sellable_plans()` reads
    that off the environment rather than off a list somebody has to remember to
    update.
    """
    return _env(f"STRIPE_PRICE_{plan.upper()}_{cadence.upper()}")


def sellable_plans() -> dict[str, list[str]]:
    """Plan -> the cadences it can actually be bought on, right now.

    Derived from configured prices. `free` is never sellable; `founding` and
    `internal` are grants, not products, so they are not either.
    """
    out: dict[str, list[str]] = {}
    for name in entitlements.plans():
        if name in entitlements.GRANTS:
            continue
        cadences = [c for c in CADENCES if price_id(name, c)]
        if cadences:
            out[name] = cadences
    return out


def app_origin() -> str:
    """Where Stripe sends the customer back to. No default: an origin guessed
    wrong sends a paying customer to somebody else's site."""
    return _env("CRA_APP_ORIGIN")


def is_billing_configured() -> bool:
    """True iff Stripe can be called and at least one plan has a price.

    Checked before every entry point, because the alternative is a customer
    meeting a Stripe SDK stack trace at the moment they were trying to pay.
    """
    return bool(
        stripe_secret_key()
        and webhook_signing_secret()
        and app_origin()
        and sellable_plans()
    )


# ---- helpers ----------------------------------------------------------------


def _stripe():
    """Lazy import — keeps the module importable without the SDK installed
    (e.g. in unit tests that don't touch billing). Sets api_key per call so
    env changes are picked up without a process restart."""
    import stripe as _s

    _s.api_key = stripe_secret_key()
    return _s


def _to_aware_utc(ts: Optional[int]) -> Optional[datetime]:
    """Stripe gives Unix epoch seconds; we store TIMESTAMPTZ in Postgres."""
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc)


# ---- customer lookup / creation --------------------------------------------


def get_or_create_customer(user: User) -> str:
    """Return the Stripe customer ID for this user, creating one if needed.

    Idempotent: re-uses the cached `users.stripe_customer_id` if present.
    Persists newly-minted IDs back to the DB so subsequent calls are cheap.
    """
    if user.stripe_customer_id:
        return user.stripe_customer_id

    s = _stripe()
    customer = s.Customer.create(
        email=user.email,
        name=user.display_name or None,
        metadata={"coauthor_user_id": user.id},
    )
    customer_id: str = customer["id"]

    # Persist the customer_id immediately so a crash/timeout between this call
    # and the eventual webhook doesn't strand us.
    with session_scope() as sess:
        u = sess.get(User, user.id)
        if u is not None and not u.stripe_customer_id:
            u.stripe_customer_id = customer_id
    return customer_id


# ---- checkout session -------------------------------------------------------


@dataclass
class CheckoutResult:
    url: str
    session_id: str


def create_checkout_session(user: User, *, plan: str, cadence: str = "monthly") -> CheckoutResult:
    """Mint a Stripe Checkout Session for an account moving onto `plan`.

    Returns the hosted Checkout URL. The agent hands it to the user, they pay
    in a browser, and Stripe separately POSTs the webhook this module uses to
    move the tier. The redirect back is only a courtesy page — **the webhook is
    what grants anything**, because a customer who closes the tab before the
    redirect has still paid.
    """
    available = sellable_plans()
    if plan not in available:
        raise ValueError(
            f"{plan!r} is not for sale here; try one of {sorted(available)}"
        )
    if cadence not in available[plan]:
        raise ValueError(
            f"{plan!r} is not sold {cadence}; try {available[plan]}"
        )

    customer_id = get_or_create_customer(user)
    s = _stripe()

    origin = app_origin().rstrip("/")
    session = s.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": price_id(plan, cadence), "quantity": 1}],
        # client_reference_id propagates into the webhook so we can match the
        # event back to our user row even if the customer object is stale.
        client_reference_id=user.id,
        # `cra_plan` is what the webhook reads to decide which tier to grant.
        # It goes on the subscription as well as the session because renewals
        # and status changes arrive as subscription events, long after the
        # session is gone.
        metadata={"coauthor_user_id": user.id, "cra_plan": plan, "cadence": cadence},
        subscription_data={
            "metadata": {
                "coauthor_user_id": user.id, "cra_plan": plan, "cadence": cadence
            },
        },
        success_url=f"{origin}/billing?checkout=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{origin}/billing?checkout=cancel",
        # Stripe Tax handles VAT/sales tax automatically when enabled in the
        # Dashboard. Setting `automatic_tax.enabled` is harmless if Tax is off.
        automatic_tax={"enabled": True},
        # Customers can update their billing address at checkout (needed for tax).
        billing_address_collection="auto",
        # `automatic_tax` requires an address on the Customer. Since we mint
        # the Customer up-front (before we know the user's address), tell
        # Stripe to write the address (and name) collected at Checkout back
        # to the Customer record. Without this, the second checkout attempt
        # for the same user errors with: "Automatic tax calculation in
        # Checkout requires a valid address on the Customer."
        customer_update={"address": "auto", "name": "auto"},
        # Allow promotion codes if any exist.
        allow_promotion_codes=True,
    )
    return CheckoutResult(url=session["url"], session_id=session["id"])


# ---- customer portal --------------------------------------------------------


def create_portal_session(user: User) -> str:
    """Mint a Stripe Customer Portal session URL.

    Pro-only flow — free users have no Stripe customer to manage. Caller
    should 400 before calling if `user.stripe_customer_id is None`.
    """
    if not user.stripe_customer_id:
        raise RuntimeError("user has no stripe_customer_id")

    s = _stripe()
    origin = app_origin().rstrip("/")
    portal = s.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=f"{origin}/billing",
    )
    return portal["url"]


# ---- webhook ----------------------------------------------------------------


class WebhookSignatureError(Exception):
    """Signature verification failed. Caller returns 400."""


def verify_webhook(payload: bytes, signature: str) -> dict:
    """Construct + verify a Stripe Event from the raw request body.

    `payload` is the raw bytes (not parsed JSON) — Stripe signs the literal
    body. `signature` is the value of the `Stripe-Signature` header.

    Returns a **plain dict** (not a `stripe.Event` / `StripeObject`). The SDK's
    construct_event returns a StripeObject whose `__getattr__` intercepts
    `.get()` attribute lookup and raises `AttributeError` instead of returning
    the dict-method — which crashed every handler downstream. Verifying the
    signature with the SDK and then re-parsing the raw JSON ourselves gives
    us a clean dict the whole way down.
    """
    import json as _json

    s = _stripe()
    secret = webhook_signing_secret()
    if not secret:
        raise WebhookSignatureError("STRIPE_WEBHOOK_SECRET is not configured")
    try:
        s.Webhook.construct_event(payload, signature, secret)
    except Exception as e:  # noqa: BLE001 — Stripe raises a typed error subtype
        raise WebhookSignatureError(str(e)) from e
    try:
        return _json.loads(payload.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        # Signature was valid but the payload didn't parse — Stripe's payload
        # is always JSON, so this would only happen on truly mangled bytes.
        raise WebhookSignatureError(f"signature ok but payload is not JSON: {e}") from e


def _mark_event_processed(event_id: str) -> bool:
    """Insert event_id into processed_stripe_events. Returns True on first
    sight, False on duplicate (caller should 200-noop in the duplicate case)."""
    try:
        with session_scope() as sess:
            sess.add(ProcessedStripeEvent(event_id=event_id))
        return True
    except IntegrityError:
        return False


def handle_event(event: dict) -> dict:
    """Process a verified Stripe webhook event. Idempotent — duplicate event
    IDs short-circuit. Unknown event types are 200-noop'd."""
    event_id = event.get("id")
    event_type = event.get("type", "")
    if not event_id:
        return {"ok": True, "ignored": "no event id"}

    if not _mark_event_processed(event_id):
        return {"ok": True, "duplicate": True, "event_id": event_id}

    log.info("stripe webhook event=%s type=%s", event_id, event_type)
    obj = event.get("data", {}).get("object", {}) or {}

    if event_type == "checkout.session.completed":
        return _handle_checkout_completed(obj)
    if event_type == "customer.subscription.updated":
        return _handle_subscription_updated(obj)
    if event_type == "customer.subscription.deleted":
        return _handle_subscription_deleted(obj)

    return {"ok": True, "ignored": event_type}


# ---- event handlers ---------------------------------------------------------


def _as_user_id(raw) -> Optional[str]:
    """Accept a value from Stripe only if it could be one of our user ids.

    `users.id` is a UUID column, so a lookup with anything else raises a
    psycopg DataError — which escapes as a 500, which Stripe reads as "try
    again", which it then does for three days over a payload that can never
    succeed. Found by a test that put a non-UUID in the metadata.
    """
    if not raw or not isinstance(raw, str):
        return None
    try:
        uuid.UUID(raw)
    except ValueError:
        log.warning("stripe payload carried a user id we cannot use: %r", raw)
        return None
    return raw


def _user_id_from_session_or_subscription(obj: dict) -> Optional[str]:
    """Fish our user.id out of the Stripe object.

    Order of preference:
      1. checkout.Session.client_reference_id (we set it on creation)
      2. metadata.coauthor_user_id (we set it on both session + subscription)
      3. fallback: lookup by stripe_customer_id
    """
    user_id = _as_user_id(obj.get("client_reference_id"))
    if user_id:
        return user_id
    md = obj.get("metadata") or {}
    user_id = _as_user_id(md.get("coauthor_user_id"))
    if user_id:
        return user_id
    customer_id = obj.get("customer")
    if customer_id:
        with session_scope() as sess:
            u = sess.scalar(select(User).where(User.stripe_customer_id == customer_id))
            return u.id if u else None
    return None


def _plan_from(obj: dict) -> Optional[str]:
    """Which plan this Stripe object was bought under.

    Read from the metadata we stamped at checkout, and validated against the
    ladder before it is trusted: this value comes back from an external system
    and is about to become an access-control decision. A plan name we do not
    recognise grants nothing rather than something arbitrary.
    """
    name = ((obj.get("metadata") or {}).get("cra_plan") or "").strip().lower()
    if not name:
        return None
    if name not in entitlements.plans():
        log.error("stripe returned unknown plan %r; refusing to grant it", name)
        return None
    return name


def _period_end_from_subscription_dict(sub: dict) -> Optional[datetime]:
    """Read `current_period_end` from a (plain dict) subscription payload.

    Stripe's recent API moved this field from the subscription top level to
    each subscription item — `subscription.items.data[*].current_period_end`
    — to support items with different billing cycles. Older payloads still
    carry a top-level value, so we check that first and fall back to the
    first item. We assume a single item per subscription (true for our
    Pro-monthly / Pro-annual product); if we ever ship multi-item plans
    this will need a max() or per-item-aware caller.
    """
    top = sub.get("current_period_end")
    if top is not None:
        return _to_aware_utc(top)
    items = (sub.get("items") or {}).get("data") or []
    if items:
        return _to_aware_utc(items[0].get("current_period_end"))
    return None


def _resolve_period_end(obj: dict) -> Optional[datetime]:
    """Pull `current_period_end` off whatever shape Stripe sent.

    For `checkout.session.completed` the session itself doesn't have it — we
    have to fetch the subscription. For `customer.subscription.*` it's right
    on the object (or its items).

    Note: `_stripe().Subscription.retrieve()` returns a `StripeObject`, whose
    `.get()` attribute is intercepted by `__getattr__` (raises AttributeError
    instead of returning the dict-method). Convert via `.to_dict()` so the
    rest of this module can keep using normal dict semantics.
    """
    direct = _period_end_from_subscription_dict(obj)
    if direct is not None:
        return direct
    sub_id = obj.get("subscription")
    if sub_id:
        try:
            sub = _stripe().Subscription.retrieve(sub_id)
            sub_dict = sub.to_dict() if hasattr(sub, "to_dict") else dict(sub)
            return _period_end_from_subscription_dict(sub_dict)
        except Exception:  # noqa: BLE001
            log.exception("could not fetch subscription %s for period_end", sub_id)
    return None


def _handle_checkout_completed(session: dict) -> dict:
    user_id = _user_id_from_session_or_subscription(session)
    if not user_id:
        log.warning("checkout.session.completed without user_id: %s", session.get("id"))
        return {"ok": False, "error": "could not match session to user"}

    customer_id = session.get("customer")
    period_end = _resolve_period_end(session)

    with session_scope() as sess:
        u = sess.get(User, user_id)
        if u is None:
            return {"ok": False, "error": f"user {user_id} not found"}
        plan = _plan_from(session)
        if plan is None:
            # Money changed hands and we cannot tell what for. Do not guess a
            # plan: leave the tier alone, shout, and let a person sort it out.
            # Silently granting the cheapest thing would be a support ticket
            # from someone who paid for more.
            log.error(
                "checkout completed for user %s with no usable plan metadata; "
                "tier unchanged", user_id,
            )
            return {"ok": False, "error": "no plan metadata on session"}
        u.tier = plan
        u.subscription_status = "active"
        if customer_id and not u.stripe_customer_id:
            u.stripe_customer_id = customer_id
        if period_end:
            u.tier_until = period_end
        email = u.email
    _confirm_by_email(email, plan)
    return {"ok": True, "user_id": user_id, "tier": plan}


def _confirm_by_email(email: str, plan: str) -> None:
    """Tell the customer it worked, and where their subscription lives.

    Until this existed, paying produced nothing from us at all — Stripe's own
    receipt, and silence. Someone who has just paid then has to go looking for
    the billing page, which is the predictable result of the only link being one
    muted line at the bottom of the pricing page.

    An inbox is the right place for this. It survives the tab being closed, it
    is searchable months later when the card expires, and it is where people
    already look for "where do I manage this thing I pay for".

    Never raises. A mail problem must not fail the webhook: Stripe would retry,
    the event is already marked processed, and the plan is already granted. The
    grant is what matters; this is a courtesy.
    """
    origin = (app_origin() or "").rstrip("/")
    billing_url = f"{origin}/billing" if origin else "the billing page"
    try:
        from cra.server import mailer

        mailer.send(
            to_email=email,
            subject=f"Your Skarp CRA {plan} plan is active",
            plain=(
                f"Your payment went through and the {plan} plan is active on "
                f"this address.\n\n"
                f"Manage it at: {billing_url}\n"
                "Card, invoices and cancellation all live there. You will be "
                "asked for your email and a six-digit code each time — there is "
                "no password to lose. Cancelling keeps the plan until the end "
                "of the period you have already paid for.\n\n"
                "In your agent, cra_overview() will now report the new plan.\n\n"
                "Questions: cra@skarp.app"
            ),
            html=(
                f"<p>Your payment went through and the <b>{plan}</b> plan is "
                "active on this address.</p>"
                f"<p><a href=\"{billing_url}\">Manage your subscription</a> — "
                "card, invoices and cancellation all live there. You will be "
                "asked for your email and a six-digit code each time; there is "
                "no password to lose.</p>"
                "<p>Cancelling keeps the plan until the end of the period you "
                "have already paid for.</p>"
                "<p>In your agent, <code>cra_overview()</code> will now report "
                "the new plan.</p>"
                "<p>Questions: <a href=\"mailto:cra@skarp.app\">cra@skarp.app</a></p>"
            ),
            hint="Set it, or subscribers get no confirmation of what they bought.",
        )
    except Exception:  # noqa: BLE001 — the grant already happened; this is extra
        log.exception("could not send the subscription confirmation to %s", email)


def _handle_subscription_updated(sub: dict) -> dict:
    user_id = _user_id_from_session_or_subscription(sub)
    if not user_id:
        log.warning("subscription.updated without user_id: %s", sub.get("id"))
        return {"ok": False, "error": "could not match subscription to user"}

    status = sub.get("status")  # active / past_due / canceled / trialing / ...
    period_end = _period_end_from_subscription_dict(sub)
    cancel_at_period_end = bool(sub.get("cancel_at_period_end"))

    with session_scope() as sess:
        u = sess.get(User, user_id)
        if u is None:
            return {"ok": False, "error": f"user {user_id} not found"}
        # Mirror Stripe's status verbatim (handy for the SPA UI).
        if cancel_at_period_end and status == "active":
            # Special case: user clicked "cancel at period end" in the portal —
            # subscription is technically still active until period_end, but we
            # surface it as "canceled" in the UI so they see the end date.
            u.subscription_status = "canceled"
        elif status:
            u.subscription_status = status
        # On any non-active state Stripe still gives us the period_end where
        # the user has access until — keep tier='pro' through it. (We don't
        # downgrade tier here; the lazy expiry in auth.py / quota.py handles
        # that.)
        if period_end:
            u.tier_until = period_end
        # If status went healthy and the tier had lapsed, put them back on the
        # plan the subscription is actually for — which also covers an upgrade
        # or downgrade made in the customer portal, where the only signal is
        # this event.
        plan = _plan_from(sub)
        if status == "active" and plan is not None and u.tier != plan:
            u.tier = plan
    return {"ok": True, "user_id": user_id, "subscription_status": status}


def _handle_subscription_deleted(sub: dict) -> dict:
    user_id = _user_id_from_session_or_subscription(sub)
    if not user_id:
        log.warning("subscription.deleted without user_id: %s", sub.get("id"))
        return {"ok": False, "error": "could not match subscription to user"}

    period_end = _period_end_from_subscription_dict(sub)

    with session_scope() as sess:
        u = sess.get(User, user_id)
        if u is None:
            return {"ok": False, "error": f"user {user_id} not found"}
        u.subscription_status = "canceled"
        # Keep tier='pro' until tier_until passes (paid-period grace). The lazy
        # expiry in auth.py / quota.py will treat them as free after that.
        if period_end and (u.tier_until is None or u.tier_until < period_end):
            u.tier_until = period_end
    return {"ok": True, "user_id": user_id, "tier_until": period_end.isoformat() if period_end else None}


# ---- lazy tier expiry (called from auth + quota) ----------------------------


def expire_stale_tier(user_id: str) -> Optional[str]:
    """If a Pro user's tier_until has passed, persistently flip them back to
    free. Returns the new tier on a flip, None if no change. Runs inside its
    own session_scope; safe to call from the request hot path."""
    now = datetime.now(timezone.utc)
    with session_scope() as sess:
        u = sess.get(User, user_id)
        if u is None:
            return None
        lapsed = (
            u.tier not in entitlements.GRANTS
            and u.tier_until is not None
            and u.tier_until < now
        )
        if lapsed:
            u.tier = "free"
            return "free"
    return None
