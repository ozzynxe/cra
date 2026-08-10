"""Prices, read from Stripe rather than written down here.

The pricing page needs amounts and this repo deliberately contains none: a
number in the source is wrong the first time somebody changes it in the Stripe
dashboard, and the version a prospect reads should be the version that will
actually be charged. So the page asks Stripe.

Two failure modes, handled differently, because they are not equally bad:

**Stripe is slow.** Prices change perhaps twice a year, so a cache with a long
TTL is not a compromise — it is the correct shape. Serve the cached copy.

**Stripe is unreachable and nothing is cached.** Then the honest page has no
prices on it. It says so and gives a contact address. Rendering a plan with a
blank or guessed price is worse than rendering one that admits it cannot say
right now: the first is a claim, the second is an outage.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from cra.server import billing

log = logging.getLogger(__name__)

# Long on purpose. See the module docstring — the failure this guards against
# is a slow page, and the thing being cached moves twice a year.
_TTL_SECONDS = 3600

# (plan, cadence) -> rendered price, plus when it was fetched.
_CACHE: dict[tuple[str, str], dict] = {}
_FETCHED_AT: dict[tuple[str, str], float] = {}


def _format(amount: Optional[int], currency: str) -> Optional[str]:
    """Stripe gives minor units. Zero-decimal currencies are not handled; there
    are none in the euro/sterling/dollar set this sells in, and guessing wrong
    would render ¥14900 as ¥149.00."""
    if amount is None:
        return None
    symbol = {"eur": "€", "usd": "$", "gbp": "£"}.get((currency or "").lower())
    major = amount / 100
    shown = f"{major:,.0f}" if major == int(major) else f"{major:,.2f}"
    return f"{symbol}{shown}" if symbol else f"{shown} {currency.upper()}"


def _field(obj, name, default=None):
    """Read a field from a Stripe object without assuming it is a dict.

    `stripe.Price.retrieve` returns a `StripeObject`, which supports `[...]` but
    **not** `.get()` — calling it raises `AttributeError: get` from the class's
    own `__getattr__`. A stub that returns a plain dict passes happily and the
    real call does not, which is how this shipped through a green suite and
    failed on the first request against Stripe.
    """
    try:
        value = obj[name]
    except (KeyError, TypeError, AttributeError):
        return default
    return default if value is None else value


def _fetch(plan: str, cadence: str) -> Optional[dict]:
    price_ref = billing.price_id(plan, cadence)
    if not price_ref:
        return None
    stripe = billing._stripe()
    price = stripe.Price.retrieve(price_ref)
    recurring = _field(price, "recurring", {})
    currency = _field(price, "currency", "")
    return {
        "amount": _format(_field(price, "unit_amount"), currency),
        "currency": currency.upper(),
        "interval": _field(recurring, "interval"),
    }


def price_for(plan: str, cadence: str, *, now: Optional[float] = None) -> Optional[dict]:
    """A rendered price, or None if we cannot currently say what it is."""
    key = (plan, cadence)
    now = time.time() if now is None else now

    cached = _CACHE.get(key)
    if cached is not None and now - _FETCHED_AT.get(key, 0) < _TTL_SECONDS:
        return cached

    try:
        fresh = _fetch(plan, cadence)
    except Exception:  # noqa: BLE001 — a marketing page must not 500 on Stripe
        log.exception("could not read the %s/%s price from Stripe", plan, cadence)
        # Stale beats absent: a price from an hour ago is almost certainly still
        # the price, and this is the copy, not the charge.
        return cached

    if fresh is not None:
        _CACHE[key] = fresh
        _FETCHED_AT[key] = now
    return fresh


def table() -> list[dict]:
    """Every sellable plan with what it lifts and what it costs."""
    from cra.server import entitlements

    limits = entitlements.plans()
    out = []
    # Ladder order, not alphabetical. `sorted()` put the dearest plan first and
    # the cheapest second, which asks a visitor to sort the cards themselves
    # before they can find the cheapest way in.
    # `entitlements._LADDER` already defines ascending order and is the thing
    # that would have to change if a tier were added between two others.
    ladder = list(entitlements.plans())
    order = {name: i for i, name in enumerate(ladder)}
    for plan, cadences in sorted(
        billing.sellable_plans().items(),
        key=lambda kv: (order.get(kv[0], len(ladder)), kv[0]),
    ):
        spec = limits[plan]
        prices = {c: price_for(plan, c) for c in cadences}
        out.append(
            {
                "plan": plan,
                "max_products": (
                    None if spec.max_products >= entitlements.UNLIMITED
                    else spec.max_products
                ),
                "max_members": (
                    None if spec.max_members >= entitlements.UNLIMITED
                    else spec.max_members
                ),
                "adds": sorted(spec.features - entitlements.FREE.features),
                "prices": {c: p for c, p in prices.items() if p},
                # True when Stripe could not be reached and nothing was cached.
                # The page renders the plan and says the price is unavailable
                # rather than inventing one.
                "price_unavailable": not any(prices.values()),
            }
        )
    return out


def _reset_cache() -> None:
    """Tests only."""
    _CACHE.clear()
    _FETCHED_AT.clear()
