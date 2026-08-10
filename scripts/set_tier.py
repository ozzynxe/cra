#!/usr/bin/env python3
"""Put an account on a plan, by hand.

    scripts/set_tier.py alice@example.com team --until 2027-01-31
    scripts/set_tier.py alice@example.com free
    scripts/set_tier.py --list

`--until` is the paid-through date. `entitlements.plan_for` treats a lapsed
paid tier as free without anything having to run, so this is the whole of
subscription expiry: set the date when they pay, and it lapses on its own.
Leaving it unset means indefinite, which is right for the plans that have no
paid-through date and wrong for the ones that do.

Prints the plan's limits after setting them, because the point of running this
is usually to find out what somebody just got.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import select  # noqa: E402

from cra.db import User, session_scope  # noqa: E402
from cra.server import entitlements  # noqa: E402


def _parse_until(raw: str) -> datetime:
    try:
        return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise SystemExit(f"--until wants YYYY-MM-DD, not {raw!r}") from None


def main() -> int:
    table = entitlements.plans()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("email", nargs="?", help="account to change")
    ap.add_argument("plan", nargs="?", choices=sorted(table), help="plan to set")
    ap.add_argument("--until", help="paid through YYYY-MM-DD (omit for indefinite)")
    ap.add_argument("--list", action="store_true", help="show the ladder and exit")
    args = ap.parse_args()

    if args.list or not (args.email and args.plan):
        print(f"{'plan':<12}{'products':>10}{'members':>10}  includes")
        for name, plan in table.items():
            products = "∞" if plan.max_products >= entitlements.UNLIMITED else plan.max_products
            members = "∞" if plan.max_members >= entitlements.UNLIMITED else plan.max_members
            includes = ", ".join(sorted(plan.features)) or "no features"
            print(f"{name:<12}{products:>10}{members:>10}  {includes}")
        print(
            f"\nenforcement: {'ON' if entitlements.enforced() else 'OFF (shadow mode)'}"
        )
        return 0 if args.list else 2

    until = _parse_until(args.until) if args.until else None
    if args.plan not in ("free", "founding", "internal") and until is None:
        # Not fatal — an indefinite grant is a real thing — but silence here is
        # how a plan ends up never lapsing.
        print(f"note: no --until, so '{args.plan}' will not expire on its own.")

    with session_scope() as db:
        user = db.execute(
            select(User).where(User.email == args.email)
        ).scalar_one_or_none()
        if user is None:
            raise SystemExit(f"no account for {args.email}")
        was = user.tier
        user.tier = args.plan
        user.tier_until = until
        user_id = user.id

    plan = entitlements.plan_for(user_id)
    print(f"{args.email}: {was} → {plan.name}" + (f" until {until.date()}" if until else ""))
    print(f"  products: {plan.max_products}, members: {plan.max_members}")
    print(f"  includes: {', '.join(sorted(plan.features)) or 'no features'}")
    if not entitlements.enforced():
        print("\nCRA_ENTITLEMENTS_ENFORCED is off — nothing is being gated yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
