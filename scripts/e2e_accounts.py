#!/usr/bin/env python
"""Provision a fresh pair of end-to-end testing accounts and print their tokens.

    docker exec cra python scripts/e2e_accounts.py
    docker exec cra python scripts/e2e_accounts.py --base you@gmail.com --tag 0810

**Fresh accounts rather than a reset.** Resetting means deleting products on a
live deployment, which is a destructive script pointed at production — the thing
that once put nineteen test artefacts into a ten-year archive. Plus-addressing
costs nothing and sidesteps it: each run gets accounts nobody has touched, so
there is no product cap in the way, no state left by the last run, and nothing
to delete first.

Two accounts, because the free ceiling is half of what the journeys test:

  <base>+e2efree-<tag>   left on `free`, so the ceiling it hits is the real one
  <base>+e2epaid-<tag>   put on a paid plan, so the conformity half is reachable

The tokens are printed once. They are stored as bcrypt hashes and cannot be
recovered — re-run to mint new ones.

**This is the operator's side of the fence.** It needs a database, so it runs on
the host. The testing agent gets only the endpoint and a token: it must not have
database access, and it must not have the repository. See `BRIEF.md` in the
end-to-end repository for why that isolation is structural rather than a promise.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

if not os.environ.get("DATABASE_URL"):
    sys.exit("DATABASE_URL is not set. Inside the container it already is.")
os.environ.setdefault("CRA_STORE", "pg")

import uuid  # noqa: E402

from sqlalchemy import select  # noqa: E402

from cra.db import Product, User, session_scope  # noqa: E402
from cra.server import connector_tokens, entitlements  # noqa: E402

UTC = timezone.utc


def _plus(base: str, suffix: str) -> str:
    local, _, domain = base.partition("@")
    local = local.split("+")[0]
    return f"{local}+{suffix}@{domain}"


def _account(email: str, tier: str, until: datetime | None, label: str) -> dict:
    with session_scope() as s:
        user = s.execute(select(User).where(User.email == email)).scalar_one_or_none()
        created = user is None
        if created:
            user = User(id=str(uuid.uuid4()), email=email)
            s.add(user)
            s.flush()
        user.tier = tier
        user.tier_until = until
        uid = user.id
        owned = len(
            s.execute(select(Product.id).where(Product.owner_user_id == uid)).all()
        )

    token, row = connector_tokens.mint_token(user_id=uid, label=label)
    plan = entitlements.plan_for(uid)
    return {
        "email": email,
        "user_id": uid,
        "created": created,
        "tier": tier,
        "plan": plan.name,
        "max_products": plan.max_products,
        "owned": owned,
        "token": token,
        "token_id": row.id,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    # Required, not defaulted. This tree is published, and an operator's own
    # address baked in as a default is personal data in a public repository —
    # gratuitously, since the only caller passes it anyway and the usage line
    # above has always shown a placeholder.
    ap.add_argument("--base", required=True,
                    help="address to plus-address from, e.g. you@example.com")
    ap.add_argument("--tag", default=datetime.now(UTC).strftime("%m%d%H%M"),
                    help="suffix making this run's accounts distinct")
    ap.add_argument("--paid-plan", default="team",
                    help="plan for the paid account (default: team)")
    ap.add_argument("--months", type=int, default=18,
                    help="how long the paid plan runs for")
    args = ap.parse_args()

    if args.paid_plan not in entitlements.plans():
        return print(f"unknown plan {args.paid_plan!r}; "
                     f"one of {sorted(entitlements.plans())}") or 2

    until = datetime.now(UTC) + timedelta(days=30 * args.months)
    accounts = [
        _account(_plus(args.base, f"e2efree-{args.tag}"), "free", None,
                 f"e2e free {args.tag}"),
        _account(_plus(args.base, f"e2epaid-{args.tag}"), args.paid_plan, until,
                 f"e2e paid {args.tag}"),
    ]

    origin = os.environ.get("CRA_APP_ORIGIN", "https://cra.skarp.app")
    print(f"\ne2e accounts for tag {args.tag}\n")
    for a in accounts:
        print(f"  {a['email']}")
        print(f"    {'created' if a['created'] else 'existing'}, "
              f"plan {a['plan']} (max {a['max_products']} product"
              f"{'' if a['max_products'] == 1 else 's'}), owns {a['owned']}")
        # The one number worth reading before a run: a fresh account owns none,
        # and an account at its cap fails journey 1 on the first call with a
        # legitimate refusal that reads exactly like a finding.
        if a["owned"] >= a["max_products"]:
            print("    ⚠ at its product cap — journey 1 will be refused. "
                  "Use a different --tag.")
        print(f"    token: {a['token']}")
        print()

    print(f"  MCP endpoint: {origin}/mcp/me/mcp")
    print(
        "\n  Hand the runner the endpoint and the tokens, nothing else. It must\n"
        "  not have this repository or a database — that isolation is what the\n"
        "  run measures, and it cannot be recovered by promising to ignore them.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
