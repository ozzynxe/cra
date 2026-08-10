#!/usr/bin/env python
"""Remove throwaway end-to-end accounts and everything they created.

    docker exec cra python scripts/e2e_teardown.py --tag 0810           # report
    docker exec cra python scripts/e2e_teardown.py --tag 0810 --apply

Pairs with `e2e_accounts.py`. That script creates accounts whose addresses carry
`+e2efree-<tag>` / `+e2epaid-<tag>`; this one takes a tag and removes exactly
those accounts, their products, and the rows hanging off both.

## What it will not do

**It refuses any account whose address does not carry an `e2e` marker**, and it
works from a tag rather than an id, so the blast radius is the accounts one run
created. There is no "all e2e accounts" mode: a run's worth of damage is
recoverable, and a sweep across every run is not.

## Two things worth understanding before running it

**`audit_events` and `attestations` carry no foreign key to `products`, and that
is deliberate.** The record of who decided what is meant to survive the product
being removed — see the comments on those models. Deleting them here overrides a
design decision on purpose, because this is test data and leaving an orphaned
audit trail describing products that no longer exist is worse than removing it.
Nothing else in this codebase should do that.

**The statutory archive is not reachable from here.** If the run froze a
technical file, drew up a declaration, signed off or recorded a release, objects
went into an S3 bucket under Object Lock and cannot be deleted by this or any
other database operation. This script reports what it finds and tells you to
finish the job with `prune_test_archive.py` from a workstation. Teardown is not
complete until that has run.
"""

from __future__ import annotations

import argparse
import os
import sys

if not os.environ.get("DATABASE_URL"):
    sys.exit("DATABASE_URL is not set. Inside the container it already is.")
os.environ.setdefault("CRA_STORE", "pg")

from sqlalchemy import delete, select, text  # noqa: E402

from cra.db import (  # noqa: E402
    Attestation,
    AuditEvent,
    Product,
    StatutoryExport,
    User,
    session_scope,
)

# What marks an address as disposable. A tag alone is not enough — an operator
# passing `--tag 2026` should not be able to reach an account that merely has
# that string in it.
MARKERS = ("+e2efree-", "+e2epaid-", "+e2e-")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", required=True,
                    help="the tag e2e_accounts.py was run with")
    ap.add_argument("--apply", action="store_true",
                    help="actually delete; without it nothing changes")
    args = ap.parse_args()

    with session_scope() as s:
        users = [
            u for u in s.execute(select(User)).scalars().all()
            if any(m in (u.email or "") for m in MARKERS) and args.tag in (u.email or "")
        ]
        if not users:
            print(f"  No e2e accounts carry the tag {args.tag!r}. Nothing to do.")
            return 0

        uids = [u.id for u in users]
        products = s.execute(
            select(Product).where(Product.owner_user_id.in_(uids))
        ).scalars().all()
        pids = [p.id for p in products]

        exports = (
            s.execute(
                select(StatutoryExport).where(StatutoryExport.product_id.in_(pids))
            ).scalars().all()
            if pids else []
        )
        audit_n = (
            len(s.execute(select(AuditEvent.id).where(AuditEvent.product_id.in_(pids))).all())
            if pids else 0
        )
        att_n = (
            len(s.execute(select(Attestation.id).where(Attestation.product_id.in_(pids))).all())
            if pids else 0
        )

        print(f"\n  tag {args.tag}: {len(users)} account(s), {len(products)} product(s)\n")
        for u in users:
            print(f"    {u.email}  tier={u.tier}")
        for p in products:
            print(f"      product {p.id[:8]}  {p.name!r}")
        print(f"\n    audit_events   {audit_n}")
        print(f"    attestations   {att_n}")
        print(f"    statutory_exports {len(exports)}"
              f"{'  ← see below' if exports else ''}")

        if not args.apply:
            print("\n  Report only. Re-run with --apply to remove these.\n")
            if exports:
                _archive_warning(pids)
            return 0

        # Everything explicitly, in dependency order, rather than trusting the
        # cascades.
        #
        # The first version of this leaned on `ondelete="CASCADE"` as declared on
        # the models and failed: `connector_tokens.user_id` says CASCADE in the
        # model and is `NO ACTION` in the database. `alembic check` does not
        # catch that — autogenerate does not compare delete rules — so the two
        # can disagree indefinitely. `notification_log.recipient_user_id` and
        # `product_invitations.invited_by` are the same.
        #
        # A teardown script depending on behaviour it cannot see is one that
        # fails halfway through on a live database. This one names every table
        # it touches, and the transaction means a surprise rolls the whole thing
        # back rather than leaving a half-deleted account.
        s.execute(delete(AuditEvent).where(AuditEvent.product_id.in_(pids)))
        s.execute(delete(Attestation).where(Attestation.product_id.in_(pids)))
        s.execute(delete(Product).where(Product.id.in_(pids)))

        for table, column in (
            ("connector_tokens", "user_id"),
            ("notification_log", "recipient_user_id"),
            ("product_invitations", "invited_by"),
            ("web_sessions", "user_id"),
        ):
            s.execute(
                text(f"delete from {table} where {column} = any(:uids)"),
                {"uids": uids},
            )
        s.execute(delete(User).where(User.id.in_(uids)))

    print(f"\n  Removed {len(users)} account(s) and {len(products)} product(s).")
    print("  Tokens, sessions, notifications and invitations were removed with")
    print("  them; evidence, vulnerabilities, incidents, obligations, candidates,")
    print("  scans and members went with the products.")
    if exports:
        _archive_warning(pids)
    return 0


def _archive_warning(pids: list[str]) -> None:
    print(
        "\n  ** The statutory archive is not covered by this. **\n"
        "  Objects for these products are in S3 under Object Lock and survive\n"
        "  everything above. Finish from a workstation with AWS credentials:\n\n"
        "    .venv/bin/python scripts/prune_test_archive.py \\\n"
        "      --bucket \"$CRA_STATUTORY_BUCKET\" --delete-products \\\n"
        f"      {' '.join(pids)}\n\n"
        "  Until that runs, the teardown is incomplete.\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
