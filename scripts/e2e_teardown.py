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

The tag is matched as a whole segment — `+e2efree-<tag>@` — rather than as a
substring. It was a substring, and `0810` is a substring of `0810j10`, so a
short tag quietly swept every longer run beginning with it. `--tag 08` would
have taken every August run, which is the mode the paragraph above says does
not exist.

`--legacy-untagged` reaches the two accounts created before tagging existed,
which no tag could match because every prefix ends in a hyphen. A separate flag
rather than a looser matcher: widening the prefixes would widen them forever.

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

# The address shapes `e2e_accounts.py` generates. A tag alone is not enough —
# an operator passing `--tag 2026` should not reach an account that merely has
# that string in it.
_PREFIXES = ("+e2efree-", "+e2epaid-", "+e2e-")

# Before the tagging convention existed there were two accounts with no tag at
# all: `<base>+e2efree@` and `<base>+e2epaid@`. No value of `--tag` can reach
# them, because every prefix above ends in a hyphen — so the very first run's
# data was unreachable by the script written to remove it. `--legacy-untagged`
# is their one door, deliberately a separate flag rather than a looser matcher:
# widening the prefixes would widen them for every future run too.
_UNTAGGED = ("+e2efree@", "+e2epaid@", "+e2e@")


def _matches(email: str, tag: str, untagged: bool) -> bool:
    """Whether this address belongs to the run being torn down.

    A *segment* match, not a substring one. `args.tag in email` was the test,
    and `0810` is a substring of `0810j10` — so a short tag silently swept
    every longer run that started with it, which is the "all e2e accounts" mode
    the module docstring says does not exist. `--tag 08` would have taken
    every August run.
    """
    email = email or ""
    if untagged:
        return any(email.endswith(u) or f"{u.rstrip('@')}@" in email for u in _UNTAGGED)
    return any(f"{p}{tag}@" in email for p in _PREFIXES)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", default="",
                    help="the tag e2e_accounts.py was run with")
    ap.add_argument("--legacy-untagged", action="store_true",
                    help="the two pre-tagging accounts instead of a tag")
    ap.add_argument("--apply", action="store_true",
                    help="actually delete; without it nothing changes")
    args = ap.parse_args()

    if bool(args.tag) == bool(args.legacy_untagged):
        return print(
            "  Pass exactly one of --tag <tag> or --legacy-untagged. Naming "
            "the run is what bounds the damage; there is no mode that removes "
            "every e2e account at once."
        ) or 2

    what = "the untagged pre-tagging accounts" if args.legacy_untagged else f"tag {args.tag!r}"

    with session_scope() as s:
        users = [
            u for u in s.execute(select(User)).scalars().all()
            if _matches(u.email, args.tag, args.legacy_untagged)
        ]
        if not users:
            print(f"  No e2e accounts match {what}. Nothing to do.")
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

        print(f"\n  {what}: {len(users)} account(s), {len(products)} product(s)\n")
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
