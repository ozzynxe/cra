"""put every pre-entitlement account on the founding plan

`users.tier` has existed since the schema was forked and nothing ever read it,
so every account sits at the column default of 'free'. Entitlements now give
that word consequences.

Anyone holding an account signed up before entitlements existed, under a
statement that they would be given notice before that changed. This is that
being kept — `founding` carries every feature, so nobody already here loses
anything they had.

The promise is what matters, not the number of rows it applies to: this
migration is also the record of why those accounts are on that plan.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Only accounts that never had a tier set deliberately. An operator who has
    # already run scripts/set_tier.py is not overwritten.
    op.execute("UPDATE users SET tier = 'founding' WHERE tier = 'free'")


def downgrade() -> None:
    op.execute("UPDATE users SET tier = 'free' WHERE tier = 'founding'")
