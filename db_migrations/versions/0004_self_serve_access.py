"""self-serve access: email verification and single-use links

Access was issued by hand with scripts/dev_token.py, which put the operator in
the path of every signup. This is the schema behind removing them.

`users.email_verified_at` matters more here than in most products: every audit
row carries `accountable_user_id`, so an unproven address would let anyone put
a colleague's name against a compliance decision.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE users ADD COLUMN terms_accepted_at TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE users ADD COLUMN terms_version VARCHAR(32)")

    # Accounts that predate self-serve were created by hand, by someone who
    # already knew who they were. Backfilling verification from created_at
    # would be inventing evidence; leaving it NULL says accurately that nobody
    # proved anything.
    op.execute("""CREATE TABLE signup_links (
	id UUID NOT NULL,
	email CITEXT NOT NULL,
	secret_sha256 VARCHAR(64) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	used_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id)
)""")
    op.execute("CREATE INDEX signup_links_email ON signup_links (email, expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS signup_links")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS terms_version")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS terms_accepted_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at")
