"""browser sessions for the read-only console

Everything else in this deployment carries its intent through a single
email-and-code exchange and remembers nothing between requests. That works for
one-shot acts — collect a token, authorize an app, start a checkout — and does
not work for somebody reading their compliance state, who clicks between pages.

A row rather than a signed cookie so a session can be *revoked*, not merely
expired. The two expiries are separate on purpose: `expires_at` slides forward
on use, `hard_expires_at` does not, so an active session cannot renew itself
into a permanent credential.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE web_sessions (
	id UUID NOT NULL,
	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	secret_sha256 VARCHAR(64) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	hard_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id)
)""")
    op.execute("CREATE INDEX web_sessions_user ON web_sessions (user_id, expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS web_sessions")
