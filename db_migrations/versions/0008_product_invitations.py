"""invite a colleague by email instead of by internal UUID

`add_member` took a `user_id` and nothing could look one up, so adding a
teammate required reading their id out of the database. It now takes an email;
this table is what happens when that address has no account yet.

Rows survive acceptance. Who was invited to a product, by whom, and when they
joined is part of the record of who could have touched a technical file.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE product_invitations (
	id UUID NOT NULL,
	product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
	email CITEXT NOT NULL,
	role VARCHAR(32) NOT NULL,
	invited_by UUID REFERENCES users(id),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	accepted_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT product_invitations_unique UNIQUE (product_id, email)
)""")
    op.execute(
        "CREATE INDEX product_invitations_email ON product_invitations (email, accepted_at)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS product_invitations")
