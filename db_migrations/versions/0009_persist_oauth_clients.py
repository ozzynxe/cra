"""persist dynamically registered OAuth clients

The registry was a module-level dict, so every container restart forgot every
client that had ever connected — and a deploy is a restart. Connectors broke on
each ship, quietly, because an unknown client falls through to the host
allowlist rather than failing loudly.

`registration_access_token_hash` backs RFC 7592 deletion. A `client_id` is not
a secret; it travels in every authorize URL. Without a separate bearer, knowing
one would be enough to delete somebody else's registration.

Revision ID: 0009
Revises: 0008
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("client_id", sa.String(length=128), primary_key=True),
        sa.Column("client_name", sa.Text(), nullable=True),
        sa.Column(
            "redirect_uris",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("registration_access_token_hash", sa.String(length=72), nullable=True),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Retention sweeps evict the oldest first; the cap check counts rows.
    op.create_index("oauth_clients_issued", "oauth_clients", ["issued_at"])


def downgrade() -> None:
    op.drop_index("oauth_clients_issued", table_name="oauth_clients")
    op.drop_table("oauth_clients")
