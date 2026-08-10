"""record the artefacts that have to outlive this database

Article 13(13) requires the technical documentation and the EU declaration of
conformity to stay available to market surveillance authorities for ten years
after the product is placed on the market, or the support period if longer.

Until 2026-08-09 that obligation was carried by accident: a nightly full
`pg_dump` into S3 Object Lock at 3,660 days. It worked, and it meant keeping
*everything* immutably for a decade — every abandoned trial draft and every
advisory scan row — because a signed technical file had to be. The nightly dump
now expires after 90 days, which removes the accident
and leaves the obligation needing somewhere deliberate to live.

This table is that place. One row per artefact that genuinely must survive:
frozen technical files, declarations, simplified declarations, sign-offs, and
the releases that anchor the retention clock.

**The row commits in the same transaction as the artefact.** That is the point
of putting it in Postgres rather than writing straight to S3. S3 cannot be
atomic with the database, so the upload happens afterwards — but the intent
cannot be lost, and there is no path that produces a signed declaration with no
row here. `status` carries the rest: `pending` is a real, alertable state
meaning the artefact exists and its durable copy does not yet.

Same shape as `notification_log`, and the same reasoning — a durability failure
that leaves no trace is indistinguishable from success.

`(product_id, kind, content_sha256)` is unique, so re-exporting an unchanged
artefact is a no-op and a retry cannot duplicate an object.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "statutory_exports",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("product_id", sa.dialects.postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("storage_key", sa.Text, nullable=True),
        sa.Column("exported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_text", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "product_id", "kind", "content_sha256", name="uq_statutory_export"
        ),
    )
    # The reconciler's only query: what still needs uploading, oldest first.
    op.create_index(
        "ix_statutory_exports_pending", "statutory_exports", ["status", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_statutory_exports_pending", table_name="statutory_exports")
    op.drop_table("statutory_exports")
