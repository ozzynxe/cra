"""tie evidence to a release, and record that a scan happened

Two additions serving Annex I's "as placed on the market", which the schema
could not previously express.

`evidence.applies_to_version` — a piece of evidence is a claim about a specific
build, not a timeless fact. Nullable, and NULL is meaningful: every row written
before this migration has no version, and `annex.evidence_currency` reads that
as *unversioned* rather than *stale*. A backfill would be the wrong move here
even though it is tempting — guessing which release an old test report
evidences would manufacture exactly the false confidence this column exists to
remove.

`advisory_scans` — that a scan ran, when, and whether the feeds answered. A
clean scan previously left no trace at all: only candidate rows are persisted,
so a product with nothing wrong produced silence indistinguishable from a
product nobody scanned. The Annex I Pt I(2)(a) release gate cannot stand on
that, because "no open candidates" is worthless without "and we looked".

`sources_ok` is the column that carries the weight: a scan that could not reach
OSV finds zero advisories, which is the same zero a genuinely clean product
produces and the opposite meaning.

There is no releases table. Releases live in `products.state` with the rest of
the compliance blob, so `store_backend.mutate` commits a release and its audit
row in one transaction.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence",
        sa.Column("applies_to_version", sa.Text(), nullable=True),
    )

    op.create_table(
        "advisory_scans",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "product_id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            sa.ForeignKey("products.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ran_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("sources_ok", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("kev_ok", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("osv_ok", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("epss_ok", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("components_checked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("exploited", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sbom_source_ref", sa.Text(), nullable=True),
    )
    op.create_index(
        "advisory_scans_product_ran", "advisory_scans", ["product_id", "ran_at"]
    )


def downgrade() -> None:
    op.drop_index("advisory_scans_product_ran", table_name="advisory_scans")
    op.drop_table("advisory_scans")
    op.drop_column("evidence", "applies_to_version")
