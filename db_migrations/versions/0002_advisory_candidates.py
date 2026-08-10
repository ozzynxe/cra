"""advisory candidates

Detection of exploited vulnerabilities in shipped components. A candidate is a
feed match awaiting a human decision — not a vulnerability record, because
recording one starts an Article 14 clock.

Literal DDL rather than autogenerate, matching 0001: a migration has to produce
the same schema in a year's time regardless of how the models have moved.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE advisory_candidates (
	id UUID NOT NULL,
	product_id UUID NOT NULL,
	advisory_id VARCHAR(64) NOT NULL,
	cve_ids JSONB,
	summary TEXT DEFAULT '' NOT NULL,
	severity VARCHAR(32),
	component_name TEXT NOT NULL,
	component_version VARCHAR(64) NOT NULL,
	component_ecosystem VARCHAR(32) NOT NULL,
	component_purl TEXT,
	exploited BOOLEAN DEFAULT false NOT NULL,
	kev_cve_id VARCHAR(32),
	kev_date_added VARCHAR(16),
	first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	notified_at TIMESTAMP WITH TIME ZONE,
	status VARCHAR(16) DEFAULT 'open' NOT NULL,
	disposition VARCHAR(48),
	disposition_note TEXT,
	decided_by UUID,
	decided_at TIMESTAMP WITH TIME ZONE,
	vulnerability_id UUID,
	PRIMARY KEY (id),
	CONSTRAINT advisory_candidates_unique UNIQUE (product_id, advisory_id, component_name, component_version),
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE
)""")
    op.execute(
        "CREATE INDEX advisory_candidates_product "
        "ON advisory_candidates (product_id, status)"
    )
    # Partial: the sweeper only ever asks for exploited, open, not-yet-notified.
    op.execute(
        "CREATE INDEX advisory_candidates_unnotified "
        "ON advisory_candidates (exploited, notified_at) "
        "WHERE notified_at IS NULL AND status = 'open'"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS advisory_candidates")
