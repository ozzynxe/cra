"""initial CRA schema

Single squashed migration. Coauthor's eleven migrations were not carried
forward: they encode the history of a document-collaboration product this
database has never been, and replaying them to arrive at a schema they never
described would be archaeology rather than provenance.

The DDL below was generated from `cra.db.models` and is deliberately literal
rather than a `metadata.create_all()` call, so this migration stays immutable —
running it on a fresh database a year from now must produce the schema as it is
today, not as the models happen to look then.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `users.email` is CITEXT so lookups are case-insensitive without a
    # functional index.
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    # ---- attestations ----
    op.execute("""CREATE TABLE attestations (
	id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	subject_type VARCHAR(32) NOT NULL, 
	subject_id TEXT, 
	subject_version_hash VARCHAR(64) NOT NULL, 
	signer_user_id UUID NOT NULL, 
	signer_name TEXT, 
	signer_role VARCHAR(64), 
	statement TEXT NOT NULL, 
	signed_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
)""")
    op.execute("""CREATE INDEX attestations_product ON attestations (product_id)""")
    # ---- audit_events ----
    op.execute("""CREATE TABLE audit_events (
	id BIGSERIAL NOT NULL, 
	product_id UUID NOT NULL, 
	subject_type VARCHAR(32) NOT NULL, 
	subject_id TEXT, 
	op VARCHAR(48) NOT NULL, 
	accountable_user_id UUID, 
	actor_kind VARCHAR(16) DEFAULT 'human' NOT NULL, 
	actor_model VARCHAR(64), 
	before_hash VARCHAR(64), 
	after_hash VARCHAR(64), 
	rationale TEXT DEFAULT '' NOT NULL, 
	payload JSONB, 
	ts TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
)""")
    op.execute("""CREATE INDEX audit_events_product_ts ON audit_events (product_id, ts)""")
    # ---- processed_stripe_events ----
    op.execute("""CREATE TABLE processed_stripe_events (
	event_id VARCHAR(255) NOT NULL, 
	received_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (event_id)
)""")
    # ---- users ----
    op.execute("""CREATE TABLE users (
	id UUID NOT NULL, 
	email CITEXT NOT NULL, 
	display_name TEXT, 
	last_seen_at TIMESTAMP WITH TIME ZONE, 
	tier VARCHAR(32) NOT NULL, 
	stripe_customer_id VARCHAR(64), 
	subscription_status VARCHAR(32), 
	tier_until TIMESTAMP WITH TIME ZONE, 
	model_credits_balance INTEGER DEFAULT '0' NOT NULL, 
	model_credits_period_start TIMESTAMP WITH TIME ZONE, 
	model_credits_trial_granted_at TIMESTAMP WITH TIME ZONE, 
	notifications_enabled BOOLEAN DEFAULT 'true' NOT NULL, 
	last_notified_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (email)
)""")
    # ---- products ----
    op.execute("""CREATE TABLE products (
	id UUID NOT NULL, 
	slug VARCHAR(64) NOT NULL, 
	name TEXT NOT NULL, 
	owner_user_id UUID NOT NULL, 
	economic_operator_role VARCHAR(32) DEFAULT 'manufacturer' NOT NULL, 
	product_class VARCHAR(32) DEFAULT 'unknown' NOT NULL, 
	lifecycle VARCHAR(32) DEFAULT 'in_development' NOT NULL, 
	support_period_end TIMESTAMP WITH TIME ZONE, 
	state JSONB NOT NULL, 
	state_version INTEGER DEFAULT '0' NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	archived_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (slug), 
	FOREIGN KEY(owner_user_id) REFERENCES users (id)
)""")
    op.execute("""CREATE INDEX products_owner ON products (owner_user_id)""")
    # ---- connector_tokens ----
    op.execute("""CREATE TABLE connector_tokens (
	id UUID NOT NULL, 
	user_id UUID NOT NULL, 
	product_id UUID, 
	label TEXT, 
	token_hash TEXT NOT NULL, 
	prefix VARCHAR(16) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	last_used_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT connector_tokens_prefix_unique UNIQUE (prefix), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE
)""")
    op.execute("""CREATE INDEX connector_tokens_prefix ON connector_tokens (prefix)""")
    op.execute("""CREATE INDEX connector_tokens_user ON connector_tokens (user_id)""")
    # ---- evidence ----
    op.execute("""CREATE TABLE evidence (
	id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	subject_ref TEXT NOT NULL, 
	title TEXT NOT NULL, 
	kind VARCHAR(32) DEFAULT 'document' NOT NULL, 
	storage_key TEXT, 
	inline_body TEXT, 
	content_type VARCHAR(128), 
	size_bytes INTEGER, 
	sha256 VARCHAR(64), 
	source_ref TEXT, 
	collected_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	added_by_user_id UUID, 
	actor_kind VARCHAR(16) DEFAULT 'human' NOT NULL, 
	superseded_by UUID, 
	deleted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE, 
	FOREIGN KEY(added_by_user_id) REFERENCES users (id) ON DELETE SET NULL
)""")
    op.execute("""CREATE INDEX evidence_product_subject ON evidence (product_id, subject_ref)""")
    # ---- model_review_logs ----
    op.execute("""CREATE TABLE model_review_logs (
	id BIGSERIAL NOT NULL, 
	user_id UUID NOT NULL, 
	product_id UUID, 
	subject_ref TEXT, 
	model_id VARCHAR(64) NOT NULL, 
	model_tier VARCHAR(16) NOT NULL, 
	tokens_in INTEGER NOT NULL, 
	tokens_out INTEGER NOT NULL, 
	credit_cost INTEGER NOT NULL, 
	success BOOLEAN NOT NULL, 
	error_code VARCHAR(64), 
	ts TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE SET NULL
)""")
    op.execute("""CREATE INDEX model_review_logs_user_ts ON model_review_logs (user_id, ts)""")
    # ---- product_members ----
    op.execute("""CREATE TABLE product_members (
	id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	user_id UUID NOT NULL, 
	role VARCHAR(32) NOT NULL, 
	added_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT product_members_unique UNIQUE (product_id, user_id), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE, 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)""")
    op.execute("""CREATE INDEX product_members_user ON product_members (user_id)""")
    # ---- tool_call_logs ----
    op.execute("""CREATE TABLE tool_call_logs (
	id BIGSERIAL NOT NULL, 
	user_id UUID NOT NULL, 
	product_id UUID, 
	tool_name VARCHAR(64) NOT NULL, 
	success BOOLEAN NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE SET NULL
)""")
    op.execute("""CREATE INDEX tool_call_logs_user_ts ON tool_call_logs (user_id, ts)""")
    # ---- vulnerabilities ----
    op.execute("""CREATE TABLE vulnerabilities (
	id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	identifier VARCHAR(64), 
	affected_component TEXT, 
	summary TEXT NOT NULL, 
	discovered_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	source VARCHAR(64), 
	cvss_score VARCHAR(8), 
	cvss_vector TEXT, 
	actively_exploited BOOLEAN DEFAULT 'false' NOT NULL, 
	exploitation_determined_at TIMESTAMP WITH TIME ZONE, 
	status VARCHAR(32) DEFAULT 'open' NOT NULL, 
	remediation_ref TEXT, 
	disclosed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE
)""")
    op.execute("""CREATE INDEX vulnerabilities_product ON vulnerabilities (product_id, status)""")
    # ---- incidents ----
    op.execute("""CREATE TABLE incidents (
	id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	kind VARCHAR(32) NOT NULL, 
	vulnerability_id UUID, 
	became_aware_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	corrective_measure_available_at TIMESTAMP WITH TIME ZONE, 
	severity VARCHAR(32), 
	description TEXT DEFAULT '' NOT NULL, 
	status VARCHAR(32) DEFAULT 'open' NOT NULL, 
	closed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE, 
	FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE SET NULL
)""")
    op.execute("""CREATE INDEX incidents_product ON incidents (product_id, status)""")
    op.execute("""CREATE UNIQUE INDEX incidents_one_per_vulnerability ON incidents (vulnerability_id) WHERE vulnerability_id IS NOT NULL""")
    # ---- reporting_obligations ----
    op.execute("""CREATE TABLE reporting_obligations (
	id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	incident_id UUID NOT NULL, 
	stage VARCHAR(32) NOT NULL, 
	due_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	submitted_at TIMESTAMP WITH TIME ZONE, 
	submission_ref TEXT, 
	recipient TEXT, 
	draft_evidence_id UUID, 
	escalation_last_notified_at TIMESTAMP WITH TIME ZONE, 
	waived_reason TEXT, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT reporting_obligations_unique_stage UNIQUE (incident_id, stage), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE, 
	FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE CASCADE, 
	FOREIGN KEY(draft_evidence_id) REFERENCES evidence (id) ON DELETE SET NULL
)""")
    op.execute("""CREATE INDEX reporting_obligations_open_due ON reporting_obligations (due_at) WHERE submitted_at IS NULL""")
    op.execute("""CREATE INDEX reporting_obligations_product ON reporting_obligations (product_id)""")
    # ---- notification_log ----
    op.execute("""CREATE TABLE notification_log (
	id UUID NOT NULL, 
	recipient_user_id UUID NOT NULL, 
	product_id UUID NOT NULL, 
	obligation_id UUID, 
	kind VARCHAR(32) DEFAULT 'digest' NOT NULL, 
	sent_at TIMESTAMP WITH TIME ZONE, 
	ses_message_id TEXT, 
	status VARCHAR(16) DEFAULT 'sent' NOT NULL, 
	error_text TEXT, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(recipient_user_id) REFERENCES users (id), 
	FOREIGN KEY(product_id) REFERENCES products (id) ON DELETE CASCADE, 
	FOREIGN KEY(obligation_id) REFERENCES reporting_obligations (id) ON DELETE CASCADE
)""")
    op.execute("""CREATE INDEX notification_log_recipient_sent ON notification_log (recipient_user_id, sent_at)""")

def downgrade() -> None:
    # Reverse dependency order. The citext extension is left in place — it may
    # be shared with other databases on the same cluster.
    op.execute("DROP TABLE IF EXISTS notification_log CASCADE")
    op.execute("DROP TABLE IF EXISTS reporting_obligations CASCADE")
    op.execute("DROP TABLE IF EXISTS incidents CASCADE")
    op.execute("DROP TABLE IF EXISTS vulnerabilities CASCADE")
    op.execute("DROP TABLE IF EXISTS tool_call_logs CASCADE")
    op.execute("DROP TABLE IF EXISTS product_members CASCADE")
    op.execute("DROP TABLE IF EXISTS model_review_logs CASCADE")
    op.execute("DROP TABLE IF EXISTS evidence CASCADE")
    op.execute("DROP TABLE IF EXISTS connector_tokens CASCADE")
    op.execute("DROP TABLE IF EXISTS products CASCADE")
    op.execute("DROP TABLE IF EXISTS users CASCADE")
    op.execute("DROP TABLE IF EXISTS processed_stripe_events CASCADE")
    op.execute("DROP TABLE IF EXISTS audit_events CASCADE")
    op.execute("DROP TABLE IF EXISTS attestations CASCADE")
