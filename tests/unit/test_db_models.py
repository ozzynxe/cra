"""Unit-level checks on the Postgres models.

No database connection — these exercise the SQLAlchemy metadata to catch typos
in column types, FK references, and table names.

Most of these assert *design decisions*, not just structure. Each one has a
failure mode that is expensive and quiet: an audit trail that cascades away, a
sweeper query with no index behind it, a product store that defaults to public.
"""

from __future__ import annotations

from sqlalchemy import UniqueConstraint

from cra.db.models import (
    Attestation,
    AuditEvent,
    Base,
    ConnectorToken,
    Evidence,
    Incident,
    Product,
    ProductMember,
    ReportingObligation,
    User,
    Vulnerability,
)


def test_all_tables_present_in_metadata():
    expected = {
        "users",
        "products",
        "product_members",
        "evidence",
        "vulnerabilities",
        "incidents",
        "reporting_obligations",
        "audit_events",
        "attestations",
        "connector_tokens",
        "tool_call_logs",
        "model_review_logs",
        "processed_stripe_events",
        "notification_log",
    }
    assert expected <= set(Base.metadata.tables)


def test_coauthor_tables_are_gone():
    """The fork should not carry document/Q&A tables forward."""
    stale = {"documents", "document_members", "source_documents", "activity_log", "tags", "document_tags"}
    assert not (stale & set(Base.metadata.tables))


def test_audit_events_has_no_fk_to_products():
    """The audit trail must outlive the product row.

    The CRA technical file is retained ten years — longer than a product's
    lifetime in this database. A cascade delete here would erase the
    deliverable, not tidy up after it.
    """
    fks = Base.metadata.tables["audit_events"].foreign_keys
    assert not any(fk.column.table.name == "products" for fk in fks)


def test_attestations_has_no_fk_to_products():
    """Same retention reasoning as audit_events: a signature must survive."""
    fks = Base.metadata.tables["attestations"].foreign_keys
    assert not any(fk.column.table.name == "products" for fk in fks)


def test_attestation_binds_to_a_version_hash():
    """A signature against "the technical file" is worthless if the file can
    change afterwards."""
    col = Base.metadata.tables["attestations"].c.subject_version_hash
    assert not col.nullable


def test_reporting_obligations_has_partial_index_on_open_due():
    """The sweeper's only hot query is "unsubmitted and coming due". That index
    existing is the entire reason obligations are rows and not blob fields.
    """
    idx = {i.name: i for i in Base.metadata.tables["reporting_obligations"].indexes}
    assert "reporting_obligations_open_due" in idx
    where = idx["reporting_obligations_open_due"].dialect_options["postgresql"]["where"]
    assert "submitted_at IS NULL" in str(where)


def test_reporting_obligations_have_no_stored_overdue_flag():
    """Status is derived by `obligation_state()`. A boolean flipped by a cron
    would let a sweeper outage silently mark a user compliant.
    """
    cols = set(Base.metadata.tables["reporting_obligations"].c.keys())
    assert "overdue" not in cols
    assert "state" not in cols
    assert {"due_at", "submitted_at"} <= cols


def test_products_have_no_visibility_column():
    """Coauthor defaulted documents to public. This store holds unreported
    exploited-vulnerability details, where that default is an incident.
    """
    assert "visibility" not in Base.metadata.tables["products"].c


def test_product_state_is_jsonb_with_version_counter():
    cols = Base.metadata.tables["products"].c
    assert "state" in cols and not cols["state"].nullable
    assert "state_version" in cols


def test_incident_clock_start_is_required():
    """`became_aware_at` is the timestamp every statutory deadline derives
    from, and it is supplied rather than inferred — teams routinely record an
    incident hours after becoming aware."""
    assert not Base.metadata.tables["incidents"].c.became_aware_at.nullable


def test_one_incident_per_vulnerability_is_enforced_by_the_database():
    """The cascade resolves an incident by vulnerability id. With duplicates it
    would have to pick one, which on a 24-hour clock means picking which
    deadline to show — so the constraint lives in the schema, not in a guard.
    """
    idx = {i.name: i for i in Base.metadata.tables["incidents"].indexes}
    one = idx["incidents_one_per_vulnerability"]
    assert one.unique
    # Partial, so several incidents unrelated to any vulnerability coexist.
    assert "vulnerability_id IS NOT NULL" in str(
        one.dialect_options["postgresql"]["where"]
    )


def test_obligations_are_unique_per_incident_stage():
    """Materialising obligations is idempotent in code; this makes a concurrent
    double-cascade impossible rather than merely unlikely."""
    uniques = {
        c.name: {col.name for col in c.columns}
        for c in Base.metadata.tables["reporting_obligations"].constraints
        if isinstance(c, UniqueConstraint)
    }
    assert uniques["reporting_obligations_unique_stage"] == {"incident_id", "stage"}


def test_vulnerability_actively_exploited_defaults_false():
    """Article 14 turns on *actively exploited*, not severity. Defaulting true
    would start legal clocks on every recorded vulnerability."""
    col = Base.metadata.tables["vulnerabilities"].c.actively_exploited
    assert not col.nullable
    assert "false" in str(col.server_default.arg).lower()


def test_connector_token_product_scope_is_nullable():
    """NULL = user-wide token, which is what makes "what's due across
    everything I own" possible."""
    assert Base.metadata.tables["connector_tokens"].c.product_id.nullable


def test_evidence_carries_hash_and_provenance():
    """Hash plus source_ref is what makes it evidence rather than an assertion."""
    cols = set(Base.metadata.tables["evidence"].c.keys())
    assert {"sha256", "source_ref", "actor_kind", "deleted_at"} <= cols
