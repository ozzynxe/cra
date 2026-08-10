"""Postgres layer.

Holds everything a sweeper queries across products, everything an auditor must
read years later unaltered, and the product state blob itself:

  - users                   — identity + tier + credits
  - products                — the CE-marked thing, with `state` JSONB
  - product_members         — RBAC membership
  - evidence                — hashed artifacts backing requirements/reports
  - vulnerabilities         — incl. the actively-exploited flag that starts a clock
  - incidents               — `became_aware_at` is the clock start
  - reporting_obligations   — the 24h / 72h / 14d deadlines
  - audit_events            — append-only, no FK (must outlive the product)
  - attestations            — sign-off bound to a version hash
  - connector_tokens        — per-(user, product) bearer tokens

`products.id` is the same string the state store keys on.
"""

from cra.db.engine import (
    create_engine_from_env,
    db_session,
    engine_for,
    get_engine,
    session_scope,
)
from cra.db.models import (
    AdvisoryCandidate,
    AdvisoryScan,
    Attestation,
    AuditEvent,
    Base,
    ConnectorToken,
    Evidence,
    Incident,
    ModelReviewLog,
    NotificationLog,
    StatutoryExport,
    ProcessedStripeEvent,
    Product,
    ProductInvitation,
    ProductMember,
    ReportingObligation,
    SignupLink,
    WebSession,
    ToolCallLog,
    User,
    Vulnerability,
)

__all__ = [
    "AdvisoryCandidate",
    "AdvisoryScan",
    "Attestation",
    "AuditEvent",
    "Base",
    "ConnectorToken",
    "Evidence",
    "Incident",
    "ModelReviewLog",
    "NotificationLog",
    "StatutoryExport",
    "ProcessedStripeEvent",
    "Product",
    "ProductInvitation",
    "ProductMember",
    "ReportingObligation",
    "SignupLink",
    "WebSession",
    "ToolCallLog",
    "User",
    "Vulnerability",
    "create_engine_from_env",
    "db_session",
    "engine_for",
    "get_engine",
    "session_scope",
]
