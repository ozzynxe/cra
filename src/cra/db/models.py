"""SQLAlchemy 2.0 models for the Postgres layer.

Storage split (see README): Postgres holds anything a sweeper queries *across*
products, anything an auditor must read years later unaltered, and anything
needing a timestamp index. The narrative working state lives in
`products.state` as JSONB.

Conventions:
- Surrogate UUID PKs; TIMESTAMPTZ everywhere, UTC-only at the app layer.
- Optimistic concurrency on `products.state` via `state_version`.
- Two tables deliberately have NO foreign key to `products`: `audit_events`
  and `attestations`. Under the CRA the technical file is retained ten years,
  which is longer than any product's lifetime in this database — a cascade
  delete that erased the audit trail would destroy the actual deliverable.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid_str() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---- users -------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    email: Mapped[str] = mapped_column(CITEXT, nullable=False, unique=True)
    display_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Set when a magic link is completed. Until then the row exists but the
    # address is unproven — which matters more here than in most products,
    # because `accountable_user_id` on every audit row names this person. An
    # unverified address would let anyone put a colleague's name against a
    # compliance decision.
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Acceptance is recorded with the version accepted, not just a boolean: the
    # terms will change, and "they agreed" is only meaningful alongside what
    # they agreed to.
    terms_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    terms_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    tier: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    subscription_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    tier_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    model_credits_balance: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    model_credits_period_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    model_credits_trial_granted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    notifications_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    last_notified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    products_owned: Mapped[list["Product"]] = relationship(
        back_populates="owner", foreign_keys="Product.owner_user_id"
    )
    memberships: Mapped[list["ProductMember"]] = relationship(
        back_populates="user", foreign_keys="ProductMember.user_id"
    )


# ---- products ----------------------------------------------------------------


class Product(Base):
    """A product with digital elements, in CRA terms — the thing CE-marked.

    `state` is the `ComplianceState` blob. `state_version` is the optimistic
    concurrency counter: several developers' agents work one product at once,
    and writes are keyed and mostly independent, so OCC with a short critical
    section beats locking.

    There is deliberately no `visibility` column. This store holds unreported
    exploited-vulnerability details, where a public default would not be a bad
    default but an incident — so the concept does not exist here at all.
    """

    __tablename__ = "products"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    owner_user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id"), nullable=False
    )

    economic_operator_role: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="manufacturer"
    )
    product_class: Mapped[str] = mapped_column(String(32), nullable=False, server_default="unknown")
    lifecycle: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="in_development"
    )
    support_period_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    state: Mapped[dict] = mapped_column(JSONB, nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped["User"] = relationship(
        back_populates="products_owned", foreign_keys=[owner_user_id]
    )
    members: Mapped[list["ProductMember"]] = relationship(
        back_populates="product", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("products_owner", "owner_user_id"),)


class ProductMember(Base):
    """Workspace membership. `role` is RBAC — who may edit.

    Distinct from `Product.economic_operator_role`, which decides which CRA
    obligations apply. A product has one economic-operator role; its people
    have RBAC roles.
    """

    __tablename__ = "product_members"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    product: Mapped["Product"] = relationship(back_populates="members")
    user: Mapped["User"] = relationship(back_populates="memberships", foreign_keys=[user_id])

    __table_args__ = (
        UniqueConstraint("product_id", "user_id", name="product_members_unique"),
        Index("product_members_user", "user_id"),
    )


# ---- evidence ----------------------------------------------------------------


class Evidence(Base):
    """An artifact supporting a requirement, risk, vulnerability or report.

    `sha256` and `source_ref` are what make this evidence rather than an
    assertion: the hash pins the bytes, and `source_ref` says where it came
    from (git SHA, CI run URL, tool name + version). Deletes are soft —
    `superseded_by` chains a replacement so the history stays readable.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    subject_ref: Mapped[str] = mapped_column(Text, nullable=False)  # "requirement:annex_i.part_i.2"
    title: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, server_default="document")

    storage_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # S3 key
    inline_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # small artifacts
    content_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Which release this artifact is a claim about.
    #
    # Annex I requirements attach to "the product with digital elements *as
    # placed on the market*", so evidence is never a timeless fact — a test
    # report proves something about one build. Without this, a requirement
    # verified three releases ago is indistinguishable from one verified
    # against what ships today, which is how a technical file ends up
    # complete, frozen, signed and describing a product from two years back.
    #
    # NULL means untagged, and `annex.evidence_currency` reads that as
    # *unversioned* rather than *stale*: every row written before this column
    # existed is NULL, and turning all of them into gaps on deploy would be
    # asserting something about them that nobody checked.
    applies_to_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    added_by_user_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False, server_default="human")
    superseded_by: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("evidence_product_subject", "product_id", "subject_ref"),
    )


# ---- vulnerabilities, incidents, and the reporting clocks --------------------


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    identifier: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # CVE / GHSA
    affected_component: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # purl
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cvss_score: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # The field that starts a legal clock. Flipping it true opens an incident
    # and materialises the obligation rows — Article 14 turns on *actively
    # exploited*, not on severity.
    actively_exploited: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    exploitation_determined_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="open")
    remediation_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    disclosed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("vulnerabilities_product", "product_id", "status"),
    )


class Incident(Base):
    """A reportable event under Article 14.

    `became_aware_at` is the clock start and therefore the single most
    consequential timestamp in the schema — every obligation deadline is
    derived from it. It is supplied by the user, not inferred from row
    creation time: a team often records an incident hours after becoming
    aware, and back-dating the awareness is the honest thing to do.
    """

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    vulnerability_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )
    became_aware_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Anchors the final-report clock for an actively exploited vulnerability:
    # the 14 days run from when a corrective measure becomes available, NOT
    # from awareness. Usually unknown when the incident is first recorded, so
    # that obligation is materialised later — see cra.deadlines.
    corrective_measure_available_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="open")
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("incidents_product", "product_id", "status"),
        # At most one incident per vulnerability. The cascade in
        # `server/reporting.py` looks an incident up by vulnerability id; with
        # duplicates it would have to choose between them, which on a 24-hour
        # clock means choosing which deadline to show.
        Index(
            "incidents_one_per_vulnerability",
            "vulnerability_id",
            unique=True,
            postgresql_where=text("vulnerability_id IS NOT NULL"),
        ),
    )


class ReportingObligation(Base):
    """One statutory reporting deadline. The core table of the product.

    Rows, not computed values, because the sweeper asks "what is due across
    every product" — a question that must hit an index, not deserialize every
    state blob.

    No `overdue` column: status is derived by `cra.deadlines.obligation_state()`
    from `due_at` / `submitted_at` / `waived_reason`. A stored boolean flipped
    by a cron would mean a sweeper outage silently marks a user compliant.
    `escalation_last_notified_at` *is* stored, but only so reminders don't
    spam — it never affects compliance status.
    """

    __tablename__ = "reporting_obligations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[str] = mapped_column(String(32), nullable=False)  # early_warning|notification|final
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    submitted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    submission_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # SRP reference
    recipient: Mapped[Optional[str]] = mapped_column(Text, nullable=True)       # CSIRT / ENISA
    draft_evidence_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    escalation_last_notified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    waived_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("incident_id", "stage", name="reporting_obligations_unique_stage"),
        # The reason obligations are rows: the sweeper's only hot query is
        # "unsubmitted and coming due", and this index answers it directly.
        Index(
            "reporting_obligations_open_due",
            "due_at",
            postgresql_where=text("submitted_at IS NULL"),
        ),
        Index("reporting_obligations_product", "product_id"),
    )


# ---- audit trail and attestations -------------------------------------------


class AuditEvent(Base):
    """Append-only record of every state mutation.

    **No foreign key to products, deliberately.** The technical file is
    retained ten years; a cascade delete that erased this trail would destroy
    the deliverable rather than tidy up after it. Same reasoning Coauthor
    applied to `moderation_actions`.

    Both actors are recorded: `actor_kind` says whether an agent or a model
    acted, and `accountable_user_id` says which human is answerable for it.
    "An agent attached this evidence" is not an answer an auditor accepts.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    product_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)  # no FK
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    op: Mapped[str] = mapped_column(String(48), nullable=False)

    accountable_user_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True)
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False, server_default="human")
    actor_model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    before_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    after_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("audit_events_product_ts", "product_id", "ts"),
    )


class Attestation(Base):
    """A human signing off on a specific version of an artifact.

    `subject_version_hash` is what makes the signature meaningful — a
    Declaration of Conformity signed against "the technical file" is
    worthless if the file changed afterwards. No FK to products, for the same
    retention reason as `audit_events`.
    """

    __tablename__ = "attestations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)  # no FK
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    subject_version_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Which definition of the subject's "content" that hash was taken over.
    # NULL is a signature predating the column, and it is not comparable with a
    # current digest — see `conformity.HASH_PAYLOAD_VERSION`.
    hash_payload_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    signer_user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    signer_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    signer_role: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("attestations_product", "product_id"),)


# ---- OAuth dynamic client registration ---------------------------------------


class OAuthClient(Base):
    """A client registered through `/oauth/register` (RFC 7591).

    In a dict until now, which meant every container restart forgot every
    client that had ever connected. A deploy is a restart, so shipping broke
    every live connector — silently, because `_redirect_uri_registered` fails
    open for an unknown client and the failure only surfaced later, as a
    connector that could neither refresh nor be removed.

    `registration_access_token_hash` is what makes RFC 7592 deletion safe:
    without it, knowing a `client_id` — which is not a secret and travels in
    every authorize URL — would be enough to delete somebody's registration.
    Bcrypt, like `connector_tokens`, and the plaintext is returned once at
    registration and never stored.
    """

    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # The exact set the client registered. `_redirect_uri_registered` narrows
    # the host allowlist down to these; an open redirect here would hand an
    # attacker an auth code.
    redirect_uris: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    registration_access_token_hash: Mapped[Optional[str]] = mapped_column(
        String(72), nullable=True
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (Index("oauth_clients_issued", "issued_at"),)


# ---- connector tokens --------------------------------------------------------


class ConnectorToken(Base):
    __tablename__ = "connector_tokens"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id"), nullable=False
    )
    # NULL = user-wide token: the agent acts across every product the user can
    # reach, and picks one by passing product_id to each tool call.
    product_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=True
    )
    label: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)  # bcrypt
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("connector_tokens_prefix", "prefix"),
        Index("connector_tokens_user", "user_id"),
        UniqueConstraint("prefix", name="connector_tokens_prefix_unique"),
    )


# ---- usage / billing logs ----------------------------------------------------


class ToolCallLog(Base):
    __tablename__ = "tool_call_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    product_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="SET NULL"), nullable=True
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("tool_call_logs_user_ts", "user_id", "ts"),)


class ModelReviewLog(Base):
    __tablename__ = "model_review_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    product_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="SET NULL"), nullable=True
    )
    subject_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_id: Mapped[str] = mapped_column(String(64), nullable=False)
    model_tier: Mapped[str] = mapped_column(String(16), nullable=False)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    credit_cost: Mapped[int] = mapped_column(Integer, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("model_review_logs_user_ts", "user_id", "ts"),)


class ProcessedStripeEvent(Base):
    """Stripe retries on 5xx for ~3 days; insert the event id first and 200 on
    duplicate-key collision without re-running side effects."""

    __tablename__ = "processed_stripe_events"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class StatutoryExport(Base):
    """One artefact that has to outlive this database, and whether it has.

    Article 13(13) keeps the technical documentation and the EU declaration
    available for ten years after placing on the market, or the support period
    if longer. Nightly database dumps used to carry that obligation by
    accident, at the cost of keeping *everything* immutably for a decade
    This table is the deliberate version: the small
    set of things that genuinely must survive, exported one object per artefact
    under Object Lock with per-object retention.

    **The row is written in the same transaction as the artefact it describes.**
    That is the whole guarantee. S3 is a different system and cannot be atomic
    with Postgres, so the upload happens afterwards — but the *intent* commits
    with the sign-off, and there is no path that produces a frozen declaration
    with no corresponding row here.

    `status` therefore matters more than it looks. `pending` means the artefact
    exists and the copy does not yet, which is a real state and an alertable
    one; `failed` carries `error_text`. The same shape as `NotificationLog`,
    and for the same reason: a durability failure that leaves no trace is
    indistinguishable from success, which is the one outcome this product
    refuses everywhere else.

    `content_sha256` keys it. Re-exporting an unchanged artefact is a no-op,
    so a retry storm cannot produce duplicate objects and a re-freeze that
    changes nothing does not write a second copy.
    """

    __tablename__ = "statutory_exports"
    __table_args__ = (
        UniqueConstraint("product_id", "kind", "content_sha256", name="uq_statutory_export"),
        Index("ix_statutory_exports_pending", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    # technical_file | declaration | simplified_declaration | sign_off | release
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Derived from `conformity.retention_status` at export time, floored at ten
    # years. Object Lock retention can be extended and not shortened, so erring
    # long is the safe direction.
    retain_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    storage_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exported_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class NotificationLog(Base):
    __tablename__ = "notification_log"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    recipient_user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id"), nullable=False
    )
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    obligation_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("reporting_obligations.id", ondelete="CASCADE"),
        nullable=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False, server_default="digest")
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ses_message_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="sent")
    error_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("notification_log_recipient_sent", "recipient_user_id", "sent_at"),
    )


class AdvisoryCandidate(Base):
    """A feed match: an advisory affecting a component that appears in an SBOM.

    Deliberately not a `Vulnerability`, and never an `Incident`. A match says an
    advisory exists for a version string present in your bill of materials. It
    does not say the vulnerable path is reachable, that the component ships in
    what you place on the market, or that your build has not already patched it.

    That gap matters more here than anywhere else in the schema, because under
    Article 14 the answer is not free: recording an actively exploited
    vulnerability starts a 24-hour clock. So detection produces a row a person
    then disposes of — confirm, and it becomes a vulnerability record; dismiss,
    and the justification is itself Annex I Pt II(2) evidence of a handled
    vulnerability.

    `notified_at` is the load-bearing timestamp. It is when the tool told a
    human, and therefore the earliest defensible answer to "when did the
    manufacturer become aware" — which is what `confirm_advisory` anchors the
    statutory clocks on by default.
    """

    __tablename__ = "advisory_candidates"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )

    advisory_id: Mapped[str] = mapped_column(String(64), nullable=False)  # GHSA-… / CVE-…
    cve_ids: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # Text, not String(n). OSV puts a CVSS *vector* in `severity.score` — 44
    # characters for v3.1 and 63 for v4.0 — which overflowed String(32) on the
    # first real scan. Vectors get longer with each CVSS revision, so a
    # generous fixed width is a bet against the next one.
    severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    component_name: Mapped[str] = mapped_column(Text, nullable=False)
    component_version: Mapped[str] = mapped_column(String(64), nullable=False)
    component_ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    component_purl: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Whether CISA lists it as known-exploited. The difference between a backlog
    # item and a reporting question.
    exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    kev_cve_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    kev_date_added: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # EPSS: how likely this CVE is to be exploited in the next 30 days, and
    # that probability's percentile among all scored CVEs. Both, always —
    # probability alone is the misleading half (0.05 at the 92nd percentile is
    # a real case, CVE-2020-8203).
    #
    # NULL means unscored, and must never be read as zero. Nullable rather than
    # defaulted for exactly that reason: a `server_default="0"` here would
    # quietly convert "the model has nothing to say" into "negligible" for
    # every row that predates this column.
    epss_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # Provenance. Scores move when the model does, so a stored score without
    # both of these cannot be reproduced or explained after the fact.
    epss_model_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    epss_score_date: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    # The scores as they stood when somebody dismissed this candidate, kept
    # apart from the live pair above, which every scan overwrites: what
    # re-opens a dismissal is a rise *since the judgement was made*, not since
    # last night. The trigger reads the probability — percentile compresses
    # near the top of the distribution, so a jump from a 5% to a 71% chance of
    # exploitation moves it barely 0.07 — and the percentile is stored beside
    # it so the note can show both.
    epss_probability_at_decision: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    epss_percentile_at_decision: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    notified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="open")
    # Text for the same reason, and this one was self-inflicted:
    # "vulnerable_code_cannot_be_controlled_by_adversary" is 49 characters and
    # the column was 48. A closed vocabulary defined in this repo did not fit a
    # column defined in this repo, because the tests used the shorter members.
    disposition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    disposition_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_by: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    vulnerability_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True)

    __table_args__ = (
        # One row per advisory per component version per product, so a nightly
        # rescan re-finds rather than re-raises — and a dismissal stays
        # dismissed instead of reappearing every morning.
        UniqueConstraint(
            "product_id",
            "advisory_id",
            "component_name",
            "component_version",
            name="advisory_candidates_unique",
        ),
        Index("advisory_candidates_product", "product_id", "status"),
        # The sweeper's question: what is exploited, unresolved, and not yet
        # told to anyone.
        Index(
            "advisory_candidates_unnotified",
            "exploited",
            "notified_at",
            postgresql_where=text("notified_at IS NULL AND status = 'open'"),
        ),
    )


class AdvisoryScan(Base):
    """That a scan ran, when, and whether it could actually see anything.

    A clean scan used to leave no trace at all: `_persist` writes candidate
    rows, so a product with nothing wrong produced an empty result and no
    record. That is fine until something has to rely on it — and the Annex I
    Pt I(2)(a) release gate does. "No open candidates" means nothing without
    "and we looked, on this date, and the feeds answered".

    `sources_ok` is the load-bearing column and the reason the counts are not
    enough on their own. A scan that could not reach OSV finds zero advisories,
    which is the same zero as a genuinely clean product and the opposite
    meaning. The gate refuses on `sources_ok=False` for exactly that reason.

    A table rather than a field on the blob: the sweeper scans every product
    nightly, and a blob write per product per night would churn `state_version`
    and `updated_at` for accounts nobody touched and serialise against real
    work. History is also worth having — a run of dated clean scans is itself
    Annex I Pt II(2) evidence that vulnerabilities were being handled.
    """

    __tablename__ = "advisory_scans"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    ran_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Whether each feed answered. `sources_ok` is KEV and OSV only — EPSS
    # merely orders findings, so a scoring outage degrades the queue rather
    # than invalidating the scan (see advisories.build_findings).
    sources_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    kev_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    osv_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    epss_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    components_checked: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    findings: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    exploited: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Which bill of materials was checked, so a scan can be tied to a build.
    sbom_source_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # And which build that bill of materials described. `sbom_source_ref` alone
    # could not answer "was this release's component list the one scanned",
    # which is the question the Annex I Pt I(2)(a) gate turns on. NULL means the
    # SBOM carried no version, or the scan predates this column — unknown, not
    # a match.
    sbom_applies_to_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # The gate's question: what is the most recent scan for this product.
        Index("advisory_scans_product_ran", "product_id", "ran_at"),
    )


class SignupLink(Base):
    """A single-use, short-lived proof that someone can read an email address.

    Two shapes, one table, because the state machine is identical — issue,
    expire, spend once — and only the presentation differs:

    - `purpose='link'`  a 32-byte secret in a URL, mailed for `/access`.
    - `purpose='code'`  a six-digit code, mailed for the OAuth consent page.

    The split exists so neither is redeemable where the other was meant to go.
    A code emailed to connect an app must not mint a raw token at `/access`,
    and a link mailed for `/access` must not complete somebody's OAuth grant.

    Stateful rather than a stateless signed token, for one reason: single use.
    A stateless HMAC can carry an expiry but cannot be spent, and these land in
    inboxes that get forwarded, backed up and indexed.

    Neither secret is stored — only its sha256. The link carries `<id>.<secret>`
    and the code is checked against the row the waiting page names, so a
    database dump contains nothing redeemable. sha256 rather than bcrypt is
    deliberate for the link: 32 random bytes are not a password, so there is
    nothing to brute-force. **The code is different** — a million values is a
    guessable space, so `attempts` is the control that matters there, not the
    hash. Five wrong guesses spend the row.
    """

    __tablename__ = "signup_links"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False, server_default="link")
    # Exactly one of these is set, per purpose. Nullable rather than two tables
    # because everything else about the row — issue, expire, spend — is shared.
    secret_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    code_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Only meaningful for codes. The whole defence: six digits is 20 bits, and
    # 20 bits with unlimited guesses is not a secret at all.
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        # The sweep for live challenges for one address, used to decide whether
        # to send another rather than let someone mail-bomb a third party.
        Index("signup_links_email", "email", "expires_at"),
        # A row that can prove nothing is a bug, not a state.
        CheckConstraint(
            "secret_sha256 IS NOT NULL OR code_sha256 IS NOT NULL",
            name="signup_links_has_a_secret",
        ),
    )


class WebSession(Base):
    """A browser signed in to the read-only console.

    The rest of this deployment deliberately has no sessions: `/access`, the
    OAuth consent page and `/billing` each carry their intent through a single
    email-and-code exchange and remember nothing. A console cannot — somebody
    reading their compliance state clicks between pages for an hour.

    A row rather than a signed cookie, for the reason the magic link is a row:
    a stateless token can carry an expiry but cannot be *revoked*. A product
    whose value is an auditable record should be able to answer "end every
    session on my account", and that needs somewhere to write.

    The secret is never stored, only its sha256, and the cookie carries
    `<id>.<secret>` — so a database dump contains nothing that can be replayed
    as a login.
    """

    __tablename__ = "web_sessions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    secret_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # Slides forward on use, but never past `hard_expires_at`. A session that
    # renews itself indefinitely is a permanent credential wearing a cookie.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hard_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        # "Show me my sessions" and "end them all" are both this index.
        Index("web_sessions_user", "user_id", "expires_at"),
    )


class ProductInvitation(Base):
    """Someone invited to a product before they had an account.

    `add_member` used to take a `user_id` — an internal UUID — with no way to
    look one up, so inviting a colleague was impossible unless you could read
    it out of the database. It now takes an email, and this row is what happens
    when that address has no account yet: the invitation waits, and
    `signup._claim_account` applies it the moment they verify.

    Kept after acceptance rather than deleted. Who was invited to a product,
    by whom, and when they joined is part of the record of who could have
    touched a technical file.
    """

    __tablename__ = "product_invitations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid_str)
    product_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    invited_by: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("product_invitations_email", "email", "accepted_at"),
        # One live invitation per address per product. Re-inviting should not
        # silently stack rows that all fire at signup.
        UniqueConstraint("product_id", "email", name="product_invitations_unique"),
    )
