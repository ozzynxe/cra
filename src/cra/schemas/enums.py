from __future__ import annotations

from enum import Enum


# ---- RBAC (carried over from Coauthor, unchanged) ---------------------------
#
# Who may edit what. Deliberately kept separate from EconomicOperatorRole
# below — see the note there for why conflating them is a trap.


class Role(str, Enum):
    """Workspace roles on a product. Ordered most → least authority."""

    OWNER = "owner"
    MAINTAINER = "maintainer"
    EDITOR = "editor"
    COMMENTER = "commenter"
    VIEWER = "viewer"


_ROLE_AUTHORITY: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.COMMENTER: 1,
    Role.EDITOR: 2,
    Role.MAINTAINER: 3,
    Role.OWNER: 4,
}


def role_at_least(actual: str, threshold: Role) -> bool:
    """True if `actual` has at least `threshold`'s authority."""
    return _ROLE_AUTHORITY[Role(actual)] >= _ROLE_AUTHORITY[threshold]


class ApprovalPolicy(str, Enum):
    """Who must sign off before an artifact counts as attested.

    `ALL_MAINTAINERS` is the default: in compliance, sign-off is usually a
    named senior person, not a quorum of everyone with commit access.
    """

    ALL_MEMBERS = "all_members"
    ALL_MAINTAINERS = "all_maintainers"
    OWNER_ONLY = "owner_only"


# ---- CRA domain -------------------------------------------------------------


class EconomicOperatorRole(str, Enum):
    """The CRA role a party plays for a product.

    **Not an authority ladder.** Manufacturer / importer / distributor /
    open-source steward carry *different obligation sets*, not more or fewer
    permissions — a steward has genuinely fewer duties, not less power. Keep
    orthogonal to `Role`: `Role` decides who may edit, this decides which
    obligations apply and therefore which tools are offered at all.
    """

    MANUFACTURER = "manufacturer"
    AUTHORISED_REPRESENTATIVE = "authorised_representative"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    OPEN_SOURCE_STEWARD = "open_source_steward"


class ProductClass(str, Enum):
    """CRA classification, which determines the conformity route.

    `IMPORTANT_CLASS_I` / `_II` are the Annex III categories; many developer
    tools land there. `UNKNOWN` is the honest default — never guess a class
    silently, because the class decides whether a notified body is required.
    """

    OUT_OF_SCOPE = "out_of_scope"
    DEFAULT = "default"
    IMPORTANT_CLASS_I = "important_class_i"
    IMPORTANT_CLASS_II = "important_class_ii"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ConformityRoute(str, Enum):
    """Which assessment path the product class forces.

    Route *families*, not modules. Whether a notified-body product goes via
    type-examination (B+C) or full quality assurance (H) is the manufacturer's
    choice; what the classification determines is whether they have that choice
    at all.
    """

    SELF_ASSESSMENT = "self_assessment"
    # Annex III class I: internal control is available only where harmonised
    # standards, common specifications or a certification scheme are applied in
    # full. Distinct from SELF_ASSESSMENT because the availability is
    # conditional, and a user who does not meet the condition is in
    # notified-body territory without having changed anything about the product.
    SELF_ASSESSMENT_WITH_STANDARDS = "self_assessment_with_standards"
    NOTIFIED_BODY = "notified_body"
    NOTIFIED_BODY_OR_CERTIFICATION = "notified_body_or_certification"
    UNKNOWN = "unknown"


class Lifecycle(str, Enum):
    """Where the product sits relative to the market.

    Load-bearing: lifecycle decides which obligations are *live*. A product in
    development has no reporting duty; one past its support period has no
    update duty. Replaces Coauthor's `GlobalStatus`, which tracked drafting
    progress — a different concept, not a rename.
    """

    IN_DEVELOPMENT = "in_development"
    PLACED_ON_MARKET = "placed_on_market"
    SUPPORT_PERIOD_ACTIVE = "support_period_active"
    SUPPORT_PERIOD_ENDED = "support_period_ended"
    WITHDRAWN = "withdrawn"


class Applicability(str, Enum):
    """Whether an Annex I requirement applies to this product.

    `NOT_APPLICABLE` requires a written justification — an auditor reads the
    justification, not the flag.
    """

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNDETERMINED = "undetermined"


class RequirementStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"


# ---- Article 13(2) risk assessment ------------------------------------------
#
# Annex I Part I requirements apply *on the basis of the risk assessment*. That
# makes the assessment the thing that determines how the rest of the checklist
# is answered, so it gets first-class state rather than living in a free-text
# justification.


class RiskStatus(str, Enum):
    """Where one identified risk stands.

    `PROPOSED` is the important one: an agent can draft risks, and a drafted
    risk determines nothing until a human decides on it. Keeping the two states
    distinct is what stops a model's output from silently becoming a compliance
    determination.
    """

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class RiskSeverity(str, Enum):
    """Qualitative on purpose.

    A CVSS-style number here would be invented: the tool has no basis for
    scoring a risk it was told about in prose, and a fabricated 7.4 reads as
    measurement. Four bands the assessor chooses, with a rationale beside them.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLikelihood(str, Enum):
    UNLIKELY = "unlikely"
    POSSIBLE = "possible"
    LIKELY = "likely"


class RiskTreatment(str, Enum):
    """What the manufacturer decided to do about it.

    `ACCEPT` is legitimate and must be recordable — Article 13(2) requires the
    risks to be assessed and taken into account, not that every one be
    eliminated. An accepted risk with a rationale is a decision; an
    unconsidered one is a hole.
    """

    MITIGATE = "mitigate"
    ACCEPT = "accept"
    TRANSFER = "transfer"
    AVOID = "avoid"


class AssessmentStatus(str, Enum):
    """Lifecycle of the assessment document itself.

    Deliberately has no `STALE` member. Staleness is *derived* from what has
    happened since confirmation (see `server/risk.py::staleness`), exactly as
    obligation state is derived from due/submitted timestamps. A stored
    staleness flag would let a missed update look like a current assessment.

    Nor is there a `SUPERSEDED` member. Article 13(3) requires the assessment
    kept up to date, so revision is the normal case rather than a terminal
    state: editing a confirmed assessment opens the next version as a DRAFT
    while the previous version stays frozen in `evidence`.
    """

    DRAFT = "draft"
    CONFIRMED = "confirmed"


class IncidentKind(str, Enum):
    """The two reportable events under Article 14. They differ only in the
    final-report deadline (14 days vs 1 month), but that difference is legal."""

    ACTIVELY_EXPLOITED_VULN = "actively_exploited_vuln"
    SEVERE_INCIDENT = "severe_incident"


class ReportStage(str, Enum):
    EARLY_WARNING = "early_warning"      # <= 24h
    NOTIFICATION = "notification"        # <= 72h
    FINAL = "final"                      # <= 14 days / 1 month


class ObligationState(str, Enum):
    """Derived, never stored.

    Computed from `due_at` / `submitted_at` / `waived_reason` by
    `cra.deadlines.obligation_state()`. Persisting it as a column would let a
    sweeper outage silently mark a user compliant.
    """

    PENDING = "pending"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    SUBMITTED = "submitted"
    SUBMITTED_LATE = "submitted_late"
    WAIVED = "waived"


class ActorKind(str, Enum):
    """Who performed an action. Recorded on every audit event *alongside* the
    accountable human — "an agent did it" is not an answer an auditor accepts.
    """

    HUMAN = "human"
    AGENT = "agent"
    MODEL = "model"


class EvidenceKind(str, Enum):
    DOCUMENT = "document"
    REPORT_DRAFT = "report_draft"
    SBOM = "sbom"
    TEST_RESULT = "test_result"
    SCAN_RESULT = "scan_result"
    POLICY = "policy"
    CORRESPONDENCE = "correspondence"
    OTHER = "other"
