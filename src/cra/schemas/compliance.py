"""The per-product compliance state blob.

Replaces Coauthor's `DocumentState`. The storage split rule:

  Postgres  — anything a sweeper queries *across* products (deadlines),
              anything an auditor must read years later unaltered
              (evidence, audit events, attestations, releases), and
              anything needing a timestamp index.
  This blob — narrative working state the agent iterates on within one
              product.

So `revisions` and `party_approvals` are deliberately absent here; they live
in `audit_events` and `attestations` rows. Coauthor put both in the blob,
which would force the deadline sweeper to deserialize every product to answer
"what's due in six hours".

Forward-compat discipline carried over from Coauthor: new fields get defaults
so older blobs keep deserializing, and `extra="forbid"` catches typos at the
boundary rather than silently dropping data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from cra.schemas.enums import (
    Applicability,
    ApprovalPolicy,
    AssessmentStatus,
    ConformityRoute,
    EconomicOperatorRole,
    Lifecycle,
    ProductClass,
    RequirementStatus,
    RiskLikelihood,
    RiskSeverity,
    RiskStatus,
    RiskTreatment,
    Role,
)


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class MemberInfo(_Base):
    """A user with a workspace role on the product.

    The dict key in `ComplianceState.members` is the user id. `role` is RBAC
    (who may edit) — the product's CRA obligations come from
    `ComplianceState.economic_operator_role`, not from here.
    """

    role: Role
    user_id: Optional[str] = None
    display_name: Optional[str] = None
    joined_at: Optional[datetime] = None


class ProductClassification(_Base):
    """Result of the scope assessment.

    `rationale` is not decoration — it is what a human checks the tool's
    indicative answer against, and what an auditor reads. A classification
    with no rationale should be treated as absent.
    """

    product_class: ProductClass = ProductClass.UNKNOWN
    in_scope: Optional[bool] = None
    annex_iii_category: Optional[str] = None
    conformity_route: ConformityRoute = ConformityRoute.UNKNOWN
    rationale: str = ""
    classified_at: Optional[datetime] = None
    classified_by: Optional[str] = None


class RiskItem(_Base):
    """One identified cybersecurity risk, and what it makes applicable.

    `affects_requirements` is the load-bearing field: it is the link from "this
    is what can go wrong" to "therefore this Annex I requirement applies to us".
    Without it the assessment is a document nobody can act on, and requirement
    applicability goes back to being asserted from nowhere.

    Provenance is split three ways on purpose. `proposed_by_kind` /
    `proposed_by_model` record that a model drafted the risk;
    `decided_by` records the human account answerable for accepting it. An
    auditor's question is "who decided this applies", and "an agent suggested
    it" is not an answer.
    """

    risk_id: str
    title: str
    description: str = ""

    # The analysis. Free text rather than a fixed taxonomy: STRIDE, attack
    # trees and ISO 27005 all fit these slots, and the CRA mandates no method.
    asset: str = ""                # what is at stake
    threat: str = ""               # what the adversary does
    attack_vector: str = ""        # how they reach it
    preconditions: str = ""        # what must be true first
    impact: str = ""               # consequence if it succeeds

    severity: Optional[RiskSeverity] = None
    likelihood: Optional[RiskLikelihood] = None
    treatment: Optional[RiskTreatment] = None
    mitigation_note: str = ""
    residual_note: str = ""

    affects_requirements: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    status: RiskStatus = RiskStatus.PROPOSED
    proposed_by: Optional[str] = None
    proposed_by_kind: str = "agent"
    proposed_by_model: Optional[str] = None
    proposed_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision_rationale: str = ""


class RiskAssessment(_Base):
    """The Article 13(2) assessment: the basis every Part I answer rests on.

    Article 13(2) requires the manufacturer to assess the product's
    cybersecurity risks and take the outcome into account across design,
    development, production and maintenance. Article 13(3) requires it
    documented and kept up to date, and Annex VII(3) requires it in the
    technical file. So this is not a planning aid — it is a retained artifact,
    which is why confirming one freezes a hashed copy into `evidence` rather
    than leaving it editable in the blob.

    The four narrative inputs are Article 13(2)'s own framing (intended
    purpose, reasonably foreseeable use and misuse, conditions of use, and how
    long the product is supported). They are held separately from the product
    description because an assessment has to state the scope it was performed
    against — the same product reassessed for a different deployment context is
    a different assessment.
    """

    version: int = 1
    status: AssessmentStatus = AssessmentStatus.DRAFT
    method: str = ""

    intended_purpose: str = ""
    foreseeable_misuse: str = ""
    conditions_of_use: str = ""
    support_duration_note: str = ""
    scope_note: str = ""

    # Article 13(3)'s last sentence, which the rest of this object does not
    # answer. The risks and their `affects_requirements` cover Part I(2) —
    # which of the fourteen product requirements apply, and why — and the
    # paragraph asks for two further things the assessment must *also*
    # indicate:
    #
    #   "It shall also indicate how the manufacturer is to apply Part I,
    #    point (1), of Annex I and the vulnerability handling requirements
    #    set out in Part II of Annex I."
    #
    # Part I(1) is the overarching "appropriate level of cybersecurity based on
    # the risks" duty, and Part II is the eight-point vulnerability handling
    # process. Neither is a per-risk determination, which is why neither fell
    # out of the risk list: they are statements of approach, made once, about
    # the whole product.
    part_i_1_approach: str = ""
    part_ii_approach: str = ""

    risks: list[RiskItem] = Field(default_factory=list)

    started_at: Optional[datetime] = None
    started_by: Optional[str] = None
    confirmed_at: Optional[datetime] = None
    confirmed_by: Optional[str] = None
    confirmation_rationale: str = ""

    # The frozen artifact. `content_hash` is what the technical file and any
    # signature bind to, so an edit after confirmation is visible as a mismatch
    # rather than silently changing what was declared.
    content_hash: Optional[str] = None
    evidence_id: Optional[str] = None

    # What the assessment was performed against, captured at confirmation.
    # Staleness is derived by comparing these to the product's state now — see
    # `server/risk.py::staleness`. Storing the comparison basis is not the same
    # as storing the verdict.
    basis_product_class: Optional[str] = None
    basis_lifecycle: Optional[str] = None


class RequirementItem(_Base):
    """One Annex I requirement as it applies to this product.

    Descends from Coauthor's `CompletenessItem`, with one upgrade that matters:
    evidence is `evidence_ids` pointing at hashed `evidence` rows, not the free
    text `CompletenessItem.evidence` carried. Free-text evidence is exactly
    what an auditor rejects.

    `celex_ref` / `eli_ref` anchor the requirement to authoritative source text
    (see `cra.regulation`) so the technical file cites the regulation rather
    than someone's paraphrase of it.
    """

    req_id: str                                   # e.g. "annex_i.part_i.2.b"
    title: str
    text: str = ""
    celex_ref: Optional[str] = None
    eli_ref: Optional[str] = None
    applicability: Applicability = Applicability.UNDETERMINED
    justification: str = ""                       # REQUIRED when not_applicable
    # Which accepted risks made this requirement applicable. Annex I Part I
    # applies "on the basis of the risk assessment", so this is the difference
    # between a determination with a basis and one asserted from nowhere.
    risk_basis: list[str] = Field(default_factory=list)
    status: RequirementStatus = RequirementStatus.NOT_STARTED
    implementation_note: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    last_reviewed_at: Optional[datetime] = None
    last_edited_by: Optional[str] = None
    last_edited_at: Optional[datetime] = None


class UserInfoItem(_Base):
    """One Annex II item, as it stands for this product.

    Deliberately thinner than `RequirementItem`. An Annex I requirement carries
    an applicability determination resting on the risk assessment, and a
    separate implementation status — the two are different questions. Annex II
    asks only whether the information accompanies the product, so `provided`
    and `not_applicable` are the whole vocabulary.

    `not_applicable` still demands a justification. Four of the fifteen items
    are conditional in the annex's own words, which makes ruling them out a
    normal and legitimate act — and precisely for that reason the reasoning has
    to be recorded, or "where applicable" becomes a way to empty the annex.
    """

    item_id: str
    anchor: str
    text: str = ""
    provided: bool = False
    not_applicable: bool = False
    justification: str = ""              # REQUIRED when not_applicable
    location: str = ""                   # where a user actually finds it
    note: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    last_edited_by: Optional[str] = None
    last_edited_at: Optional[datetime] = None


class ReleaseGate(_Base):
    """The Annex I Pt I(2)(a) determination, frozen at the moment of release.

    I(2)(a) bars *making available on the market* a product with known
    exploitable vulnerabilities. That is a claim about an instant, not a state,
    and this is the record of what was true at that instant: when the backing
    scan ran, whether its sources were actually reachable, and how many
    candidates were still unresolved.

    `accepted_rationale` is the whole reason this can be non-empty. Shipping
    with open candidates is a decision a manufacturer is allowed to make; what
    they are not allowed to do is make it silently. Same shape as
    `dismiss_advisory`, where the price of proceeding is saying why.
    """

    scan_at: Optional[datetime] = None
    scan_sources_ok: bool = False
    scan_age_days: Optional[float] = None
    # Optional since 2026-08-09, and `None` means "never looked" rather than
    # "none found". A never-scanned product genuinely has nought open
    # candidates, and reporting that number beside a null `scan_at` reads as
    # good news — the same failure `scan_sources_ok` exists to prevent, where a
    # feed that could not be reached and a clean result are the same zero.
    # Releases frozen before this keep whatever was stored; a frozen
    # determination is not rewritten to be clearer after the fact.
    open_candidates: Optional[int] = None
    exploited_open: int = 0
    # Confirmed vulnerabilities, not candidates. Added 2026-08-09: the gate
    # counted only the candidate queue, so confirming an exploited advisory —
    # the act of agreeing your product is affected — removed it from the gate
    # and the frozen position recorded `exploited_open: 0`. Defaults to 0 and
    # an empty list, so releases frozen before this read as "not recorded"
    # rather than as "none", which is what they are.
    exploited_vulnerabilities: int = 0
    exploited_vulnerability_ids: list[str] = Field(default_factory=list)
    accepted_rationale: str = ""
    evidence_id: Optional[str] = None
    # Which feeds backed the determination, so it can be explained later.
    epss_model_version: Optional[str] = None
    epss_score_date: Optional[str] = None


class Release(_Base):
    """A version placed on the market, and what was known when it was.

    The object the rest of the versioning work hangs off. Annex I attaches to
    "the product with digital elements *as placed on the market*", so evidence
    is a claim about a specific one of these — see `annex.evidence_currency`.

    `version` is the manufacturer's own identifier and is not parsed or
    ordered. Semver, a date, a build number and an internal codename are all
    legitimate, and a tool that sorted them would eventually sort one wrongly
    and call the wrong release current. Order comes from `released_at`.
    """

    version: str
    released_at: datetime
    source_ref: str = ""
    notes: str = ""
    recorded_at: datetime
    recorded_by: str = ""
    gate: ReleaseGate = Field(default_factory=ReleaseGate)


class SupportPeriod(_Base):
    """Article 13(8): how long vulnerabilities will be handled, and why.

    Two things, and the second is the one people forget. 13(8) sets a floor of
    five years — but it also requires *the information taken into account* in
    determining the period to be in the technical documentation, which is what
    Annex VII(4) is. A date alone satisfies neither: `rationale` is not
    decoration here, it is half the obligation.

    `expected_use_years` records the paragraph's only exception. "The support
    period shall be at least five years. Where the product is expected to be in
    use for less than five years, the support period shall correspond to the
    expected use time." So a shorter period is not invalid — it is a claim
    about the product's expected life, and it has to be made explicitly rather
    than arrived at by picking a nearer date.
    """

    start: Optional[datetime] = None
    end: Optional[datetime] = None
    rationale: str = ""
    published_url: Optional[str] = None
    # Set only when the period is shorter than five years, and then it is what
    # makes it lawful rather than merely short.
    expected_use_years: Optional[float] = None
    determined_at: Optional[datetime] = None
    determined_by: Optional[str] = None


class SubmitterProfile(_Base):
    """Who files, in ENISA's terms — separate from the product itself.

    `legal_name` is SRP field 7 and `member_states_available` is field 11;
    without the first, no report can be filed at all. The registration flags
    exist because EU Login enrolment is a prerequisite nobody should be
    discovering at hour 3 of a 24-hour clock.
    """

    legal_name: str = ""
    # Annex V(2) is "Name **and address** of the manufacturer or authorised
    # representative", and there was nowhere to put the second half. The
    # declaration filled the field from `legal_name` alone, so V(2) could never
    # be complete and was never reported incomplete — a mandatory element
    # silently omitted from a signed artefact.
    #
    # Free text, and one field rather than a structured address: Annex V does
    # not prescribe a form, the declaration is read by people, and a schema
    # with a `postcode` would start refusing addresses that do not have one.
    postal_address: str = ""
    member_states_available: list[str] = Field(default_factory=list)
    eu_login_registered: Optional[bool] = None
    srp_registered: Optional[bool] = None
    security_contact: str = ""
    disclosure_policy_url: Optional[str] = None


class ConformityClaim(_Base):
    """Which assessment route the manufacturer says they relied on, and why.

    **A claim, not a derivation.** `classification.conformity_route` is what the
    catalogue says the product's class permits; this is what the manufacturer
    asserts they actually did. The two are different things and the declaration
    rests on the second.

    They were conflated until 2026-08-10, and an end-to-end run showed what that
    costs. The product was Annex III class I, where self-assessment is available
    *only* where harmonised standards, common specifications or a certification
    scheme are applied in full. The technical file recorded, in its own words,
    "ETSI EN 303 645 in part; no harmonised standard applied in full" — and the
    declaration was then issued asserting conformity with Annex V(7), the
    notified body, absent. A signed claim of conformity by a route the record
    says was not open.

    Deciding that from `standards_applied` would mean parsing a sentence, and
    being wrong in the permissive direction manufactures exactly the assurance
    this service exists to withhold. So the condition is asserted explicitly and
    the reasoning is recorded beside it — the same shape as Article 13(8), where
    the support period needs the date *and* the information taken into account.
    """

    route: Optional[str] = None
    basis: str = ""
    # Annex III class I only. `True` asserts the condition that makes internal
    # control available; anything else leaves the conditional route unclaimed.
    standards_applied_in_full: Optional[bool] = None
    claimed_at: Optional[datetime] = None
    claimed_by: Optional[str] = None


class ComplianceState(_Base):
    product_id: str
    name: str
    description: str = ""
    intended_use: str = ""
    deployment_context: str = ""

    members: dict[str, MemberInfo] = Field(default_factory=dict)
    economic_operator_role: EconomicOperatorRole = EconomicOperatorRole.MANUFACTURER
    approval_policy: ApprovalPolicy = ApprovalPolicy.ALL_MAINTAINERS

    classification: ProductClassification = Field(default_factory=ProductClassification)
    # Article 13(2). Sits between classification and the checklist because that
    # is the order the regulation works in: in scope → assess the risks → the
    # assessment decides which Part I requirements apply and how.
    risk_assessment: Optional[RiskAssessment] = None
    requirements: list[RequirementItem] = Field(default_factory=list)
    # Annex II, the information that must accompany the product. Separate from
    # `requirements` on purpose: Annex I is about what the product *is* and
    # Annex II about what ships beside it, and merging them would break the
    # part_i/part_ii filters and the technical file's Annex I coverage count.
    user_information: list[UserInfoItem] = Field(default_factory=list)
    # Versions placed on the market, oldest first. `annex.latest_release`
    # reads the last entry rather than sorting: version strings are the
    # manufacturer's own and are not orderable, so arrival order is the only
    # honest sequence.
    releases: list[Release] = Field(default_factory=list)
    support_period: SupportPeriod = Field(default_factory=SupportPeriod)
    submitter: SubmitterProfile = Field(default_factory=SubmitterProfile)

    # Annex VII / Annex V. Hashes rather than documents: the artifacts live in
    # `evidence` rows, and what the blob needs is the pointer plus the version
    # a signature can bind to.
    technical_file_hash: Optional[str] = None
    technical_file_evidence_id: Optional[str] = None
    technical_file_finalized_at: Optional[datetime] = None
    conformity_declaration_hash: Optional[str] = None
    # Which Annex V fields the last draft could not fill. On the blob rather
    # than only in the evidence payload because `sign_off` and
    # `get_conformity_status` both need it, and neither should have to open an
    # evidence row to find out what it is about to attest to. Added 2026-08-09:
    # a declaration signed with the manufacturer's name missing, and nothing in
    # the sign-off response said so.
    conformity_declaration_missing: list[str] = Field(default_factory=list)
    # What the manufacturer says they relied on, distinct from what the
    # class permits. See `ConformityClaim`.
    conformity_claim: ConformityClaim = Field(default_factory=ConformityClaim)
    conformity_declaration_evidence_id: Optional[str] = None
    # Article 13(20): where the *full* declaration is published, so the
    # simplified form can name it. Kept on the record rather than only in the
    # rendered document, because the address is a required element of the
    # short form and not presentation.
    conformity_declaration_url: Optional[str] = None

    lifecycle: Lifecycle = Lifecycle.IN_DEVELOPMENT

    created_at: datetime
    updated_at: datetime

    # Optimistic-concurrency counter. Several developers' agents work one
    # product concurrently; writes are keyed and mostly independent, so OCC
    # with a short critical section is enough and TTL claims are not needed.
    state_version: int = 0
