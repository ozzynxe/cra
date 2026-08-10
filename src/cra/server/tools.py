"""MCP tool registration.

Thin wrappers: each tool marshals arguments and calls `dispatch`. The
annotation taxonomy is carried over from Coauthor's `server/tools.py` — clients
use `readOnlyHint` / `destructiveHint` to decide what to auto-approve, so
getting these right is what keeps a compliance tool from silently recording a
legal statement.

Docstrings are the agent-facing UX. They decide whether the model reaches for
the tool at all, so they're written for the situations a developer is actually
in ("we just found out we're being exploited"), not as API reference.
"""

from __future__ import annotations

from typing import Optional

from mcp.types import ToolAnnotations

from cra.agents import dispatch as dispatcher
from cra.server import handlers  # noqa: F401 — import registers the handlers


def _annot(title: str, kind: ToolAnnotations) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=kind.readOnlyHint,
        destructiveHint=kind.destructiveHint,
        idempotentHint=kind.idempotentHint,
        openWorldHint=kind.openWorldHint,
    )


_READ_LOCAL = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)

_WRITE_ADDITIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)

# Writes that make or close a legal statement — recording a submission,
# freezing a technical file, signing a Declaration of Conformity. Marked
# destructive so clients prompt rather than auto-approving: these are not
# undoable in any sense that matters to a regulator.
_WRITE_LEGAL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)

# Hands back a URL for the user to open on somebody else's site. Not read-only
# — it creates a Stripe session — but nothing here is destructive and nothing
# is charged until the user acts on the link. `openWorldHint` because the call
# leaves this service entirely.
_EXTERNAL_LINK = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)

# An additive write that also queries the public internet — `scan_advisories`
# sends component names, ecosystems and versions to OSV. Same field values as
# `_EXTERNAL_LINK` and deliberately a separate name: these are different
# categories, and collapsing them would lose the reason either one is set.
# `openWorldHint` is not decoration here. It is the only annotation that tells
# a client this tool talks to a third party, and the privacy page makes a
# specific promise about what that call carries.
_WRITE_REMOTE_QUERY = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)


def register_tools(mcp, actor_id: str, product_id_default: Optional[str] = None) -> None:
    """Register tools on a FastMCP instance with `actor_id` closure-bound.

    `actor_id` comes from the mount, not from the model — an agent cannot claim
    to be someone else. When a `coauth_*` token is used, auth middleware
    overrides both values via contextvars (see `agents/dispatch._resolve_identity`).
    """

    def _pid(product_id: Optional[str]) -> str:
        return product_id if product_id is not None else (product_id_default or "")

    @mcp.tool(annotations=_annot("CRA overview", _READ_LOCAL))
    def cra_overview() -> dict:
        """**Use this first** when the user mentions the Cyber Resilience Act,
        CRA compliance, CE marking for software, vulnerability reporting
        deadlines, or an EU regulatory obligation for a product they ship.

        Explains what this server does, the statutory dates, and the 24h / 72h /
        14-day reporting clocks. Cheap, no state read, safe to re-invoke.

        Not a regulation-text lookup — it won't quote the CRA at you.
        """
        return dispatcher.dispatch("cra_overview", "", actor_id, {})

    @mcp.tool(annotations=_annot("List products", _READ_LOCAL))
    def list_products() -> dict:
        """List the products this user tracks for CRA compliance, with each
        one's class and lifecycle. Works without a product id — use it to find
        the right `product_id` before any other call."""
        return dispatcher.dispatch("list_products", "", actor_id, {})

    @mcp.tool(annotations=_annot("Get compliance status", _READ_LOCAL))
    def get_compliance_status(product_id: Optional[str] = None) -> dict:
        """The workhorse read. Returns, in this order: **open reporting
        deadlines with time remaining**, classification and conformity route,
        requirement coverage, and members.

        Call this at the start of any CRA conversation — one call surfaces
        anything urgent, so you don't need to ask the user whether a clock is
        running.
        """
        return dispatcher.dispatch(
            "get_compliance_status", _pid(product_id), actor_id, {}
        )

    @mcp.tool(annotations=_annot("Create product", _WRITE_ADDITIVE))
    def create_product(
        name: str,
        description: str = "",
        intended_use: str = "",
        economic_operator_role: str = "manufacturer",
    ) -> dict:
        """Start tracking a product for CRA compliance.

        `economic_operator_role` is one of `manufacturer`,
        `authorised_representative`, `importer`, `distributor`,
        `open_source_steward` — it decides which obligations apply, so it is
        not a permission level. Ask the user rather than assuming
        `manufacturer`; an open-source steward has a genuinely lighter regime.

        Creates the product with classification undetermined. Nothing is
        assessed until `classify_product` runs.
        """
        return dispatcher.dispatch(
            "create_product",
            "",
            actor_id,
            {
                "name": name,
                "description": description,
                "intended_use": intended_use,
                "economic_operator_role": economic_operator_role,
            },
        )

    # ---- vulnerabilities and the reporting clocks ----------------------------

    @mcp.tool(annotations=_annot("Record vulnerability", _WRITE_ADDITIVE))
    def record_vulnerability(
        summary: str,
        product_id: Optional[str] = None,
        identifier: Optional[str] = None,
        affected_component: Optional[str] = None,
        discovered_at: Optional[str] = None,
        actively_exploited: bool = False,
        became_aware_at: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
    ) -> dict:
        """Record a vulnerability in this product.

        **Set `actively_exploited=true` if there is any evidence the flaw is
        being exploited in the wild.** That single flag is what the CRA's
        reporting duty turns on — not severity — and setting it opens an
        incident and starts a 24-hour clock automatically. If you are unsure
        whether exploitation is confirmed, say so to the user and ask; do not
        quietly leave it false.

        **When exploitation is involved, ask when they became aware and pass
        `became_aware_at`.** The Article 14 clocks run from awareness, not from
        the moment this gets recorded, and teams routinely find out on a Friday
        and log it on a Monday. Omit it and the clocks anchor at now — which
        makes deadlines look further away than they legally are, and can report
        someone as on time when they are already late. Ask; do not assume it
        just happened.

        `became_aware_at` and `discovered_at` are different moments: the second
        is when you learned the flaw exists, the first is when you learned it
        was being exploited. Only the first starts a clock. Both are ISO 8601
        **with a timezone** (`2026-09-01T14:00:00Z`).

        `identifier` is a CVE or GHSA id if one exists. `affected_component` is
        best given as a package URL (purl).
        """
        return dispatcher.dispatch(
            "record_vulnerability",
            _pid(product_id),
            actor_id,
            {
                "summary": summary,
                "identifier": identifier,
                "affected_component": affected_component,
                "discovered_at": discovered_at,
                "actively_exploited": actively_exploited,
                "became_aware_at": became_aware_at,
                "severity": severity,
                "source": source,
            },
        )

    @mcp.tool(annotations=_annot("Update vulnerability", _WRITE_ADDITIVE))
    def update_vulnerability(
        vulnerability_id: str,
        product_id: Optional[str] = None,
        actively_exploited: Optional[bool] = None,
        status: Optional[str] = None,
        remediation_ref: Optional[str] = None,
        corrective_measure_available_at: Optional[str] = None,
        became_aware_at: Optional[str] = None,
        awareness_rationale: str = "",
    ) -> dict:
        """Update a known vulnerability.

        Three arguments have legal consequences:

        - `actively_exploited=true` — flipping this from false opens an
          incident and starts the 24h / 72h clocks. Call it the moment
          exploitation is confirmed, before doing anything else — and pass
          `became_aware_at` if they knew before now.
        - `became_aware_at` — ISO 8601 with a timezone. Alongside
          `actively_exploited=true` it anchors the new clocks. On a
          vulnerability whose incident already exists it **moves** the anchor
          and recomputes every unsubmitted deadline, which needs
          `awareness_rationale` saying what established the earlier date.
          Use it when a clock was anchored at recording time by default and
          the real moment was earlier.
        - `corrective_measure_available_at` — the moment a fix or mitigation
          became available to users. The final report's 14 days run from this,
          so that deadline does not exist until you supply it. **It records
          what happened, not what is planned**, and a date in the future is
          refused for the same reason as a future `became_aware_at`: it would
          mark a mitigation available when there is none, and start a statutory
          clock from an event that has not occurred. Leave it unset until the
          fix is actually out.

        Re-anchoring can put a deadline in the past. That is the honest
        outcome: tell the user plainly what is now overdue and that filing late
        beats filing later.

        `remediation_ref` takes a commit SHA, advisory URL, or release tag.
        """
        return dispatcher.dispatch(
            "update_vulnerability",
            _pid(product_id),
            actor_id,
            {
                "vulnerability_id": vulnerability_id,
                "actively_exploited": actively_exploited,
                "status": status,
                "remediation_ref": remediation_ref,
                "corrective_measure_available_at": corrective_measure_available_at,
                "became_aware_at": became_aware_at,
                "awareness_rationale": awareness_rationale,
            },
        )

    @mcp.tool(annotations=_annot("Report incident", _WRITE_ADDITIVE))
    def report_incident(
        product_id: Optional[str] = None,
        kind: str = "severe_incident",
        became_aware_at: Optional[str] = None,
        description: str = "",
        severity: Optional[str] = None,
    ) -> dict:
        """Open a reportable incident and start its statutory clocks.

        Use this when the user says something like "we've been breached", "our
        product is being exploited", or "we had a security incident affecting
        the product we ship".

        `kind` is `severe_incident` (an incident affecting product security) or
        `actively_exploited_vuln` — though for the latter, prefer
        `record_vulnerability(actively_exploited=true)`, which links the record.

        **`became_aware_at` is the most consequential argument here.** Every
        deadline derives from it, so ask the user when they actually became
        aware rather than defaulting to now — teams routinely record an
        incident hours later, and back-dating honestly is what the regulation
        expects. ISO 8601 with a timezone.
        """
        return dispatcher.dispatch(
            "report_incident",
            _pid(product_id),
            actor_id,
            {
                "kind": kind,
                "became_aware_at": became_aware_at,
                "description": description,
                "severity": severity,
            },
        )

    @mcp.tool(annotations=_annot("Get reporting deadlines", _READ_LOCAL))
    def get_reporting_deadlines(
        product_id: Optional[str] = None,
        include_submitted: bool = False,
    ) -> dict:
        """Open reporting obligations, soonest first, with hours remaining.

        **Omit `product_id` to see everything due across every product this
        user owns** — the right call when someone asks "is anything due?" or
        when you have just been told about an incident and want to know what
        else is already running.
        """
        return dispatcher.dispatch(
            "get_reporting_deadlines",
            product_id or "",
            actor_id,
            {"include_submitted": include_submitted},
        )

    @mcp.tool(annotations=_annot("Draft SRP report", _WRITE_ADDITIVE))
    def draft_report(
        incident_id: str,
        product_id: Optional[str] = None,
        stage: str = "early_warning",
        values: Optional[dict] = None,
        template_version: str = "v1",
    ) -> dict:
        """Render one stage of a CRA report in ENISA's Single Reporting
        Platform field layout, ready to paste in.

        `stage` is `early_warning` (24h), `notification` (72h) or `final`.

        **Always produces a draft.** ENISA's own posture on the early warning
        is "send what you know, then follow up", so missing fields come back in
        `missing_required` alongside the draft, never instead of it. Do not
        withhold the output while you collect more from the user — give them
        the draft first, then the gap list.

        Fields marked copy-forward in ENISA's template are pre-populated from
        the previous stage's draft, so the 72-hour notification is an edit
        rather than a retype. Pass `values` as `{field_id: text}` to supply
        narrative the record doesn't hold — the ids are in the returned draft.

        This does not submit. The user files it themselves under their EU
        Login, then calls `record_report_submission`.
        """
        return dispatcher.dispatch(
            "draft_report",
            _pid(product_id),
            actor_id,
            {
                "incident_id": incident_id,
                "stage": stage,
                "values": values,
                "template_version": template_version,
            },
        )

    @mcp.tool(annotations=_annot("Check reporting readiness", _READ_LOCAL))
    def check_reporting_readiness(product_id: Optional[str] = None) -> dict:
        """Can this team actually file a report today?

        Checks the prerequisites that take days and cannot be done inside a
        24-hour window: EU Login enrolment, SRP registration, the submitting
        legal entity's name, Member States of availability, a security contact.

        Worth running proactively when a user first sets up a product — the
        whole point is that none of this is discovered mid-incident.
        """
        return dispatcher.dispatch(
            "check_reporting_readiness", _pid(product_id), actor_id, {}
        )

    @mcp.tool(annotations=_annot("Set submitter profile", _WRITE_ADDITIVE))
    def set_submitter_profile(
        product_id: Optional[str] = None,
        legal_name: Optional[str] = None,
        postal_address: Optional[str] = None,
        member_states_available: Optional[list[str]] = None,
        eu_login_registered: Optional[bool] = None,
        srp_registered: Optional[bool] = None,
        security_contact: Optional[str] = None,
        disclosure_policy_url: Optional[str] = None,
    ) -> dict:
        """Record who files reports for this product, and whether they can yet.

        `legal_name` is the registered name of the manufacturer or open-source
        steward — obligatory on every report, so without it nothing can be
        filed. `postal_address` is the other half of Annex V(2), which asks for
        name **and** address: the EU Declaration of Conformity cannot complete
        that field without it, and a name on its own leaves an expressly
        required element out of a signed document. `member_states_available`
        takes ISO country codes and is what routes a report to the right
        national CSIRT.

        Only the arguments you pass are changed; the rest are left alone.
        """
        return dispatcher.dispatch(
            "set_submitter_profile",
            _pid(product_id),
            actor_id,
            {
                "legal_name": legal_name,
                "postal_address": postal_address,
                "member_states_available": member_states_available,
                "eu_login_registered": eu_login_registered,
                "srp_registered": srp_registered,
                "security_contact": security_contact,
                "disclosure_policy_url": disclosure_policy_url,
            },
        )

    # ---- proactive detection --------------------------------------------------

    @mcp.tool(annotations=_annot("Scan for exploited vulnerabilities", _WRITE_REMOTE_QUERY))
    def scan_advisories(product_id: Optional[str] = None) -> dict:
        """Check the components in this product's SBOM against OSV advisories
        and CISA's Known Exploited Vulnerabilities catalogue.

        Needs an SBOM on file (`record_sbom`) — that is where the component list
        comes from. Runs automatically once a day too; this is for when the user
        wants an answer now.

        **Read the result carefully before summarising it.** `sources_ok: false`
        means a feed could not be reached and nothing was ruled out — never
        report that as a clean scan. `coverage` says how many components could
        actually be checked; components with no version or an unsupported
        ecosystem are not covered, and are not thereby safe.
        """
        return dispatcher.dispatch("scan_advisories", _pid(product_id), actor_id, {})

    @mcp.tool(annotations=_annot("List advisory candidates", _READ_LOCAL))
    def list_advisory_candidates(
        product_id: Optional[str] = None,
        filter: str = "open",
    ) -> dict:
        """Advisories matching components this product ships, exploited first.

        `filter` is `open`, `exploited`, `confirmed`, `dismissed` or `all`.

        A candidate is a match between an advisory and a version string in the
        SBOM — **not** a finding that the product is affected. Vendored patches,
        unreachable code and over-broad version ranges all produce false
        positives. Work through them with the user: `confirm_advisory` when the
        product really is affected, `dismiss_advisory` with a VEX justification
        when it is not.

        **`actively_exploited` is not the dividing line between important and
        unimportant.** It marks the Article 14 set — Art 3(42), reliable
        evidence someone has used it — which carries a 24-hour reporting clock.
        The others still matter: Annex I Pt I(2)(a) bars placing a product on
        the market with a known *exploitable* vulnerability, defined in Art
        3(41) as having the potential to be effectively used by an adversary
        under practical operational conditions. Whether anyone has used it yet
        is a different question. Do not describe the non-exploited ones as a
        backlog.

        An empty list means these feeds know of nothing today. Do not present it
        as a clean bill of health.
        """
        return dispatcher.dispatch(
            "list_advisory_candidates", _pid(product_id), actor_id, {"filter": filter}
        )

    @mcp.tool(annotations=_annot("Confirm an advisory affects us", _WRITE_LEGAL))
    def confirm_advisory(
        candidate_id: str,
        rationale: str,
        product_id: Optional[str] = None,
        became_aware_at: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> dict:
        """Record that this advisory really does affect the product.

        For an actively exploited advisory **this starts the Article 14 clocks**
        — an incident opens and the 24h/72h deadlines are created. Only call it
        once the user has actually checked, and put what they checked in
        `rationale`.

        **A feed match is not that check, and "the scanner found it" is not a
        rationale.** A candidate is a match between an advisory and a version
        string in the bill of materials. What turns it into a determination is
        knowledge the feed does not have: the version actually shipped, whether
        the vulnerable code path is reachable, how it is configured. If the user
        has not established that, ask them before calling this — the reply
        attributes the determination to them and, for an exploited advisory,
        notifies a CSIRT on it.

        Awareness defaults to when this service notified them, not now. That is
        deliberate and usually correct: the clock runs from awareness, and the
        notification is the earliest defensible moment. Pass `became_aware_at`
        only if there is a reason the later date is right, and expect to justify
        it.
        """
        return dispatcher.dispatch(
            "confirm_advisory",
            _pid(product_id),
            actor_id,
            {
                "candidate_id": candidate_id,
                "rationale": rationale,
                "became_aware_at": became_aware_at,
                "summary": summary,
            },
        )

    @mcp.tool(annotations=_annot("Dismiss an advisory candidate", _WRITE_ADDITIVE))
    def dismiss_advisory(
        candidate_id: str,
        justification: str,
        note: str,
        product_id: Optional[str] = None,
    ) -> dict:
        """Record that this advisory does not affect the product, and why.

        `justification` is one of the standard VEX categories:
        `component_not_present`, `vulnerable_code_not_present`,
        `vulnerable_code_not_in_execute_path`,
        `vulnerable_code_cannot_be_controlled_by_adversary`,
        `inline_mitigations_already_exist`, `false_positive`.

        `note` says why that category applies here — the category is the shape
        of the reason, the note is the reason. Both are required.

        This is not paperwork to get past. Those categories are statements that
        the vulnerability lacks "the potential to be effectively used by an
        adversary under practical operational conditions" — which is Art
        3(41)'s definition of *exploitable*. So a dismissal is an exploitability
        determination under Annex I Pt I(2)(a), and the record that the product
        was placed on the market without a known exploitable vulnerability. It
        is also Annex I Pt II(2) evidence of vulnerability handling.

        Dismissing something CISA lists as exploited is a much stronger claim
        again: make sure the note would hold up read after an incident.
        """
        return dispatcher.dispatch(
            "dismiss_advisory",
            _pid(product_id),
            actor_id,
            {
                "candidate_id": candidate_id,
                "justification": justification,
                "note": note,
            },
        )

    # ---- the Article 13(2) risk assessment ------------------------------------

    @mcp.tool(annotations=_annot("Start risk assessment", _WRITE_ADDITIVE))
    def start_risk_assessment(
        product_id: Optional[str] = None,
        method: Optional[str] = None,
        intended_purpose: Optional[str] = None,
        foreseeable_misuse: Optional[str] = None,
        conditions_of_use: Optional[str] = None,
        support_duration_note: Optional[str] = None,
        scope_note: Optional[str] = None,
        part_i_1_approach: Optional[str] = None,
        part_ii_approach: Optional[str] = None,
    ) -> dict:
        """**Do this before working the Annex I checklist.** Opens the Article
        13(2) cybersecurity risk assessment.

        Annex I Part I requirements apply *on the basis of* this assessment,
        and Annex VII(3) requires the assessment itself in the technical file.
        Answering requirements first inverts the regulation's own order and
        leaves every applicability decision resting on nothing.

        Returns the scope frame to fill in, the Part I requirements to map
        risks onto, and guidance on drafting. **You do the drafting** — you can
        see the codebase, the dependency manifest, the deployment topology and
        the auth model, which is exactly the material a risk assessment is made
        from. Ask the user about what you cannot observe: who uses it, where it
        runs, what it connects to, what would genuinely hurt if it failed.

        Two of the fields are not scope and are easy to miss. Article 13(3)
        requires the assessment to *also* indicate how Annex I Part I(1) — an
        appropriate level of cybersecurity based on the risks — and the Part II
        vulnerability handling requirements are applied. The risks you draft
        answer Part I(2); `part_i_1_approach` and `part_ii_approach` are the
        rest of the paragraph, they are statements about the whole product
        rather than any one risk, and confirming is refused without them.

        Call it again at any time to update the scope fields; on a confirmed
        assessment that opens the next version, leaving the previous one frozen.
        """
        return dispatcher.dispatch(
            "start_risk_assessment",
            _pid(product_id),
            actor_id,
            {
                "method": method,
                "intended_purpose": intended_purpose,
                "foreseeable_misuse": foreseeable_misuse,
                "conditions_of_use": conditions_of_use,
                "support_duration_note": support_duration_note,
                "scope_note": scope_note,
                "part_i_1_approach": part_i_1_approach,
                "part_ii_approach": part_ii_approach,
            },
        )

    @mcp.tool(annotations=_annot("Propose risks", _WRITE_ADDITIVE))
    def propose_risks(
        risks: list[dict],
        basis: str,
        product_id: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        """Submit the risks you have drafted. **They determine nothing.**

        Each risk is an object; only `title` is required, but an entry an
        auditor can use has `asset`, `threat`, `attack_vector`,
        `preconditions`, `impact`, and `affects_requirements` — the Annex I
        Part I requirement ids this risk makes applicable. Optionally
        `severity` (low/medium/high/critical), `likelihood`
        (unlikely/possible/likely), `treatment`
        (mitigate/accept/transfer/avoid), `mitigation_note`, `residual_note`.

        `basis` says what you drafted from — repository and commit, the
        architecture, the SBOM, what the user told you. It is recorded as the
        provenance of the draft.

        Everything arrives as `proposed` and marked as drafted by you. Present
        the result to the user **as your draft, not as findings**, and walk
        them through `decide_risk` for each one. Do not pad the list: every
        entry has to be individually decided, and twenty generic risks bury the
        three real ones.
        """
        return dispatcher.dispatch(
            "propose_risks",
            _pid(product_id),
            actor_id,
            {"risks": risks, "basis": basis, "model": model},
        )

    @mcp.tool(annotations=_annot("Decide on a risk", _WRITE_LEGAL))
    def decide_risk(
        risk_id: str,
        decision: str,
        rationale: str,
        product_id: Optional[str] = None,
        severity: Optional[str] = None,
        likelihood: Optional[str] = None,
        treatment: Optional[str] = None,
        affects_requirements: Optional[list[str]] = None,
        mitigation_note: Optional[str] = None,
        residual_note: Optional[str] = None,
    ) -> dict:
        """Accept or reject one drafted risk. This is the act that counts.

        `decision` is `accept` or `reject`. `rationale` is mandatory — for a
        risk you drafted, it is the only record that a person actually
        considered it rather than waving it through.

        Accepting requires a `treatment`. "We are living with this" is a
        legitimate answer (`treatment='accept'` with the reasoning), but it has
        to be a recorded decision rather than an omission.

        **Get the user's actual answer for each one.** Do not accept your own
        proposals on their behalf, and do not batch them past the user as a
        formality — accepting a risk is what makes Annex I requirements
        applicable, and rejecting one is a statement that this threat does not
        apply to their product.
        """
        return dispatcher.dispatch(
            "decide_risk",
            _pid(product_id),
            actor_id,
            {
                "risk_id": risk_id,
                "decision": decision,
                "rationale": rationale,
                "severity": severity,
                "likelihood": likelihood,
                "treatment": treatment,
                "affects_requirements": affects_requirements,
                "mitigation_note": mitigation_note,
                "residual_note": residual_note,
            },
        )

    @mcp.tool(annotations=_annot("Confirm risk assessment", _WRITE_LEGAL))
    def confirm_risk_assessment(
        rationale: str,
        product_id: Optional[str] = None,
    ) -> dict:
        """Freeze this version of the assessment and set applicability from it.

        Refuses while any risk is still undecided — confirming would freeze a
        draft into a ten-year artifact as though it had been reviewed.

        What it does to the checklist: requirements named by **accepted** risks
        become `applicable`, carrying the risk ids as their basis. Everything
        else stays `undetermined`, which still counts as a gap. **It never
        marks anything not_applicable** — ruling a requirement out remains a
        deliberate decision with a justification, made through
        `update_requirement`.

        Only call this once the user has genuinely reviewed the assessment.
        """
        return dispatcher.dispatch(
            "confirm_risk_assessment",
            _pid(product_id),
            actor_id,
            {"rationale": rationale},
        )

    @mcp.tool(annotations=_annot("Get risk assessment", _READ_LOCAL))
    def get_risk_assessment(
        product_id: Optional[str] = None,
        include_rejected: bool = True,
        verbose: bool = False,
    ) -> dict:
        """The assessment as it stands: scope, risks, and whether it is stale.

        `stale_reasons` is the one to check — an assessment confirmed against a
        different product class or lifecycle no longer describes what ships,
        and Article 13(3) requires it kept up to date across the support
        period.
        """
        return dispatcher.dispatch(
            "get_risk_assessment",
            _pid(product_id),
            actor_id,
            {"include_rejected": include_rejected, "verbose": verbose},
        )

    # ---- scope, evidence, and the team ---------------------------------------

    @mcp.tool(annotations=_annot("Classify product", _WRITE_LEGAL))
    def classify_product(
        product_id: Optional[str] = None,
        product_class: Optional[str] = None,
        in_scope: Optional[bool] = None,
        annex_iii_category: Optional[str] = None,
        rationale: str = "",
    ) -> dict:
        """Decide, with the user, which CRA class a product falls in — then
        record it.

        **Call it without `product_class` first.** That writes nothing and
        returns the Annex III / Annex IV category lists plus the out-of-scope
        tests, so you and the user can work the question through. Only then call
        it again with `product_class` to record the answer.

        (This said "with no arguments", which fails on the first session of a
        new account — the most common session this tool has — because
        `product_id` is still needed to say which product you are asking about.)

        `product_class` is `default`, `important_class_i`, `important_class_ii`
        or `critical`. `rationale` is mandatory and should say which category
        matched and why — it is what a human re-checks later.

        **Never infer the class from the product's name or your own guess about
        what it does.** This decides whether a notified body is required, and a
        product wrongly recorded as `default` looks settled to everyone who
        reads it afterwards. Ask the user what the product actually does. Where
        two categories arguably fit, take the higher one and say so.

        The result is indicative — it records a decision and spells out its
        consequences; it is not a conformity determination.
        """
        return dispatcher.dispatch(
            "classify_product",
            _pid(product_id),
            actor_id,
            {
                "product_class": product_class,
                "in_scope": in_scope,
                "annex_iii_category": annex_iii_category,
                "rationale": rationale,
            },
        )

    @mcp.tool(annotations=_annot("Which CSIRT", _READ_LOCAL))
    def get_applicable_csirt(product_id: Optional[str] = None) -> dict:
        """Where this product's Article 14 reports go, and what determines it.

        Short answer: the Single Reporting Platform routes on your registered
        main establishment, so there is no per-report recipient to choose. Use
        this when a user asks "who do we actually report to".
        """
        return dispatcher.dispatch(
            "get_applicable_csirt", _pid(product_id), actor_id, {}
        )

    @mcp.tool(annotations=_annot("Record SBOM", _WRITE_ADDITIVE))
    def record_sbom(
        sbom: str,
        product_id: Optional[str] = None,
        sbom_format: str = "cyclonedx",
        component_count: Optional[int] = None,
        source_ref: Optional[str] = None,
        version: Optional[str] = None,
    ) -> dict:
        """Store a software bill of materials as evidence for Annex I Pt II(1).

        Pass the SBOM document itself, not a path or URL — it is stored by
        value and hashed, because a link evidences nothing in ten years' time
        and that is how long the technical file is kept.

        `sbom_format` is `cyclonedx` or `spdx`. `source_ref` should identify
        the build it describes (git SHA, CI run URL), since the obligation
        attaches to what you shipped.
        """
        return dispatcher.dispatch(
            "record_sbom",
            _pid(product_id),
            actor_id,
            {
                "sbom": sbom,
                "sbom_format": sbom_format,
                "component_count": component_count,
                "source_ref": source_ref,
                "version": version,
            },
        )

    @mcp.tool(annotations=_annot("Add member", _WRITE_ADDITIVE))
    def add_member(
        email: str,
        product_id: Optional[str] = None,
        role: str = "editor",
    ) -> dict:
        """Add a teammate to this product by email, so their own agent can
        work on it.

        `role` is `owner`, `maintainer`, `editor`, `commenter` or `viewer`.
        Each member connects with their own token, which is what lets the audit
        trail name the human accountable for a change rather than only the
        agent that made it — so the answer to "two of us need to work on this"
        is this tool, never a shared token. Members also receive this product's
        deadline alerts. Owner only.

        If the address has no account yet they are emailed an invitation and
        join automatically when they sign up. The reply is the same either way,
        so it never reveals whether someone already has an account.

        Everyone on a product works under the **owner's** plan, so adding a
        colleague does not require them to buy anything.
        """
        return dispatcher.dispatch(
            "add_member",
            _pid(product_id),
            actor_id,
            {"email": email, "role": role},
        )

    @mcp.tool(annotations=_annot("Remove member", _WRITE_LEGAL))
    def remove_member(user_id: str, product_id: Optional[str] = None) -> dict:
        """Remove a teammate's access to this product. Owner only.

        Their past actions stay in the audit trail — that record is retained
        for ten years and is not the manufacturer's to edit.
        """
        return dispatcher.dispatch(
            "remove_member", _pid(product_id), actor_id, {"user_id": user_id}
        )

    @mcp.tool(annotations=_annot("Get recent activity", _READ_LOCAL))
    def get_recent_activity(
        product_id: Optional[str] = None,
        limit: int = 30,
        since: Optional[str] = None,
    ) -> dict:
        """What changed on this product, newest first, and who is accountable.

        The "what did my teammates' agents do while I was away" read. Comes
        straight from the audit trail, so it shows exactly what an auditor
        would see. `since` is ISO 8601 with a timezone.
        """
        return dispatcher.dispatch(
            "get_recent_activity",
            _pid(product_id),
            actor_id,
            {"limit": limit, "since": since},
        )

    # ---- Annex I checklist and evidence --------------------------------------

    @mcp.tool(annotations=_annot("List requirements", _READ_LOCAL))
    def list_requirements(
        product_id: Optional[str] = None,
        filter: str = "all",
        verbose: bool = False,
    ) -> dict:
        """The product's Annex I checklist.

        `filter` is `all`, `gaps`, `part_i` (product security properties) or
        `part_ii` (vulnerability handling processes). **Start with `gaps`** —
        it returns only what would leave a hole in the technical file, which is
        the useful question almost every time.

        Each entry carries `last_edited_by` and `last_edited_at`, so when
        several developers' agents work the same product you can see what a
        teammate touched minutes ago and route around it.
        """
        return dispatcher.dispatch(
            "list_requirements",
            _pid(product_id),
            actor_id,
            {"filter": filter, "verbose": verbose},
        )

    @mcp.tool(annotations=_annot("Update requirement", _WRITE_ADDITIVE))
    def update_requirement(
        req_id: str,
        product_id: Optional[str] = None,
        applicability: Optional[str] = None,
        justification: Optional[str] = None,
        status: Optional[str] = None,
        implementation_note: Optional[str] = None,
    ) -> dict:
        """Record how one Annex I requirement applies and where it has got to.

        `applicability` is `applicable`, `not_applicable` or `undetermined`.
        `status` is `not_started`, `in_progress`, `implemented` or `verified`.

        **`not_applicable` requires a `justification`** and is refused without
        one. An auditor reads the justification, not the flag, and a
        requirement waved away with no reasoning is the most common finding in
        a thin technical file. Write why it does not apply *to this product* —
        "we don't do that" is not a justification.

        A requirement is not settled until it is implemented or verified *and*
        has evidence attached; use `attach_evidence` for the artifact.
        """
        return dispatcher.dispatch(
            "update_requirement",
            _pid(product_id),
            actor_id,
            {
                "req_id": req_id,
                "applicability": applicability,
                "justification": justification,
                "status": status,
                "implementation_note": implementation_note,
            },
        )

    @mcp.tool(annotations=_annot("Attach evidence", _WRITE_ADDITIVE))
    def attach_evidence(
        subject_ref: str,
        title: str,
        body: str,
        source_ref: str,
        product_id: Optional[str] = None,
        kind: str = "document",
        content_type: str = "text/plain",
        applies_to_version: Optional[str] = None,
    ) -> dict:
        """Attach a hashed artifact to a requirement, vulnerability, obligation
        or technical-file section.

        `subject_ref` is `<kind>:<id>` — `requirement:annex_i.i.2.a`,
        `vuln:<id>`, `obligation:<id>`, `technical_file:tf.3`.

        Pass the artifact itself as `body`; it is stored by value and hashed,
        because a link evidences nothing in ten years and that is how long the
        file is retained. `source_ref` is mandatory and says where it came from
        — a git SHA, a CI run URL, a tool name and version. Provenance is what
        makes it evidence rather than an assertion.

        `applies_to_version` is the release this artifact is a claim about.
        Leave it out and it ties to the latest recorded release — the reply
        says which — since you are normally evidencing what you have now. Pass
        it when back-filling evidence for an older release.
        """
        return dispatcher.dispatch(
            "attach_evidence",
            _pid(product_id),
            actor_id,
            {
                "subject_ref": subject_ref,
                "title": title,
                "body": body,
                "source_ref": source_ref,
                "kind": kind,
                "content_type": content_type,
                "applies_to_version": applies_to_version,
            },
        )

    @mcp.tool(annotations=_annot("List evidence", _READ_LOCAL))
    def list_evidence(
        product_id: Optional[str] = None,
        subject_ref: Optional[str] = None,
        limit: int = 50,
    ) -> dict:
        """Evidence on file, newest first, optionally for one `subject_ref`."""
        return dispatcher.dispatch(
            "list_evidence",
            _pid(product_id),
            actor_id,
            {"subject_ref": subject_ref, "limit": limit},
        )

    # ---- conformity ----------------------------------------------------------

    @mcp.tool(annotations=_annot("List Annex II user information", _READ_LOCAL))
    def list_user_information(
        product_id: Optional[str] = None,
        filter: str = "all",
    ) -> dict:
        """The Annex II checklist — what must **accompany** the product.

        Different audience from everything else here: the technical file is for
        market surveillance authorities, this is what a user receives. Article
        13(18) requires it in paper or electronic form, in a language its users
        can easily understand, kept available for ten years or the support
        period.

        `filter` is `all`, `gaps`, or `conditional` — the four items the annex
        itself qualifies with "where applicable" or "if the manufacturer
        decides".
        """
        return dispatcher.dispatch(
            "list_user_information", _pid(product_id), actor_id, {"filter": filter}
        )

    @mcp.tool(annotations=_annot("Update Annex II item", _WRITE_ADDITIVE))
    def update_user_information(
        item_id: str,
        product_id: Optional[str] = None,
        provided: Optional[bool] = None,
        not_applicable: Optional[bool] = None,
        justification: Optional[str] = None,
        location: Optional[str] = None,
        note: Optional[str] = None,
    ) -> dict:
        """Record whether an Annex II item accompanies the product, and where.

        `location` is the useful half — a manual section, a page, a URL. "We
        provide it" is an assertion; where a user finds it is the thing an
        auditor checks.

        `not_applicable` needs a `justification`. Four items are conditional in
        the annex's own words, so ruling one out is often right — which is
        exactly why the reason has to be recorded, or "where applicable"
        becomes a way to empty the annex.
        """
        return dispatcher.dispatch(
            "update_user_information",
            _pid(product_id),
            actor_id,
            {
                "item_id": item_id,
                "provided": provided,
                "not_applicable": not_applicable,
                "justification": justification,
                "location": location,
                "note": note,
            },
        )

    @mcp.tool(annotations=_annot("Simplified Declaration of Conformity", _WRITE_LEGAL))
    def generate_simplified_declaration(
        full_declaration_url: str,
        product_id: Optional[str] = None,
    ) -> dict:
        """The Article 13(20) short form, for shipping with the product.

        13(20) lets you provide a simplified declaration **instead of** a copy
        of the full one, on one condition: it must contain the exact internet
        address at which the full declaration can be accessed. So the full
        declaration has to exist first, and it has to be published somewhere
        durable — that address is the entire reason the short form is allowed.

        The address is recorded exactly as given and **never fetched**. This
        tool cannot confirm the declaration is published there or that it stays
        there; keeping it reachable is yours.
        """
        return dispatcher.dispatch(
            "generate_simplified_declaration",
            _pid(product_id),
            actor_id,
            {"full_declaration_url": full_declaration_url},
        )

    @mcp.tool(annotations=_annot("Set support period", _WRITE_LEGAL))
    def set_support_period(
        end: str,
        rationale: str,
        product_id: Optional[str] = None,
        start: Optional[str] = None,
        expected_use_years: Optional[float] = None,
        published_url: Optional[str] = None,
    ) -> dict:
        """Record the Article 13(8) support period and the reasoning behind it.

        Both halves matter. 13(8) sets a floor of five years, *and* requires
        the information taken into account to be in the technical
        documentation — which is Annex VII(4). A date with no `rationale` fills
        the section without meeting the obligation, so the rationale is
        required: reasonable user expectations, the nature of the product,
        comparable products on the market, the support periods of components
        you depend on.

        A period under five years is refused unless you state
        `expected_use_years`, the paragraph's only exception — where the
        product is expected to be in use for less, the period corresponds to
        that. It has to be claimed, not arrived at by choosing a nearer date.

        `start` defaults to the earliest recorded release, since the period
        runs from placing on the market.
        """
        return dispatcher.dispatch(
            "set_support_period",
            _pid(product_id),
            actor_id,
            {
                "end": end,
                "start": start,
                "rationale": rationale,
                "expected_use_years": expected_use_years,
                "published_url": published_url,
            },
        )

    @mcp.tool(annotations=_annot("List releases", _READ_LOCAL))
    def list_releases(product_id: Optional[str] = None) -> dict:
        """Versions placed on the market, with the Annex I(2)(a) position at each.

        The latest one is what evidence is measured against: a requirement
        evidenced only against an earlier release reports as stale, because
        Annex I attaches to the product *as placed on the market*.
        """
        return dispatcher.dispatch("list_releases", _pid(product_id), actor_id, {})

    @mcp.tool(annotations=_annot("Record a build", _WRITE_ADDITIVE))
    def record_build(
        version: str,
        product_id: Optional[str] = None,
        built_at: Optional[str] = None,
        source_ref: str = "",
        notes: str = "",
    ) -> dict:
        """Record that a version of the product exists. Claims nothing about the market.

        Use this whenever a build is worth naming — a release candidate, an
        internal cut, something shipped to one customer under test. It is free,
        it gates on nothing and it changes no lifecycle. What it buys is an
        anchor: evidence can be attached against this version, so
        `attach_evidence(applies_to_version=...)` and the technical file's
        currency check have something real to measure against.

        **It is deliberately not a legal act.** Placing on the market starts the
        Article 13(13) retention clock, anchors the 13(8) support period and
        freezes the Annex I Pt I(2)(a) determination — none of which follows
        from a build existing. `place_on_market` is the call that does that, and
        it is the one that can refuse.

        Use `version` exactly as you build it — stored verbatim, never parsed.
        """
        return dispatcher.dispatch(
            "record_build",
            _pid(product_id),
            actor_id,
            {
                "version": version,
                "built_at": built_at,
                "source_ref": source_ref,
                "notes": notes,
            },
        )

    @mcp.tool(annotations=_annot("Place a version on the market", _WRITE_LEGAL))
    def place_on_market(
        version: str,
        product_id: Optional[str] = None,
        released_at: Optional[str] = None,
        accepted_rationale: str = "",
    ) -> dict:
        """Declare a recorded version placed on the market, freezing its I(2)(a) position.

        **Record the build first** with `record_build(version=...)`; this call
        works on a version that already exists. The two are separate because
        they assert different things: one says a build exists, this one makes a
        legal claim about the EU market that starts the Article 13(13) retention
        clock and anchors the 13(8) support period.

        Annex I Pt I(2)(a) bars placing a product on the market with a known
        exploitable vulnerability, and that is a claim about a *moment*. This is
        that moment: it checks the advisory picture, freezes the result as
        evidence tied to this version, and makes it the release everything is
        evidenced against from now on.

        It refuses when the record cannot support the claim, on two fronts.

        *The scan* — none has run, the last one could not reach its feeds, it is
        more than seven days old, or candidates are still unresolved.

        *The file* — no confirmed Article 13(2) risk assessment, one that has
        gone stale, missing Article 13(3) Part I(1)/Part II statements, or Annex
        I requirements still undetermined. Placing on the market is when working
        state becomes the record an authority can ask for, so it is checked
        here. Expect this on a first release: `start_risk_assessment` →
        `propose_risks` → `decide_risk` → `confirm_risk_assessment`, then settle
        the checklist with `update_requirement`.

        Every reason comes back at once, in `blockers`, each naming what to do.
        A refusal is **not** a finding that your product is affected.

        `accepted_rationale` proceeds anyway and is kept with the determination.
        Shipping with something outstanding is your call to make; making it in
        writing is the price. Nothing measures that reason — it is not checked
        for length or substance, because a rule that refused a short one would
        only teach people to pad it. What it does is travel: onto the frozen
        determination, into the audit trail, and back to you in the reply.

        **A release recorded that way is not a clean release, and must not be
        reported as one.** The reply says so in `note`, and carries
        `accepted_despite`, `blockers_accepted` and the rationale you gave.
        Relay it — the person you are relaying to is the one who has to stand
        behind the reason later.

        Use `version` exactly as you ship it — it is stored verbatim and never
        parsed.
        """
        return dispatcher.dispatch(
            "place_on_market",
            _pid(product_id),
            actor_id,
            {
                "version": version,
                "released_at": released_at,
                "accepted_rationale": accepted_rationale,
            },
        )

    @mcp.tool(annotations=_annot("Assemble technical file", _WRITE_LEGAL))
    def assemble_technical_file(
        product_id: Optional[str] = None,
        finalize: bool = False,
    ) -> dict:
        """The Annex VII technical file, section by section, with gaps named.

        **Read it as a gap report.** The useful output is `missing_slots`, not
        the document — run it early and often while the file is being built.

        `finalize=true` freezes a version and computes its content hash, and is
        refused while any mandatory section is empty: a frozen file with holes
        is a document that looks finished. Freeze before signing, because a
        signature binds to the hash.
        """
        return dispatcher.dispatch(
            "assemble_technical_file",
            _pid(product_id),
            actor_id,
            {"finalize": finalize},
        )

    @mcp.tool(annotations=_annot("Draft Declaration of Conformity", _WRITE_LEGAL))
    def generate_declaration_of_conformity(
        conformity_route: str,
        conformity_route_basis: str,
        product_id: Optional[str] = None,
        product_identification: Optional[str] = None,
        standards_applied: Optional[str] = None,
        notified_body: Optional[str] = None,
        standards_applied_in_full: Optional[bool] = None,
    ) -> dict:
        """Draft the Annex V EU Declaration of Conformity.

        A **draft**. Signing it is a separate, human act, and affixing the CE
        marking is another one you perform yourself. This tool cannot make a
        product conformant.

        Requires a finalized technical file — a declaration resting on a file
        that can still change means nothing. Where the product class needs a
        notified body, `notified_body` is required: Annex V(7) wants its name
        and number, the procedure performed and the certificate.

        **`conformity_route` is a claim the manufacturer makes, not something
        this tool infers.** Classification says which routes a class permits;
        only they know which one was taken. `self_assessment` is internal
        control under Module A; `notified_body` is a notified-body procedure.
        `conformity_route_basis` says what makes that route available, in the
        same way the Article 13(8) support period needs its reasoning.

        For Annex III class I, internal control is available **only** where
        harmonised standards, common specifications or a European cybersecurity
        certification scheme are applied *in full*. Applying one in part does not
        open it. Ask the user directly rather than reading it off whatever they
        wrote in `standards_applied`, and pass
        `standards_applied_in_full=true` only if they say so — the declaration is
        what CE marking rests on, and claiming a route that was not available is
        a false statement with legal weight.

        Not applicable to open-source stewards, who do not issue a declaration.
        """
        return dispatcher.dispatch(
            "generate_declaration_of_conformity",
            _pid(product_id),
            actor_id,
            {
                "product_identification": product_identification,
                "standards_applied": standards_applied,
                "notified_body": notified_body,
                "conformity_route": conformity_route,
                "conformity_route_basis": conformity_route_basis,
                "standards_applied_in_full": standards_applied_in_full,
            },
        )

    @mcp.tool(annotations=_annot("Sign off", _WRITE_LEGAL))
    def sign_off(
        signer_name: str,
        signer_role: str,
        statement: str,
        product_id: Optional[str] = None,
        subject: str = "technical_file",
        require_independent: bool = False,
    ) -> dict:
        """Record a human attestation against a frozen version.

        **Only call this when the user has explicitly told you to sign, in
        their own words.** It writes a named person's statement of
        responsibility into a record kept for ten years. Never infer it from
        "looks good" or "that's done", and never supply `signer_name` or
        `statement` yourself — ask.

        `subject` is `technical_file` or `declaration`. The signature binds to
        that version's content hash, so any later edit stops being covered and
        `get_conformity_status` will say so.

        `require_independent=true` refuses a signer who was the last person to
        change the document — use it where the organisation separates producing
        evidence from attesting to it.
        """
        return dispatcher.dispatch(
            "sign_off",
            _pid(product_id),
            actor_id,
            {
                "subject": subject,
                "signer_name": signer_name,
                "signer_role": signer_role,
                "statement": statement,
                "require_independent": require_independent,
            },
        )

    @mcp.tool(annotations=_annot("Get conformity status", _READ_LOCAL))
    def get_conformity_status(product_id: Optional[str] = None) -> dict:
        """Where this product stands on the 11 Dec 2027 obligations: requirement
        coverage, whether the technical file is frozen, whether a declaration
        exists, and which signatures still cover the current version.

        `stale_signatures` is the one to look at — a sign-off against a
        superseded hash is not a sign-off on what you ship today.
        """
        return dispatcher.dispatch(
            "get_conformity_status", _pid(product_id), actor_id, {}
        )

    @mcp.tool(annotations=_annot("Record report submission", _WRITE_LEGAL))
    def record_report_submission(
        obligation_id: str,
        product_id: Optional[str] = None,
        submitted_at: Optional[str] = None,
        submission_ref: Optional[str] = None,
        recipient: Optional[str] = None,
    ) -> dict:
        """Record that a report has been filed, closing that obligation.

        **This does not submit anything.** Submission happens on ENISA's Single
        Reporting Platform under the manufacturer's own EU Login. Only call
        this once the user confirms they have actually filed — it writes a
        statement about a legal filing into a trail kept for ten years.

        `submission_ref` is the reference the platform gave back; capture it if
        the user has it. `submitted_at` defaults to now, ISO 8601 with a
        timezone.
        """
        return dispatcher.dispatch(
            "record_report_submission",
            _pid(product_id),
            actor_id,
            {
                "obligation_id": obligation_id,
                "submitted_at": submitted_at,
                "submission_ref": submission_ref,
                "recipient": recipient,
            },
        )


    # ---- billing ------------------------------------------------------------

    @mcp.tool(annotations=_annot("Get an upgrade link", _EXTERNAL_LINK))
    def get_upgrade_link(plan: Optional[str] = None, cadence: str = "monthly") -> dict:
        """See what plans are available, or start a checkout for one.

        Call with no arguments first: it returns the current plan, what each
        paid plan lifts, and how each is billed. Call again with `plan=` to get
        a Stripe Checkout URL.

        **Give the user the URL and stop.** Never ask them for card details —
        the card is typed into Stripe's page, and this service never sees it.
        The returned link is not an upgrade: the plan moves when Stripe
        confirms payment, so tell them to run `cra_overview()` afterwards
        rather than assuming it worked.

        Prices are not returned here; they are shown on the checkout page, by
        the system that does the charging.
        """
        return dispatcher.dispatch(
            "get_upgrade_link", "", actor_id, {"plan": plan or "", "cadence": cadence}
        )

    @mcp.tool(annotations=_annot("Manage subscription", _EXTERNAL_LINK))
    def manage_subscription() -> dict:
        """A Stripe billing portal link: change the card, read invoices, or
        cancel.

        Hand the user the URL. Cancelling keeps the plan until the period
        already paid for ends — say so if they ask, because the alternative
        assumption is that cancelling cuts them off mid-obligation.
        """
        return dispatcher.dispatch("manage_subscription", "", actor_id, {})
