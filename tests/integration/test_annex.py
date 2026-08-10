"""The Annex I checklist, evidence, and the conformity chain.

The chain is the point: requirements → evidence → technical file → declaration
→ signature, with each link refusing to form before the one behind it exists.
A declaration resting on a file that can still change means nothing, and a
signature that no longer covers what you ship is worse than no signature at
all, because it looks like one.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from sqlalchemy import select  # noqa: E402

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import Attestation, AuditEvent, Evidence, User, session_scope  # noqa: E402
from cra.regulation import (  # noqa: E402
    requirements,
    technical_file_slots,
    user_information,
)
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc
REQ = "annex_i.i.2.a"  # "no known exploitable vulnerabilities"


def _user() -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def owner():
    return _user()


@pytest.fixture
def product(owner):
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Acme Gateway",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    return pid


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def scoped(product, owner):
    _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Not listed in Annex III or IV.",
    )
    return product


def _attach(product, owner, subject_ref, title="Scan report"):
    return _call(
        "attach_evidence",
        product,
        owner,
        subject_ref=subject_ref,
        title=title,
        body='{"findings": []}',
        source_ref="git:abc123",
    )


# ---- the checklist -----------------------------------------------------------


def test_an_unclassified_product_says_where_the_checklist_comes_from(product, owner):
    r = _call("list_requirements", product, owner)
    assert r["ok"] is True and r["count"] == 0
    assert "classify_product" in r["note"]


def test_everything_starts_as_a_gap(scoped, owner):
    """`undetermined` counts as a gap. Treating an unanswered requirement as
    merely 'not yet done' is how a file reaches an auditor with a third of it
    unconsidered."""
    r = _call("list_requirements", scoped, owner, filter="gaps")
    assert r["count"] == len(requirements())
    assert r["gaps_total"] == len(requirements())


def test_filters_split_the_two_parts(scoped, owner):
    part_i = _call("list_requirements", scoped, owner, filter="part_i")
    part_ii = _call("list_requirements", scoped, owner, filter="part_ii")
    assert part_i["count"] == 14 and part_ii["count"] == 8
    ids_i = {x["req_id"] for x in part_i["requirements"]}
    assert not (ids_i & {x["req_id"] for x in part_ii["requirements"]})


def test_an_unknown_filter_is_refused(scoped, owner):
    r = _call("list_requirements", scoped, owner, filter="urgent")
    assert r["ok"] is False and "part_ii" in r["error"]


def test_marking_not_applicable_without_reasoning_is_refused(scoped, owner):
    """The single most common finding in a thin technical file."""
    r = _call(
        "update_requirement", scoped, owner, req_id=REQ, applicability="not_applicable"
    )
    assert r["ok"] is False
    assert "auditor reads the justification" in r["error"]


def test_a_justification_can_arrive_with_the_flag(scoped, owner):
    r = _call(
        "update_requirement",
        scoped,
        owner,
        req_id=REQ,
        applicability="not_applicable",
        justification="No network interface; the product is an offline library.",
    )
    assert r["ok"] is True
    assert r["requirement"]["justification"].startswith("No network interface")
    # Settled, so no longer a gap.
    assert "still_a_gap" not in r


def test_justifying_later_is_also_refused_until_it_arrives(scoped, owner):
    """Guards the "set the flag now, justify later" path, which is how a bare
    flag would otherwise slip through."""
    assert (
        _call(
            "update_requirement",
            scoped,
            owner,
            req_id=REQ,
            applicability="not_applicable",
            justification="",
        )["ok"]
        is False
    )


def test_switching_back_to_applicable_clears_a_stale_justification(scoped, owner):
    _call(
        "update_requirement",
        scoped,
        owner,
        req_id=REQ,
        applicability="not_applicable",
        justification="offline library",
    )
    r = _call("update_requirement", scoped, owner, req_id=REQ, applicability="applicable")
    assert r["ok"] is True
    assert "justification" not in r["requirement"]


def test_implemented_without_evidence_is_still_a_gap(scoped, owner):
    """"We did it" is an assertion. The artifact is what makes it evidence."""
    r = _call(
        "update_requirement",
        scoped,
        owner,
        req_id=REQ,
        applicability="applicable",
        status="implemented",
    )
    assert "still_a_gap" in r["still_a_gap"] or "attach_evidence" in r["still_a_gap"]

    _attach(scoped, owner, f"requirement:{REQ}")
    after = _call("list_requirements", scoped, owner, filter="gaps")
    assert REQ not in {x["req_id"] for x in after["requirements"]}


def test_an_empty_update_is_refused(scoped, owner):
    assert _call("update_requirement", scoped, owner, req_id=REQ)["ok"] is False


def test_an_unknown_requirement_points_at_classification(scoped, owner):
    r = _call("update_requirement", scoped, owner, req_id="annex_i.i.99", status="verified")
    assert r["ok"] is False and "classify_product" in r["error"]


def test_edits_are_attributed_for_team_visibility(scoped, owner):
    """Visibility beats locking at team scale — an arriving agent can see the
    requirement was touched minutes ago and route around it."""
    _call("update_requirement", scoped, owner, req_id=REQ, status="in_progress")
    row = next(
        x
        for x in _call("list_requirements", scoped, owner)["requirements"]
        if x["req_id"] == REQ
    )
    assert row["last_edited_by"] == owner
    assert row["last_edited_at"]


# ---- evidence ----------------------------------------------------------------


def test_evidence_is_stored_by_value_and_hashed(scoped, owner):
    r = _attach(scoped, owner, f"requirement:{REQ}")
    assert r["ok"] is True and len(r["sha256"]) == 64
    with session_scope() as s:
        ev = s.get(Evidence, r["evidence_id"])
    assert ev.inline_body == '{"findings": []}'
    assert ev.source_ref == "git:abc123"


def test_evidence_without_provenance_is_refused(scoped, owner):
    r = _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref=f"requirement:{REQ}",
        title="Scan",
        body="x",
        source_ref="",
    )
    assert r["ok"] is False and "source_ref is required" in r["error"]


def test_evidence_with_no_artifact_is_refused(scoped, owner):
    r = _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref=f"requirement:{REQ}",
        title="Trust me",
        body="",
        source_ref="git:abc",
    )
    assert r["ok"] is False and "stored by value" in r["error"]


def test_a_typoed_subject_is_refused_rather_than_filed_invisibly(scoped, owner):
    """Evidence against a bad reference is in the database, absent from the
    technical file, and nobody finds out until an auditor asks."""
    r = _attach(scoped, owner, "requirement:annex_i.i.99")
    assert r["ok"] is False

    r = _attach(scoped, owner, "nonsense:1")
    assert r["ok"] is False and "subject_ref must be" in r["error"]

    r = _attach(scoped, owner, f"vuln:{uuid.uuid4()}")
    assert r["ok"] is False


def test_evidence_attaches_to_a_real_vulnerability(scoped, owner):
    vid = _call("record_vulnerability", scoped, owner, summary="parser overflow")[
        "vulnerability_id"
    ]
    assert _attach(scoped, owner, f"vuln:{vid}", title="Fix verification")["ok"] is True


def test_list_evidence_filters_by_subject(scoped, owner):
    _attach(scoped, owner, f"requirement:{REQ}", title="A")
    _attach(scoped, owner, "technical_file:tf.1", title="B")
    all_ev = _call("list_evidence", scoped, owner)
    assert all_ev["count"] == 2
    one = _call("list_evidence", scoped, owner, subject_ref=f"requirement:{REQ}")
    assert one["count"] == 1 and one["evidence"][0]["title"] == "A"


# ---- the technical file ------------------------------------------------------


def _confirm_assessment(product, owner, affects=(REQ,)):
    """Run the Article 13(2) assessment through to a confirmed version.

    Annex VII(3) needs the assessment itself, not just the checklist derived
    from it, so nothing downstream of the technical file can be reached without
    this. Kept minimal — the assessment's own behaviour is tested in
    `test_risk_assessment.py`.
    """
    _call(
        "start_risk_assessment",
        product,
        owner,
        method="STRIDE",
        intended_purpose="An API gateway fronting internal services",
        foreseeable_misuse="Exposed to the public internet without a WAF",
        conditions_of_use="Runs in the customer's own Kubernetes cluster",
        part_i_1_approach="Threat modelling each release against the accepted risks.",
        part_ii_approach="SBOM per build, daily scanning, CVD policy, Article 14 clocks here.",
    )
    _call(
        "propose_risks",
        product,
        owner,
        basis="repo at HEAD, architecture notes",
        risks=[
            {
                "title": "Unauthenticated access to the admin API",
                "asset": "administrative control plane",
                "threat": "an unauthenticated caller reconfigures routing",
                "affects_requirements": list(affects),
            }
        ],
    )
    _call(
        "decide_risk",
        product,
        owner,
        risk_id="risk-001",
        decision="accept",
        treatment="mitigate",
        rationale="Real for our deployment; mitigated by mTLS on the admin listener.",
    )
    return _call(
        "confirm_risk_assessment",
        product,
        owner,
        rationale="Reviewed with the maintainers against the shipped topology.",
    )


def _fill_file(product, owner):
    """Assess, settle every requirement, and fill every slot the honest way.

    "Honest way" is doing work now: slots carrying `satisfied_by` complete from
    a record rather than from an attachment, so filling them means calling the
    tool that makes the determination. tf.4 was the first — before
    `set_support_period` existed it could only be satisfied by attaching a
    document, which is the gap this helper used to paper over.
    """
    _confirm_assessment(product, owner)
    _call(
        "set_support_period",
        product,
        owner,
        start="2026-01-01T00:00:00Z",
        end="2031-06-30T00:00:00Z",
        rationale=(
            "Five and a half years from first shipment: comparable gateways in "
            "this segment are supported for five, and the platform we depend on "
            "has security support until mid-2031."
        ),
    )
    for req in requirements():
        _call(
            "update_requirement",
            product,
            owner,
            req_id=req.id,
            applicability="applicable",
            status="verified",
        )
        _attach(product, owner, f"requirement:{req.id}", title=f"evidence for {req.id}")
    # Annex II is worked item by item now, so filling the file means settling
    # the checklist rather than attaching a document and hoping.
    for item in user_information():
        _call(
            "update_user_information",
            product,
            owner,
            item_id=item.id,
            provided=True,
            location="docs/security.md",
        )
    for slot in technical_file_slots():
        if slot.auto_from_part or slot.satisfied_by == "support_period":
            continue
        if slot.satisfied_by == "declaration_of_conformity":
            continue
        _attach(product, owner, f"technical_file:{slot.id}", title=slot.title)


def test_an_out_of_scope_product_has_no_file_to_assemble(product, owner):
    r = _call("assemble_technical_file", product, owner)
    assert r["ok"] is False and "not recorded as in scope" in r["error"]


def test_assembly_is_a_gap_report_first(scoped, owner):
    r = _call("assemble_technical_file", scoped, owner)
    assert r["ok"] is True
    assert r["complete"] is False
    assert len(r["slots"]) == len(technical_file_slots())
    assert r["missing_slots"]
    # Retention is a rule, not a number: Article 13(13) is ten years from
    # placing on the market *or the support period, whichever is longer*. This
    # product has never been released, so the clock has not started.
    assert r["retention"]["anchor"] == "Article 13(13)"
    assert r["retention"]["until"] is None
    assert r["retention"]["basis"] == "not_yet_placed_on_market"
    assert "not a conformity assessment" in r["disclaimer"]


def test_the_annex_i_slot_reports_requirement_coverage(scoped, owner):
    r = _call("assemble_technical_file", scoped, owner)
    tf3 = next(s for s in r["slots"] if s["slot"] == "tf.3")
    assert tf3["requirement_coverage"]["total"] == 14
    assert len(tf3["requirement_coverage"]["gaps"]) == 14


def test_finalizing_with_holes_is_refused(scoped, owner):
    """A frozen file with holes is a document that looks finished."""
    r = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert r["ok"] is False
    assert "looks finished" in r["error"]


def test_a_complete_file_freezes_with_a_content_hash(scoped, owner):
    _fill_file(scoped, owner)
    r = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert r["ok"] is True and r["finalized"] is True
    assert len(r["content_hash"]) == 64

    with session_scope() as s:
        snapshot = s.get(Evidence, r["evidence_id"])
    assert snapshot.sha256 == r["content_hash"]
    assert _call("get_conformity_status", scoped, owner)["technical_file"][
        "finalized"
    ] is True


def test_an_optional_slot_does_not_block_finalizing(scoped, owner):
    """Annex VII(8) is produced on reasoned request, not held as a matter of
    course — it must not gate the file."""
    _fill_file(scoped, owner)
    assert _call("assemble_technical_file", scoped, owner, finalize=True)["ok"] is True


# ---- Declaration of Conformity -----------------------------------------------


def test_a_declaration_needs_a_frozen_file_behind_it(scoped, owner):
    r = _declare(scoped, owner)
    assert r["ok"] is False
    assert "no finalized technical file" in r["error"]


def test_a_steward_does_not_issue_a_declaration(product, owner):
    """Article 24 is a different, lighter obligation set — the tool is not
    applicable rather than merely unavailable."""
    state = store_pg.load_state(product)
    state.economic_operator_role = "open_source_steward"
    store_pg.save_state(state)
    r = _declare(product, owner)
    assert r["ok"] is False and "open-source steward" in r["error"]


def test_a_notified_body_product_cannot_declare_without_one(product, owner):
    _call(
        "classify_product",
        product,
        owner,
        product_class="important_class_ii",
        in_scope=True,
        rationale="Intrusion detection engine.",
    )
    _fill_file(product, owner)
    _call("assemble_technical_file", product, owner, finalize=True)

    # Claiming internal control on a class II product is refused before
    # anything else: the route is mandatory there, and routing around the
    # classification in the declaration is not an option the tool offers.
    wrong_route = _declare(product, owner)
    assert wrong_route["ok"] is False
    assert "notified-body procedure is mandatory" in wrong_route["error"]

    nb = dict(
        conformity_route="notified_body",
        conformity_route_basis="Module B type-examination by NB 1234.",
    )
    r = _declare(product, owner, **nb)
    assert r["ok"] is False
    assert "Annex V(7)" in r["error"]

    ok = _declare(product, owner,
        notified_body="NB 1234, Module B certificate 5678",
        standards_applied="EN 18031-1",
        **nb,
    )
    assert ok["ok"] is True


def test_the_draft_names_its_missing_fields_rather_than_inventing_them(scoped, owner):
    _fill_file(scoped, owner)
    _call("assemble_technical_file", scoped, owner, finalize=True)

    r = _declare(scoped, owner)
    assert r["ok"] is True and r["draft"] is True
    missing = {m["field"] for m in r["missing_fields"]}
    assert "doc.2" in missing  # manufacturer legal name not recorded
    assert "⚠️ MISSING" in r["markdown"]
    assert "Not signed" in r["markdown"]


def test_the_declaration_binds_to_the_file_it_rests_on(scoped, owner):
    _fill_file(scoped, owner)
    tf = _call("assemble_technical_file", scoped, owner, finalize=True)
    _call("set_submitter_profile", scoped, owner, legal_name="Acme Oy")
    doc = _declare(scoped, owner,
        standards_applied="EN 18031-1 applied in full",
    )
    assert doc["technical_file_hash"] == tf["content_hash"]
    assert doc["missing_fields"] == []


# ---- sign-off ----------------------------------------------------------------


def _declare(product, owner, **kw):
    """Draft a declaration with a route claimed, since one is now required.

    Default is internal control on the default class, which is the ordinary
    case. Tests about a conditional or notified-body route pass their own.
    """
    kw.setdefault("conformity_route", "self_assessment")
    kw.setdefault(
        "conformity_route_basis",
        "Default class under Article 32; internal control per Annex VIII Module A.",
    )
    return _call("generate_declaration_of_conformity", product, owner, **kw)


def _signable(product, owner):
    _fill_file(product, owner)
    return _call("assemble_technical_file", product, owner, finalize=True)


def test_nothing_frozen_means_nothing_to_sign(scoped, owner):
    r = _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest.",
    )
    assert r["ok"] is False and "no frozen technical file" in r["error"]


def test_a_signature_binds_to_the_exact_version(scoped, owner):
    tf = _signable(scoped, owner)
    r = _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest that this technical file is complete and accurate.",
    )
    assert r["ok"] is True
    assert r["bound_to_hash"] == tf["content_hash"]

    with session_scope() as s:
        att = s.get(Attestation, r["attestation_id"])
    assert att.signer_name == "A. Manager"
    assert att.subject_version_hash == tf["content_hash"]


def test_a_signature_is_recorded_as_a_human_act(scoped, owner):
    """Every other op is `agent`. A named person taking responsibility is not."""
    _signable(scoped, owner)
    _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest.",
    )
    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == scoped, AuditEvent.op == "sign_off")
            .one()
        )
    assert row.actor_kind == "human"
    assert row.rationale == "I attest."


def test_an_empty_statement_is_refused(scoped, owner):
    _signable(scoped, owner)
    r = _call(
        "sign_off", scoped, owner, signer_name="A", signer_role="CTO", statement="   "
    )
    assert r["ok"] is False and "taking responsibility" in r["error"]


def test_the_same_version_cannot_be_signed_twice(scoped, owner):
    _signable(scoped, owner)
    args = dict(signer_name="A. Manager", signer_role="CTO", statement="I attest.")
    assert _call("sign_off", scoped, owner, **args)["ok"] is True
    again = _call("sign_off", scoped, owner, **args)
    assert again["ok"] is False and "already signed" in again["error"]


def test_segregation_of_duties_refuses_the_last_editor(scoped, owner):
    """In compliance the person producing evidence frequently must not be the
    person attesting to it."""
    _signable(scoped, owner)
    r = _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest.",
        require_independent=True,
    )
    assert r["ok"] is False
    assert "segregation of duties" in r["error"]


def test_segregation_is_off_by_default_for_the_solo_maintainer(scoped, owner):
    """Defaulting it on would block the audience this tool is aimed at."""
    _signable(scoped, owner)
    r = _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest.",
    )
    assert r["ok"] is True


def test_only_an_owner_can_sign(scoped, owner):
    _signable(scoped, owner)
    junior = _user()
    _call("add_member", scoped, owner, user_id=junior, role="maintainer")
    r = _call(
        "sign_off",
        scoped,
        junior,
        signer_name="J. Junior",
        signer_role="dev",
        statement="I attest.",
    )
    assert r["ok"] is False and r["code"] == "permission_denied"


# ---- staleness ---------------------------------------------------------------


def test_editing_after_a_signature_makes_it_visibly_stale(scoped, owner):
    """A signature that no longer covers what you ship is worse than none —
    it looks like one."""
    _signable(scoped, owner)
    _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest.",
    )
    assert _call("get_conformity_status", scoped, owner)["stale_signatures"] == []

    # Change something, re-freeze: the hash moves and the old signature no
    # longer covers the current version.
    _attach(scoped, owner, "technical_file:tf.6", title="second test round")
    _call("assemble_technical_file", scoped, owner, finalize=True)

    status = _call("get_conformity_status", scoped, owner)
    assert len(status["stale_signatures"]) == 1
    assert status["attestations"][0]["covers_current_version"] is False


def test_conformity_status_summarises_the_whole_2027_half(scoped, owner):
    r = _call("get_conformity_status", scoped, owner)
    assert r["in_scope"] is True
    assert r["requirements"]["total"] == len(requirements())
    assert r["requirements"]["settled"] == 0
    assert r["technical_file"]["finalized"] is False
    assert r["declaration_of_conformity"]["drafted"] is False
    assert r["attestations"] == []


# ---- the ordering that resolves the circular dependency ----------------------


def test_the_declaration_slot_is_deferred_not_missing(scoped, owner):
    """Annex VII(7) holds a copy of the declaration; the declaration is drawn
    up *against* the technical documentation. Treating that slot as a blocker
    deadlocks the whole chain — the file cannot freeze without the declaration,
    and the declaration must not rest on an unfrozen file.
    """
    _fill_file(scoped, owner)
    r = _call("assemble_technical_file", scoped, owner)

    assert r["missing_slots"] == []
    assert [d["slot"] for d in r["deferred_slots"]] == ["tf.7"]
    assert "Filled last, by design" in r["deferred_slots"][0]["why"]
    # And the guidance names the order rather than leaving the agent stuck.
    assert "re-freeze" in r["next"]


def test_the_full_chain_runs_freeze_declare_refreeze_sign(scoped, owner):
    """The end-to-end sequence, in the order the regulation implies."""
    _fill_file(scoped, owner)
    _call("set_submitter_profile", scoped, owner, legal_name="Acme Oy")

    first = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert first["finalized"] is True

    doc = _declare(scoped, owner,
        standards_applied="EN 18031-1 applied in full",
    )
    assert doc["ok"] is True
    assert doc["technical_file_hash"] == first["content_hash"]
    assert doc["missing_fields"] == []

    second = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert second["deferred_slots"] == []          # tf.7 now holds the copy
    assert second["content_hash"] != first["content_hash"]

    signed = _call(
        "sign_off",
        scoped,
        owner,
        signer_name="A. Manager",
        signer_role="CTO",
        statement="I attest that this technical file is complete and accurate.",
    )
    assert signed["bound_to_hash"] == second["content_hash"]

    status = _call("get_conformity_status", scoped, owner)
    assert status["stale_signatures"] == []
    assert status["declaration_of_conformity"]["drafted"] is True


# ---- issues #28 and #29: signing a declaration with holes, and the green wall -


def test_the_declaration_lists_every_field_the_document_renders_as_missing(scoped, owner):
    """#28, the third bug inside it.

    `missing_fields` was accumulated alongside `values` rather than derived from
    it, and the two disagreed: the rendered document showed Annex V(7) as
    "⚠️ MISSING" while `missing_fields` did not mention it. The tool's summary
    and the tool's own document said different things about the same draft.
    """
    _fill_file(scoped, owner)
    _call("assemble_technical_file", scoped, owner, finalize=True)

    doc = _declare(scoped, owner,
                standards_applied="EN 18031-1 applied in full")
    rendered_missing = doc["markdown"].count("⚠️ MISSING")
    assert rendered_missing == len(doc["missing_fields"]), (
        f"document shows {rendered_missing} missing, list has "
        f"{len(doc['missing_fields'])}: {doc['missing_fields']}"
    )


def test_a_declaration_with_a_blank_mandatory_field_cannot_be_signed(scoped, owner):
    """#28. No submitter profile, so Annex V(2) — the manufacturer's name and
    address — cannot be filled. The run signed exactly this and got a clean
    confirmation."""
    _fill_file(scoped, owner)
    _call("assemble_technical_file", scoped, owner, finalize=True)

    doc = _declare(scoped, owner,
                standards_applied="EN 18031-1 applied in full")
    assert doc["missing_fields"], "expected the manufacturer's details to be missing"

    signed = _call("sign_off", scoped, owner, subject="declaration",
                   signer_name="A. Manager", signer_role="Managing Director",
                   statement="I declare that the product conforms.")
    assert signed["ok"] is False, "a declaration with a blank mandatory field was signed"
    said = str(signed.get("error", "")).lower()
    assert "annex v" in said
    assert "ten years" in said


def test_filling_the_field_lets_the_declaration_be_signed(scoped, owner):
    """The refusal has to be recoverable, and the route out has to work."""
    _fill_file(scoped, owner)
    _call("set_submitter_profile", scoped, owner, legal_name="Acme Oy")
    _call("assemble_technical_file", scoped, owner, finalize=True)
    doc = _declare(scoped, owner,
                standards_applied="EN 18031-1 applied in full")
    assert doc["missing_fields"] == []

    signed = _call("sign_off", scoped, owner, subject="declaration",
                   signer_name="A. Manager", signer_role="Managing Director",
                   statement="I declare that the product conforms.")
    assert signed["ok"] is True, signed


def test_the_status_read_qualifies_a_wall_of_green(scoped, owner):
    """#29. The run's own words: 'the strongest honest-seeming summary is
    "you're done" — I would have sent that, and it is false.'

    The disclaimer was already there and did not help; it disclaims the
    conclusion rather than correcting the inputs. These are the inputs.
    """
    _fill_file(scoped, owner)
    _call("assemble_technical_file", scoped, owner, finalize=True)
    _declare(scoped, owner,
          standards_applied="EN 18031-1 applied in full")

    out = _call("get_conformity_status", scoped, owner)
    assert out["ok"] is True
    quals = {q["about"] for q in out["qualifications"]}

    # The declaration is missing the manufacturer's details, and says so here.
    assert "declaration_of_conformity" in quals, out["qualifications"]
    assert out["declaration_of_conformity"]["missing_fields"]

    # Nothing has been placed on the market, so no evidence is tied to a build.
    assert "evidence" in quals, out["qualifications"]


def test_a_clean_product_carries_no_qualifications(scoped, owner):
    """The list has to be empty when there is nothing to say, or it becomes
    noise nobody reads — which is how the wall of green happened."""
    _fill_file(scoped, owner)
    _call("set_submitter_profile", scoped, owner, legal_name="Acme Oy")
    _call("assemble_technical_file", scoped, owner, finalize=True)
    _declare(scoped, owner,
          standards_applied="EN 18031-1 applied in full")

    out = _call("get_conformity_status", scoped, owner)
    about = {q["about"] for q in out["qualifications"]}
    assert "declaration_of_conformity" not in about, out["qualifications"]


# ---- issue #21: a justification of no substance counts as settled -------------


def test_a_one_character_justification_is_surfaced_not_hidden(scoped, owner):
    """The run ruled two Annex I essential requirements out on 'x' and 'n/a'.

    Both counted towards the coverage the file reports and the release gate
    checks, and nothing downstream mentioned them again. tf.3's own note warns
    that a requirement ruled out with no justification 'leaves a hole an auditor
    reads directly' — 'x' left no hole at all, which is worse, because the hole
    became invisible.

    Not refused. No mechanical test measures a reason, and a length rule that
    refused would teach the next caller to pad to the threshold and change
    nothing. What it must not do is let them vanish.
    """
    _call("update_requirement", scoped, owner, req_id="annex_i.i.2.g",
          applicability="not_applicable", justification="x")
    _call("update_requirement", scoped, owner, req_id="annex_i.i.2.h",
          applicability="not_applicable", justification="n/a")

    out = _call("assemble_technical_file", scoped, owner)
    thin = {j["req_id"] for j in out["thin_justifications"]}
    assert {"annex_i.i.2.g", "annex_i.i.2.h"} <= thin, out["thin_justifications"]


def test_a_real_justification_is_not_flagged(scoped, owner):
    """The flag has to be quiet when there is nothing to say, or it is noise."""
    _call("update_requirement", scoped, owner, req_id="annex_i.i.2.g",
          applicability="not_applicable",
          justification="The product processes no personal data at all; there is "
                        "nothing to minimise and no storage to limit.")
    out = _call("assemble_technical_file", scoped, owner)
    flagged = {j["req_id"] for j in out["thin_justifications"]}
    assert "annex_i.i.2.g" not in flagged, out["thin_justifications"]


def test_the_freeze_says_it_out_loud(scoped, owner):
    """The freeze is the moment it becomes permanent and the one place a person
    is definitely looking, so it says so in words rather than only in a list."""
    _fill_file(scoped, owner)
    _call("update_requirement", scoped, owner, req_id="annex_i.i.2.g",
          applicability="not_applicable", justification="x")

    out = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert out["ok"] is True, out
    said = out.get("review_before_this_is_relied_on", "")
    assert "annex_i.i.2.g" in said, out
    assert "your call" in said, "it must not read as a refusal"


# ---- what the signature actually spans ----------------------------------------
#
# A signature binds to a content hash, so the hash decides what "the document"
# means. Until 2026-08-10 it covered the file's *shape* — which slots were
# complete, how many requirements were settled — and not what any requirement
# said. An end-to-end run signed a file, then rewrote an implementation note
# from a claim that hardening flags were applied to a statement that they were
# only partly applied. The hash did not move, `stale_signatures` stayed empty,
# and the agent reported the sign-off intact.


def test_rewriting_an_implementation_note_after_signature_is_visible(scoped, owner):
    """The exact sequence from the run that found this.

    Annex VII(3) asks the file to record how each applicable requirement is
    implemented, so the note *is* content — and it is the part a reader is most
    likely to revise quietly.
    """
    _signable(scoped, owner)
    _call("sign_off", scoped, owner, signer_name="A. Manager",
          signer_role="CTO", statement="I attest.")
    before = _call("assemble_technical_file", scoped, owner)["content_hash"]
    assert _call("get_conformity_status", scoped, owner)["stale_signatures"] == []

    _call("update_requirement", scoped, owner, req_id=REQ,
          implementation_note="Amended after signature: hardening flags were "
                              "only partially applied in the 1.0.0 build.")

    after = _call("assemble_technical_file", scoped, owner)["content_hash"]
    assert after != before, "rewriting the implementation note did not move the hash"


def test_rewriting_a_justification_after_signature_is_visible(scoped, owner):
    """The other half of it. Ruling a requirement out is a claim the file makes,
    and the reason is the whole of that claim."""
    _signable(scoped, owner)
    other = "annex_i.i.2.l"
    _call("update_requirement", scoped, owner, req_id=other,
          applicability="not_applicable",
          justification="No network interface in this product at all.")
    _call("assemble_technical_file", scoped, owner, finalize=True)
    before = _call("assemble_technical_file", scoped, owner)["content_hash"]

    _call("update_requirement", scoped, owner, req_id=other,
          applicability="not_applicable",
          justification="Reviewed again; the interface is present but disabled "
                        "by default.")
    after = _call("assemble_technical_file", scoped, owner)["content_hash"]
    assert after != before, "rewriting the justification did not move the hash"


def test_an_unchanged_file_still_hashes_the_same(scoped, owner):
    """The other direction, and it is why the timestamp is not in the payload:
    a hash that moved on every read would make staleness noise rather than a
    signal, and nobody would look at it."""
    _signable(scoped, owner)
    a = _call("assemble_technical_file", scoped, owner)["content_hash"]
    b = _call("assemble_technical_file", scoped, owner)["content_hash"]
    assert a == b


def test_emptying_a_note_is_not_the_same_as_never_writing_one(scoped, owner):
    """Every narrative field is rendered even when blank. A payload that omitted
    empty values would hash identically whether a note was cleared or never
    existed, which is the one edit most worth catching."""
    _signable(scoped, owner)
    _call("update_requirement", scoped, owner, req_id=REQ,
          implementation_note="Hardening flags applied to the 1.0.0 build.")
    written = _call("assemble_technical_file", scoped, owner)["content_hash"]

    _call("update_requirement", scoped, owner, req_id=REQ, implementation_note="")
    cleared = _call("assemble_technical_file", scoped, owner)["content_hash"]
    assert cleared != written


def test_a_signature_from_before_the_widening_is_not_called_stale(scoped, owner):
    """A change in how the hash is computed must not be reported as a change to
    the document.

    Widening the payload moved every digest. An older signature compares unequal
    and would have landed in `stale_signatures`, asserting an edit nobody made —
    the inverse of this codebase's rule that an absence of knowledge must not
    read as knowledge of absence.
    """
    _signable(scoped, owner)
    _call("sign_off", scoped, owner, signer_name="A. Manager",
          signer_role="CTO", statement="I attest.")

    # Exactly what a row signed before migration 0013 looks like.
    with session_scope() as s:
        row = s.execute(
            select(Attestation).where(Attestation.product_id == scoped)
        ).scalars().first()
        row.hash_payload_version = None
        row.subject_version_hash = "0" * 64

    status = _call("get_conformity_status", scoped, owner)
    att = status["attestations"][0]
    assert att["coverage"] == "incomparable"
    assert att["covers_current_version"] is False      # cannot be shown to cover
    assert status["stale_signatures"] == []            # but not evidence of an edit
    assert len(status["unverifiable_signatures"]) == 1
    assert "does not mean the document changed" in att["detail"]


def test_a_document_that_really_changed_is_still_called_superseded(scoped, owner):
    """The distinction only earns its place if the ordinary case still works."""
    _signable(scoped, owner)
    _call("sign_off", scoped, owner, signer_name="A. Manager",
          signer_role="CTO", statement="I attest.")
    _attach(scoped, owner, "technical_file:tf.6", title="second test round")
    _call("assemble_technical_file", scoped, owner, finalize=True)

    status = _call("get_conformity_status", scoped, owner)
    assert status["attestations"][0]["coverage"] == "superseded"
    assert len(status["stale_signatures"]) == 1
    assert status["unverifiable_signatures"] == []


# ---- the reply has to describe the record it just wrote ------------------------


def test_the_gap_reason_matches_what_was_actually_recorded(scoped, owner):
    """One canned sentence covered every case: "Marked applicable but not yet
    implemented and verified with evidence attached."

    It said `applicable` when applicability was undetermined, and `not yet
    implemented and verified` when the status just written was `verified`. The
    substance underneath was right — the file counted it as a gap either way —
    but this is the sentence an agent repeats to its user.
    """
    _call("update_requirement", scoped, owner, req_id=REQ, applicability="applicable")
    out = _call("update_requirement", scoped, owner, req_id=REQ, status="verified")
    assert "no evidence attached" in out["still_a_gap"]
    assert "not yet implemented and verified" not in out["still_a_gap"]


def test_an_undetermined_requirement_is_not_described_as_applicable(scoped, owner):
    other = "annex_i.i.2.l"
    out = _call("update_requirement", scoped, owner, req_id=other,
                implementation_note="looked at it")
    assert "no applicability recorded" in out["still_a_gap"]
    assert "Marked applicable" not in out["still_a_gap"]


def test_a_bare_not_applicable_says_the_reason_is_missing(scoped, owner):
    other = "annex_i.i.2.l"
    out = _call("update_requirement", scoped, owner, req_id=other,
                applicability="not_applicable", justification="   ")
    assert out["ok"] is False or "no justification" in out.get("still_a_gap", "")


def test_verified_with_no_assessment_says_it_rests_on_nothing(scoped, owner):
    """The checklist order is the regulation's: Annex I Part I applies *on the
    basis of* the Article 13(2) assessment.

    Not refused — this tool reports gaps rather than blocking work, and a
    sequencing rule is not a validity rule. But the highest status reachable
    with no assessment on file rests on nothing, and the reply said nothing
    about that while the technical file counted it as a gap.
    """
    out = _call("update_requirement", scoped, owner, req_id=REQ, status="verified")
    assert out["ok"] is True
    assert "no confirmed" in out["rests_on_no_assessment"]
    assert "rests on nothing" in out["rests_on_no_assessment"] or \
           "establishes that this requirement applies" in out["rests_on_no_assessment"]


def test_with_an_assessment_confirmed_that_note_is_gone(scoped, owner):
    _confirm_assessment(scoped, owner)
    out = _call("update_requirement", scoped, owner, req_id=REQ, status="verified")
    assert "rests_on_no_assessment" not in out


# ---- one definition of settled -------------------------------------------------


def test_the_status_read_and_the_file_agree_on_what_is_settled(scoped, owner):
    _confirm_assessment(scoped, owner)
    """Two tools, one product, one moment, two answers — and the headline was
    the optimistic one.

    `get_conformity_status` counted a requirement ruled out with no
    justification, and one verified against a build nobody ships, as settled.
    The technical file counted neither. It is the status read an agent quotes.
    """
    status = _call("get_conformity_status", scoped, owner)["requirements"]
    tf = _call("assemble_technical_file", scoped, owner)

    part_i = next(
        s for s in tf["slots"] if s.get("requirement_coverage")
    )["requirement_coverage"]
    # The file counts one Annex VII slot's part; the status read counts the
    # whole checklist. What has to agree is which items are gaps.
    assert set(part_i["gaps"]) <= set(status["gaps"])
    assert status["settled"] == status["total"] - len(status["gaps"])


def test_the_status_read_says_what_it_is_counting(scoped, owner):
    """The denominators differed and neither response said which it used, so a
    number moved between sessions for reasons a user could not account for."""
    req = _call("get_conformity_status", scoped, owner)["requirements"]
    assert {"total", "settled", "gaps", "applicable", "counting"} <= set(req)
    assert "never made applicable" in req["counting"]


# ---- the route is claimed, not inferred ----------------------------------------


def _class_i(product, owner):
    _call("classify_product", product, owner, product_class="important_class_i",
          in_scope=True, rationale="Password manager.")
    _fill_file(product, owner)
    _call("assemble_technical_file", product, owner, finalize=True)


def test_class_i_cannot_self_assess_on_standards_applied_in_part(product, owner):
    """The finding, exactly. Annex III class I permits internal control only
    where harmonised standards, common specifications or a certification scheme
    are applied *in full*.

    An end-to-end run recorded "ETSI EN 303 645 in part; no harmonised standard
    applied in full" in the technical file, then issued and signed a declaration
    asserting conformity with Annex V(7) absent — a route the record said was
    not open.
    """
    _class_i(product, owner)
    out = _declare(product, owner, standards_applied="ETSI EN 303 645 in part")
    assert out["ok"] is False
    assert "applied in full" in out["error"]


def test_class_i_may_self_assess_when_the_condition_is_asserted(product, owner):
    """Asserted, not parsed. Reading it off `standards_applied` would mean
    deciding from a sentence, and being wrong in the permissive direction issues
    the declaration this refuses."""
    _class_i(product, owner)
    out = _declare(
        product, owner,
        standards_applied="EN 18031-1:2024",
        standards_applied_in_full=True,
        conformity_route_basis="EN 18031-1:2024 applied in full across the product.",
    )
    assert out["ok"] is True, out


def test_a_route_with_no_basis_is_refused(product, owner):
    """Same shape as Article 13(8): the support period needs the date and the
    information taken into account. A route with no stated basis is that gap."""
    _class_i(product, owner)
    out = _declare(product, owner, conformity_route_basis="   ",
                   standards_applied_in_full=True)
    assert out["ok"] is False
    assert "conformity_route_basis is required" in out["error"]


def test_an_unknown_route_is_refused_rather_than_guessed(scoped, owner):
    _signable(scoped, owner)
    out = _declare(scoped, owner, conformity_route="module_h")
    assert out["ok"] is False
    assert "conformity_route is required" in out["error"]


def test_the_declaration_states_the_route_it_relied_on(scoped, owner):
    """In the document, not only the tool's reply — an auditor reading the
    declaration should find the route rather than infer it from which fields
    happen to be filled."""
    _signable(scoped, owner)
    out = _declare(scoped, owner, standards_applied="EN 18031-1:2024")
    doc = out["markdown"]
    assert "Conformity assessment route relied on" in doc
    assert "internal control (Module A)" in doc
    assert "Annex VIII Module A" in doc


def test_the_technical_file_carries_the_claim_separately_from_the_class(
    scoped, owner
):
    """What the class permits and what was claimed are different facts, and the
    file should not make a reader derive the second from the first."""
    _signable(scoped, owner)
    _declare(scoped, owner, standards_applied="EN 18031-1:2024")
    tf = _call("get_conformity_status", scoped, owner)
    assert tf["conformity_claimed"]["route"] == "self_assessment"
    assert "Module A" in tf["conformity_claimed"]["basis"]
