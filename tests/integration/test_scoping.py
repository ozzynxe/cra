"""Classification, SBOM, membership and the activity read.

The classification tests carry the most weight. Class membership decides
whether a notified body is required, and a wrong answer here is one the user
cannot detect — the tool would simply be agreeing with what they already
believed.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import AuditEvent, Evidence, ProductMember, User, session_scope  # noqa: E402
from cra.regulation import requirements  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc


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


# ---- classification ----------------------------------------------------------


def test_calling_it_bare_explores_without_committing(product, owner):
    """Exploring the question should be free; committing to an answer should
    not be."""
    r = _call("classify_product", product, owner)
    assert r["ok"] is True and r["recorded"] is False
    assert {c["product_class"] for c in r["classes"]} == {
        "default",
        "important_class_i",
        "important_class_ii",
        "critical",
    }
    assert r["out_of_scope"]
    assert r["provenance"]["source_verified"] is True

    # Nothing was written.
    status = _call("get_compliance_status", product, owner)
    assert status["classification"]["product_class"] == "unknown"


def test_the_decision_aid_tells_the_agent_not_to_guess(product, owner):
    r = _call("classify_product", product, owner)
    assert "not what it is called" in r["how_to_decide"]
    assert "take the higher class" in r["how_to_decide"]


def test_a_classification_without_reasoning_is_refused(product, owner):
    """A classification with no rationale is worse than none: it looks
    settled."""
    r = _call("classify_product", product, owner, product_class="default")
    assert r["ok"] is False
    assert "rationale is required" in r["error"]
    assert _call("get_compliance_status", product, owner)["classification"][
        "product_class"
    ] == "unknown"


def test_whitespace_is_not_a_rationale(product, owner):
    r = _call("classify_product", product, owner, product_class="default", rationale="   ")
    assert r["ok"] is False


def test_recording_a_class_spells_out_its_consequences(product, owner):
    r = _call(
        "classify_product",
        product,
        owner,
        product_class="important_class_ii",
        in_scope=True,
        rationale="Ships an intrusion detection engine — Annex III class II.",
    )
    assert r["ok"] is True and r["recorded"] is True
    assert r["indicative"] is True
    assert r["notified_body_required"] is True
    assert r["conformity_route"] == "notified_body"
    assert "Annex III" in r["anchor"]
    assert "not a determination" in r["caveat"]


def test_class_i_is_reported_as_conditional_self_assessment(product, owner):
    r = _call(
        "classify_product",
        product,
        owner,
        product_class="important_class_i",
        in_scope=True,
        rationale="It is a password manager — Annex III class I.",
    )
    assert r["conformity_route"] == "self_assessment_with_standards"
    assert r["notified_body_required"] is False
    assert "in full" in r["what_this_means"]


def test_an_unknown_class_points_back_at_the_decision_aid(product, owner):
    r = _call(
        "classify_product",
        product,
        owner,
        product_class="quite_important",
        rationale="feels important",
    )
    assert r["ok"] is False
    assert "classify_product() with no arguments" in r["error"]


def test_classifying_in_scope_seeds_the_annex_i_checklist(product, owner):
    r = _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Not listed in Annex III or IV.",
    )
    assert r["requirements_seeded"] == len(requirements())
    status = _call("get_compliance_status", product, owner)
    assert status["requirements"]["total"] == len(requirements())
    assert status["requirements"]["by_status"] == {"not_started": len(requirements())}


def test_an_out_of_scope_product_gets_no_checklist(product, owner):
    r = _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=False,
        rationale="Pure SaaS with no product component — Article 2.",
    )
    assert r["requirements_seeded"] == 0
    assert r["in_scope"] is False


def test_reclassifying_does_not_discard_existing_work(product, owner):
    """Someone who has attached evidence must not lose it because the class
    was corrected."""
    _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="initial read",
    )
    state = store_pg.load_state(product)
    state.requirements[0].implementation_note = "done, see PR 412"
    state.requirements[0].evidence_ids = ["ev-1"]
    store_pg.save_state(state)

    second = _call(
        "classify_product",
        product,
        owner,
        product_class="important_class_i",
        in_scope=True,
        rationale="On reflection it is a network management system.",
    )
    assert second["requirements_seeded"] == 0  # nothing re-added
    after = store_pg.load_state(product)
    assert len(after.requirements) == len(requirements())
    assert after.requirements[0].implementation_note == "done, see PR 412"
    assert after.requirements[0].evidence_ids == ["ev-1"]


def test_the_rationale_and_the_class_change_land_in_the_audit_trail(product, owner):
    _call(
        "classify_product",
        product,
        owner,
        product_class="critical",
        in_scope=True,
        rationale="Secure element — Annex IV.",
    )
    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "classify_product")
            .one()
        )
    assert row.rationale == "Secure element — Annex IV."
    assert row.payload["from"] == "unknown"
    assert row.payload["to"] == "critical"
    assert row.accountable_user_id == owner


def test_an_editor_cannot_classify(product, owner):
    """Classification decides the conformity route, so it needs maintainer."""
    junior = _user()
    _call("add_member", product, owner, user_id=junior, role="editor")
    r = _call(
        "classify_product",
        product,
        junior,
        product_class="default",
        rationale="looks fine",
    )
    assert r["ok"] is False
    assert r["code"] == "permission_denied"


# ---- CSIRT -------------------------------------------------------------------


def test_the_csirt_answer_explains_that_the_platform_routes(product, owner):
    r = _call("get_applicable_csirt", product, owner)
    assert "main establishment" in r["rule"]
    assert "Single Reporting Platform" in r["rule"]
    assert r["member_states_recorded"] == []

    _call("set_submitter_profile", product, owner, member_states_available=["FI"])
    assert _call("get_applicable_csirt", product, owner)["member_states_recorded"] == ["FI"]


# ---- SBOM --------------------------------------------------------------------


SBOM = json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "openssl"}]})


def test_an_sbom_is_stored_by_value_and_hashed(product, owner):
    """A link evidences nothing in ten years, which is how long the technical
    file is kept."""
    r = _call(
        "record_sbom",
        product,
        owner,
        sbom=SBOM,
        source_ref="git:abc123",
        version="2.1.0",
    )
    assert r["ok"] is True
    assert r["satisfies"] == "annex_i.ii.1"

    with session_scope() as s:
        ev = s.get(Evidence, r["evidence_id"])
    assert ev.inline_body == SBOM
    assert ev.sha256 == r["sha256"] and len(ev.sha256) == 64
    assert ev.subject_ref == "requirement:annex_i.ii.1"
    assert ev.source_ref == "git:abc123"
    assert ev.kind == "sbom"


def test_an_unsupported_sbom_format_is_refused(product, owner):
    r = _call("record_sbom", product, owner, sbom=SBOM, sbom_format="a-spreadsheet")
    assert r["ok"] is False
    assert "cyclonedx" in r["error"]


def test_an_empty_sbom_is_refused(product, owner):
    assert _call("record_sbom", product, owner, sbom="   ")["ok"] is False


def test_recording_an_sbom_is_audited(product, owner):
    _call("record_sbom", product, owner, sbom=SBOM, version="2.1.0")
    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "record_sbom")
            .one()
        )
    assert row.after_hash and row.accountable_user_id == owner


# ---- membership --------------------------------------------------------------


def test_adding_a_member_reaches_the_queryable_table(product, owner):
    """The projection is what makes cross-product deadline queries and alert
    fan-out work."""
    teammate = _user()
    r = _call("add_member", product, owner, user_id=teammate, role="maintainer")
    assert r["ok"] is True and r["members"] == 2

    with session_scope() as s:
        roles = {
            m.user_id: m.role
            for m in s.query(ProductMember).filter(ProductMember.product_id == product)
        }
    assert roles[teammate] == "maintainer"


def test_a_new_member_can_immediately_act_under_their_own_credential(product, owner):
    teammate = _user()
    _call("add_member", product, owner, user_id=teammate, role="maintainer")
    r = _call("record_vulnerability", product, teammate, summary="found by Priya")
    assert r["ok"] is True

    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(
                AuditEvent.product_id == product,
                AuditEvent.op == "record_vulnerability",
            )
            .one()
        )
    assert row.accountable_user_id == teammate


def test_only_an_owner_can_add_members(product, owner):
    teammate = _user()
    _call("add_member", product, owner, user_id=teammate, role="maintainer")
    r = _call("add_member", product, teammate, user_id=_user(), role="editor")
    assert r["ok"] is False and r["code"] == "permission_denied"


def test_an_unknown_role_lists_the_valid_ones(product, owner):
    r = _call("add_member", product, owner, user_id=_user(), role="admin")
    assert r["ok"] is False and "maintainer" in r["error"]


def test_adding_someone_twice_is_refused(product, owner):
    teammate = _user()
    _call("add_member", product, owner, user_id=teammate)
    assert _call("add_member", product, owner, user_id=teammate)["ok"] is False


def test_removing_a_member_revokes_access_but_not_history(product, owner):
    teammate = _user()
    _call("add_member", product, owner, user_id=teammate, role="maintainer")
    _call("record_vulnerability", product, teammate, summary="found by Priya")

    assert _call("remove_member", product, owner, user_id=teammate)["ok"] is True
    assert _call("get_compliance_status", product, teammate)["ok"] is False

    with session_scope() as s:
        assert (
            s.query(ProductMember)
            .filter(
                ProductMember.product_id == product,
                ProductMember.user_id == teammate,
            )
            .count()
            == 0
        )
        # The trail is retained ten years and is not the manufacturer's to edit.
        assert (
            s.query(AuditEvent)
            .filter(AuditEvent.accountable_user_id == teammate)
            .count()
            >= 1
        )


def test_the_last_owner_cannot_be_removed(product, owner):
    """A product nobody is accountable for is not a compliance artifact."""
    r = _call("remove_member", product, owner, user_id=owner)
    assert r["ok"] is False
    assert "only owner" in r["error"]


def test_an_owner_can_be_removed_once_there_is_another(product, owner):
    second = _user()
    _call("add_member", product, owner, user_id=second, role="owner")
    assert _call("remove_member", product, owner, user_id=owner)["ok"] is True


# ---- activity ----------------------------------------------------------------


def test_recent_activity_reads_the_audit_trail_newest_first(product, owner):
    _call("record_sbom", product, owner, sbom=SBOM)
    _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Not listed in Annex III or IV.",
    )
    r = _call("get_recent_activity", product, owner)
    assert r["ok"] is True
    ops = [e["op"] for e in r["events"]]
    assert ops[0] == "classify_product"
    assert "record_sbom" in ops
    assert all(e["accountable_user_id"] == owner for e in r["events"])
    # #46: every one of these arrived over MCP, so every one is `agent`.
    assert all(e["actor_kind"] == "agent" for e in r["events"])


def test_activity_names_the_accountable_person_not_only_their_uuid(product, owner):
    """Issue #38. "What did the others do while I was out?" was unanswerable:
    every event identified the accountable party as a UUID, and there is no tool
    a caller could use to resolve one.

    The id stays — it is what the trail stores and what another call takes. The
    label is what makes the response usable without a lookup that does not exist.
    """
    _call("record_sbom", product, owner, sbom=SBOM)
    with session_scope() as s:
        expected = s.get(User, owner).email

    r = _call("get_recent_activity", product, owner)
    ev = r["events"][0]
    assert ev["accountable_user_id"] == owner
    assert ev["accountable"] == expected

    # And the response says what `actor_kind: agent` and a null `actor_model`
    # actually mean, rather than leaving both to be inferred from column names.
    assert ev["actor_kind"] == "agent"
    assert "does not mean nobody was asked" in r["attribution"]
    assert "the model was never recorded" in r["attribution"]


def test_a_display_name_wins_over_the_address(product, owner):
    with session_scope() as s:
        s.get(User, owner).display_name = "Priya R."
    _call("record_sbom", product, owner, sbom=SBOM)
    r = _call("get_recent_activity", product, owner)
    assert r["events"][0]["accountable"] == "Priya R."


def test_members_are_named_in_the_status_read_too(product, owner):
    """Same defect, the other surface. `get_compliance_status` is the call an
    agent makes first, and its members list was UUID-only."""
    with session_scope() as s:
        expected = s.get(User, owner).email
    members = _call("get_compliance_status", product, owner)["members"]
    row = next(m for m in members if m["user_id"] == owner)
    assert row["name"] == expected
    assert row["role"] == "owner"


def test_since_filters_and_demands_a_timezone(product, owner):
    _call("record_sbom", product, owner, sbom=SBOM)
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert _call("get_recent_activity", product, owner, since=future)["count"] == 0

    bad = _call("get_recent_activity", product, owner, since="2026-09-01T00:00:00")
    assert bad["ok"] is False and "timezone" in bad["error"]


def test_the_limit_is_clamped_not_trusted(product, owner):
    _call("record_sbom", product, owner, sbom=SBOM)
    assert _call("get_recent_activity", product, owner, limit=100000)["ok"] is True
    assert _call("get_recent_activity", product, owner, limit=0)["ok"] is True


def test_a_non_member_sees_nothing(product):
    stranger = _user()
    r = _call("get_recent_activity", product, stranger)
    assert r["ok"] is False and r["code"] == "not_found"


# ---- authorization -----------------------------------------------------------


def test_a_product_id_is_not_a_capability(product, owner):
    """Regression guard on a real gap.

    `get_compliance_status` originally took a product id and returned the
    state, with no membership check — so anyone holding a token and a product
    id could read another team's unreported exploited-vulnerability details.
    That is the most sensitive data this server holds.
    """
    stranger = _user()
    r = _call("get_compliance_status", product, stranger)
    assert r["ok"] is False
    assert r["code"] == "not_found"
    # And the error must not confirm the product exists.
    assert "vulnerab" not in r["error"].lower()


@pytest.mark.parametrize(
    "tool,args",
    [
        ("get_compliance_status", {}),
        ("get_recent_activity", {}),
        ("get_applicable_csirt", {}),
        ("get_reporting_deadlines", {}),
        ("check_reporting_readiness", {}),
        ("classify_product", {"product_class": "default", "rationale": "x"}),
        ("record_sbom", {"sbom": SBOM}),
        ("record_vulnerability", {"summary": "x"}),
        ("report_incident", {}),
        ("add_member", {"user_id": "00000000-0000-0000-0000-000000000000"}),
        ("set_submitter_profile", {"legal_name": "Not Acme"}),
    ],
)
def test_every_product_scoped_tool_refuses_a_non_member(product, tool, args):
    """Swept rather than spot-checked: the gap above existed because one
    handler was written without the check the others had."""
    stranger = _user()
    r = _call(tool, product, stranger, **args)
    assert r["ok"] is False, f"{tool} leaked to a non-member"
    assert r["code"] in ("not_found", "permission_denied"), tool


# ---- issue #52: Annex I binds manufacturers, and nobody else -------------------


def test_annex_i_is_not_reported_as_binding_on_a_steward(product, owner):
    """Issue #52, verified against the regulation.

    Article 13(1) imposes Annex I Part I on manufacturers. Article 19(1) has
    importers verify that *the manufacturer's* processes comply; Article 20 has
    distributors check the CE marking; Article 24 gives stewards a policy, a
    duty to cooperate, and part of Article 14 — Annex I appears nowhere in it.

    The checklist was seeded for all of them regardless, so a steward opening
    this tool was told they had twenty-two outstanding requirements. Tracking
    them is a legitimate thing to do; being told they are owed is not.
    """
    _call("set_economic_operator_role", product, owner, role="open_source_steward",
          rationale="We steward an upstream library; we do not place it on the market.")
    _call("classify_product", product, owner, product_class="default",
          in_scope=True, rationale="In scope as a product with digital elements.")

    reqs = _call("list_requirements", product, owner)
    assert reqs["count"] == 22, "the checklist is still available"
    assert reqs["annex_i"]["binds_you"] is False
    assert reqs["annex_i"]["whose_obligation"] == "manufacturer"
    assert "Article 13(1)" in reqs["annex_i"]["note"]
    assert "legitimate thing to do" in reqs["annex_i"]["note"]
    # And it names the transition that would make them binding.
    assert "Article 21" in reqs["annex_i"]["note"]

    status = _call("get_compliance_status", product, owner)
    assert status["requirements"]["annex_i"]["binds_you"] is False


def test_a_manufacturer_is_told_they_are_bound(product, owner):
    _call("classify_product", product, owner, product_class="default",
          in_scope=True, rationale="We build and ship it.")
    reqs = _call("list_requirements", product, owner)
    assert reqs["annex_i"]["binds_you"] is True
    # No caveat where there is nothing to caveat.
    assert "note" not in reqs["annex_i"]


def test_the_article_21_transition_can_be_recorded(product, owner):
    """The hole underneath #52. The role was write-once at create_product, so an
    importer who went on to substantially modify — becoming a manufacturer in
    law under Article 21 — could either leave the record wrong or start a new
    product and abandon every requirement, evidence row and audit entry.
    """
    _call("set_economic_operator_role", product, owner, role="importer",
          rationale="We import and resell without modification.")
    _call("classify_product", product, owner, product_class="default",
          in_scope=True, rationale="In scope.")
    assert _call("list_requirements", product, owner)["annex_i"]["binds_you"] is False

    out = _call("set_economic_operator_role", product, owner, role="manufacturer",
                rationale="We now fork and ship it under our own brand.")
    assert out["ok"] is True
    assert out["previous"] == "importer"
    assert out["annex_i"]["binds_you"] is True
    assert "now your statutory obligations" in out["now_binding"]
    assert "Anything already recorded against them stands" in out["now_binding"]

    assert _call("list_requirements", product, owner)["annex_i"]["binds_you"] is True


def test_stepping_back_from_manufacturer_does_not_erase_what_attached(product, owner):
    """The other direction, and the honest thing to say about it. Obligations
    that attached while they were the manufacturer did not end — 13(13) keeps
    the documentation ten years."""
    out = _call("set_economic_operator_role", product, owner, role="distributor",
                rationale="Corrected: we only distribute this.")
    assert out["ok"] is True
    assert "did not end" in out["care"]
    assert "ten years" in out["care"]


def test_changing_the_role_without_a_reason_is_refused(product, owner):
    out = _call("set_economic_operator_role", product, owner,
                role="open_source_steward", rationale="   ")
    assert out["ok"] is False
    assert "rationale is required" in out["error"]
    assert "which obligations apply" in out["error"]


def test_an_unknown_role_lists_the_real_ones(product, owner):
    out = _call("set_economic_operator_role", product, owner,
                role="reseller", rationale="x")
    assert out["ok"] is False
    assert "open_source_steward" in out["error"]


def test_creating_a_product_says_when_it_assumed_the_role(owner):
    """#45's journey 2 finding: the role was defaulted silently. It is still
    assumed — refusing to create a product until the question is answered is
    worse — but the reply now says so."""
    made = dispatcher.dispatch("create_product", "", owner, {"name": "Assumed"})
    assert made["economic_operator_role"] == "manufacturer"
    assert "No economic_operator_role was given" in made["role_assumed"]
    assert "Article 24" in made["role_assumed"]

    stated = dispatcher.dispatch(
        "create_product", "", owner,
        {"name": "Stated", "economic_operator_role": "importer"},
    )
    assert stated["economic_operator_role"] == "importer"
    assert "role_assumed" not in stated
