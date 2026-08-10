"""The Article 13(2) risk assessment, and what it gates.

The assessment is the basis Annex I Part I applies on, so the tests that matter
are the ones about *authority*: what an agent's draft can and cannot do on its
own, and what the technical file refuses to do without a confirmed assessment
behind it.

The sharpest one is `test_a_file_cannot_be_frozen_without_an_assessment`. Annex
VII(3) is titled "cybersecurity risk assessment" and used to report complete on
checklist coverage alone — so a technical file could be frozen, declared and
signed with the one artifact Article 13(2) mandates never recorded, and the gap
report said the section was filled.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import AuditEvent, Evidence, User, session_scope  # noqa: E402
from cra.regulation import (  # noqa: E402
    requirements,
    technical_file_slots,
    user_information,
)
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc
REQ = "annex_i.i.2.a"
REQ_B = "annex_i.i.2.b"


def _user() -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


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
            intended_use="Fronts internal services for enterprise customers",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    return pid


@pytest.fixture
def scoped(product, owner):
    _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Not an Annex III category; ordinary product with digital elements.",
    )
    return product


def _started(product, owner, **kw):
    args = {
        "method": "STRIDE",
        "intended_purpose": "An API gateway fronting internal services",
        "foreseeable_misuse": "Deployed on the public internet with no WAF",
        "conditions_of_use": "Customer-operated Kubernetes cluster",
        "support_duration_note": "Five years from GA",
        # Article 13(3)'s last sentence. Required before an assessment can be
        # confirmed, so every fixture that gets as far as confirming needs
        # them — which is the point of the change that added them.
        "part_i_1_approach": (
            "Threat modelling each release against the accepted risks, with "
            "the controls tracked as Annex I requirements."
        ),
        "part_ii_approach": (
            "SBOM on every build, daily advisory scanning, a published CVD "
            "policy, and the Article 14 clocks run from this tool."
        ),
    }
    args.update(kw)
    return _call("start_risk_assessment", product, owner, **args)


def _proposed(product, owner, affects=(REQ,), model=None):
    return _call(
        "propose_risks",
        product,
        owner,
        basis="repository at HEAD plus the deployment topology",
        model=model,
        risks=[
            {
                "title": "Unauthenticated access to the admin API",
                "asset": "administrative control plane",
                "threat": "an unauthenticated caller reconfigures routing",
                "attack_vector": "admin listener bound to 0.0.0.0",
                "impact": "full traffic interception",
                "affects_requirements": list(affects),
            }
        ],
    )


def _accepted(product, owner, affects=(REQ,), model=None):
    _started(product, owner)
    _proposed(product, owner, affects, model=model)
    return _call(
        "decide_risk",
        product,
        owner,
        risk_id="risk-001",
        decision="accept",
        treatment="mitigate",
        rationale="Real for our topology; mitigated by mTLS on the admin listener.",
    )


def _confirmed(product, owner, affects=(REQ,), model=None):
    _accepted(product, owner, affects, model=model)
    return _call(
        "confirm_risk_assessment",
        product,
        owner,
        rationale="Reviewed with the maintainers against the shipped topology.",
    )


# ---- ordering ----------------------------------------------------------------


def test_an_unclassified_product_has_nothing_to_assess_against(product, owner):
    r = _started(product, owner)
    assert r["ok"] is False
    assert "classify_product" in r["error"]


def test_an_out_of_scope_product_carries_no_article_13_duty(product, owner):
    _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=False,
        rationale="Pure SaaS, not placed on the market as a product.",
    )
    r = _started(product, owner)
    assert r["ok"] is False and "out of scope" in r["error"]


def test_classification_points_at_the_assessment_not_the_checklist(product, owner):
    """The order is the regulation's, not a preference."""
    r = _call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Ordinary product with digital elements.",
    )
    assert "start_risk_assessment" in r["next"]


def test_the_frame_offers_the_part_i_requirements_to_map_onto(scoped, owner):
    r = _started(scoped, owner)
    assert r["ok"] is True
    ids = {x["req_id"] for x in r["map_risks_onto"]}
    assert ids == {x.id for x in requirements() if x.part == "part_i"}
    assert "Part II" in r["note_on_part_ii"]


def test_the_frame_reuses_what_the_product_row_already_says(scoped, owner):
    """Not re-asking the user something they have already answered."""
    r = _call("start_risk_assessment", scoped, owner, method="STRIDE")
    assert r["scope"]["intended_purpose"] == (
        "Fronts internal services for enterprise customers"
    )


# ---- a draft determines nothing ----------------------------------------------


def test_a_proposal_changes_no_requirement(scoped, owner):
    _started(scoped, owner)
    r = _proposed(scoped, owner)
    assert r["ok"] is True
    assert r["added"][0]["status"] == "proposed"
    assert "No requirement's applicability has changed" in r["determined_nothing"]

    item = next(
        x
        for x in _call("list_requirements", scoped, owner)["requirements"]
        if x["req_id"] == REQ
    )
    assert item["applicability"] == "undetermined"
    assert "risk_basis" not in item


def test_a_proposal_records_the_model_that_drafted_it(scoped, owner):
    """`actor_model` was never populated anywhere before this. For an
    AI-drafted legal artifact the trail has to say which model wrote it."""
    _started(scoped, owner)
    _proposed(scoped, owner, model="claude-opus-5")

    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == scoped, AuditEvent.op == "propose_risks")
            .one()
        )
        assert row.actor_kind == "model"
        assert row.actor_model == "claude-opus-5"
        # The accountable human is recorded separately — "a model did it" is
        # not an answer to who is answerable.
        assert row.accountable_user_id == owner


def test_drafting_without_a_basis_is_refused(scoped, owner):
    _started(scoped, owner)
    r = _call(
        "propose_risks",
        scoped,
        owner,
        basis="",
        risks=[{"title": "Something"}],
    )
    assert r["ok"] is False and "basis is required" in r["error"]


def test_invented_requirement_ids_are_dropped_not_stored(scoped, owner):
    _started(scoped, owner)
    r = _proposed(scoped, owner, affects=[REQ, "annex_i.i.99"])
    assert r["dropped_requirement_refs"] == {"risk-001": ["annex_i.i.99"]}
    assert r["added"][0]["affects_requirements"] == [REQ]


# ---- deciding ----------------------------------------------------------------


def test_a_decision_without_reasoning_is_refused(scoped, owner):
    _started(scoped, owner)
    _proposed(scoped, owner)
    r = _call(
        "decide_risk", scoped, owner, risk_id="risk-001", decision="accept", rationale=""
    )
    assert r["ok"] is False and "rationale is required" in r["error"]


def test_accepting_a_risk_requires_a_treatment(scoped, owner):
    """'We are living with this' is legitimate — as a recorded decision, not an
    omission."""
    _started(scoped, owner)
    _proposed(scoped, owner)
    r = _call(
        "decide_risk",
        scoped,
        owner,
        risk_id="risk-001",
        decision="accept",
        rationale="Considered and understood.",
    )
    assert r["ok"] is False and "treatment" in r["error"]


def test_a_decision_is_recorded_as_a_human_act(scoped, owner):
    _accepted(scoped, owner, model="claude-opus-5")
    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == scoped, AuditEvent.op == "decide_risk")
            .one()
        )
    assert row.actor_kind == "human"
    assert row.accountable_user_id == owner
    # The draft's provenance travels with the decision, so the trail shows a
    # person signed off on something a model wrote.
    assert row.payload["drafted_by_model"] == "claude-opus-5"


def test_an_unknown_risk_id_is_refused(scoped, owner):
    _started(scoped, owner)
    _proposed(scoped, owner)
    r = _call(
        "decide_risk",
        scoped,
        owner,
        risk_id="risk-999",
        decision="reject",
        rationale="n/a",
    )
    assert r["ok"] is False and "no risk" in r["error"]


# ---- confirming --------------------------------------------------------------


def test_confirming_with_undecided_drafts_is_refused(scoped, owner):
    """Otherwise a model's unreviewed output is frozen into a ten-year artifact
    as though a person had agreed with it."""
    _started(scoped, owner)
    _proposed(scoped, owner)
    r = _call("confirm_risk_assessment", scoped, owner, rationale="Looks fine.")
    assert r["ok"] is False
    assert "undecided" in r["error"] and "risk-001" in r["error"]


def test_an_assessment_with_no_risks_at_all_is_refused(scoped, owner):
    _started(scoped, owner)
    r = _call("confirm_risk_assessment", scoped, owner, rationale="Nothing found.")
    assert r["ok"] is False and "no risks at all" in r["error"]


def test_an_assessment_with_no_stated_scope_is_refused(scoped, owner):
    _call("start_risk_assessment", scoped, owner, method="STRIDE")
    _proposed(scoped, owner)
    _call(
        "decide_risk",
        scoped,
        owner,
        risk_id="risk-001",
        decision="accept",
        treatment="mitigate",
        rationale="Real.",
    )
    r = _call("confirm_risk_assessment", scoped, owner, rationale="Done.")
    assert r["ok"] is False
    assert "foreseeable_misuse" in r["error"]


def test_confirming_without_a_rationale_is_refused(scoped, owner):
    _accepted(scoped, owner)
    r = _call("confirm_risk_assessment", scoped, owner, rationale="")
    assert r["ok"] is False and "rationale is required" in r["error"]


def test_confirming_makes_named_requirements_applicable_with_their_basis(scoped, owner):
    r = _confirmed(scoped, owner, affects=[REQ, REQ_B])
    assert r["ok"] is True
    assert {m["req_id"] for m in r["requirements_made_applicable"]} == {REQ, REQ_B}

    items = {
        x["req_id"]: x
        for x in _call("list_requirements", scoped, owner)["requirements"]
    }
    assert items[REQ]["applicability"] == "applicable"
    assert items[REQ]["risk_basis"] == ["risk-001"]


def test_confirming_never_rules_anything_out(scoped, owner):
    """The failure mode the whole design exists to prevent."""
    r = _confirmed(scoped, owner, affects=[REQ])
    assert r["still_undetermined"], "other Part I requirements should be unanswered"

    items = _call("list_requirements", scoped, owner)["requirements"]
    assert not [x for x in items if x["applicability"] == "not_applicable"]
    # And they are still counted as gaps, not quietly settled.
    gaps = _call("list_requirements", scoped, owner, filter="gaps")
    assert set(r["still_undetermined"]) <= {x["req_id"] for x in gaps["requirements"]}


def test_confirming_says_part_ii_is_not_answered_by_the_assessment(scoped, owner):
    r = _confirmed(scoped, owner)
    part_ii = {x.id for x in requirements() if x.part == "part_ii"}
    assert set(r["part_ii_still_undetermined"]) == part_ii
    assert "regardless of the risk assessment" in r["part_ii_note"]


def test_confirming_freezes_a_hashed_copy(scoped, owner):
    r = _confirmed(scoped, owner)
    assert len(r["content_hash"]) == 64

    with session_scope() as s:
        row = s.get(Evidence, r["evidence_id"])
    assert row.sha256 == r["content_hash"]
    assert row.subject_ref == "risk_assessment:v1"
    # Rejected risks stay in the frozen copy: "we considered this and ruled it
    # out" is evidence of a thorough assessment.
    assert "Unauthenticated access to the admin API" in row.inline_body


def test_an_accepted_risk_reopens_a_requirement_that_was_ruled_out(scoped, owner):
    _call(
        "update_requirement",
        scoped,
        owner,
        req_id=REQ,
        applicability="not_applicable",
        justification="We believed this could not be reached from outside.",
    )
    r = _confirmed(scoped, owner, affects=[REQ])
    assert [x["req_id"] for x in r["reopened"]] == [REQ]
    assert "contradiction" in r["reopened_note"] or "resolve" in r["reopened_note"]


def test_a_requirement_a_risk_names_cannot_then_be_ruled_out(scoped, owner):
    """Recording both would put a contradiction into Annex VII(3)."""
    _confirmed(scoped, owner, affects=[REQ])
    r = _call(
        "update_requirement",
        scoped,
        owner,
        req_id=REQ,
        applicability="not_applicable",
        justification="On reflection, out of reach.",
    )
    assert r["ok"] is False
    assert "risk assessment says it applies" in r["error"]


# ---- evidence against a risk --------------------------------------------------


def test_evidence_can_be_filed_against_a_risk(scoped, owner):
    _confirmed(scoped, owner)
    r = _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="risk:risk-001",
        title="Threat model review notes",
        body="Reviewed 2026-08-01 with the platform team.",
        source_ref="git:abc1234",
    )
    assert r["ok"] is True


def test_evidence_against_a_risk_that_does_not_exist_is_refused(scoped, owner):
    """`risk` was an accepted subject kind with no existence check, so this
    filed silently into a row nobody would ever find."""
    _confirmed(scoped, owner)
    r = _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="risk:risk-404",
        title="Notes",
        body="...",
        source_ref="git:abc1234",
    )
    assert r["ok"] is False and "no risk" in r["error"]


# ---- what the technical file now requires -------------------------------------


def _settle_everything(product, owner):
    """Fill the file the old way — no risk assessment anywhere."""
    for req in requirements():
        _call(
            "update_requirement",
            product,
            owner,
            req_id=req.id,
            applicability="applicable",
            status="verified",
        )
        _call(
            "attach_evidence",
            product,
            owner,
            subject_ref=f"requirement:{req.id}",
            title=f"evidence for {req.id}",
            body="artifact",
            source_ref="git:abc1234",
        )
    # tf.4 completes from the Article 13(8) determination rather than an
    # attachment, so filling it means making the determination.
    _call(
        "set_support_period",
        product,
        owner,
        start="2026-01-01T00:00:00Z",
        end="2031-06-30T00:00:00Z",
        rationale="Five and a half years; the platform we depend on is supported to mid-2031.",
    )
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
        if slot.auto_from_part or slot.satisfied_by in (
            "support_period",
            "declaration_of_conformity",
        ):
            continue
        _call(
            "attach_evidence",
            product,
            owner,
            subject_ref=f"technical_file:{slot.id}",
            title=slot.title,
            body="artifact",
            source_ref="git:abc1234",
        )


def test_a_file_cannot_be_frozen_without_an_assessment(scoped, owner):
    """The regression this feature exists to close.

    Every requirement settled, every slot evidenced — and Annex VII(3) is still
    not satisfied, because the section is titled "cybersecurity risk
    assessment" and there isn't one.
    """
    _settle_everything(scoped, owner)

    view = _call("assemble_technical_file", scoped, owner)
    tf3 = next(s for s in view["slots"] if s["slot"] == "tf.3")
    assert tf3["complete"] is False
    assert tf3["risk_assessment"]["confirmed"] is False
    assert "Article 13(2)" in tf3["risk_assessment"]["missing"]

    frozen = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert frozen["ok"] is False
    assert "tf.3" in frozen["error"]


def test_the_same_file_freezes_once_the_assessment_is_confirmed(scoped, owner):
    _settle_everything(scoped, owner)
    assert _call("assemble_technical_file", scoped, owner, finalize=True)["ok"] is False

    _confirmed(scoped, owner)
    r = _call("assemble_technical_file", scoped, owner, finalize=True)
    assert r["ok"] is True and r["finalized"] is True

    tf3 = next(s for s in r["slots"] if s["slot"] == "tf.3")
    assert tf3["risk_assessment"]["confirmed"] is True
    assert tf3["risk_assessment"]["content_hash"]


def test_reclassifying_makes_the_assessment_stale_in_the_file(scoped, owner):
    """Article 13(3): kept up to date. A class change is exactly the kind of
    change that invalidates the assessment behind it."""
    _settle_everything(scoped, owner)
    _confirmed(scoped, owner)
    assert _call("assemble_technical_file", scoped, owner, finalize=True)["ok"] is True

    _call(
        "classify_product",
        scoped,
        owner,
        product_class="important_class_ii",
        in_scope=True,
        rationale="Reassessed: it is an Annex III class II category after all.",
    )
    view = _call("assemble_technical_file", scoped, owner)
    tf3 = next(s for s in view["slots"] if s["slot"] == "tf.3")
    assert tf3["complete"] is False
    assert any(
        x["reason"] == "classification_changed" for x in tf3["risk_assessment"]["stale_reasons"]
    )


# ---- revision ----------------------------------------------------------------


def test_editing_a_confirmed_assessment_opens_the_next_version(scoped, owner):
    """Revision is the normal case — Article 13(3) requires it kept current."""
    first = _confirmed(scoped, owner)
    assert first["version"] == 1

    r = _proposed(scoped, owner, affects=[REQ_B])
    assert r["opened_new_version"] == 2

    view = _call("get_risk_assessment", scoped, owner)
    assert view["assessment"]["version"] == 2
    assert view["assessment"]["status"] == "draft"
    # v1 stays frozen and citable while v2 is in flight.
    assert view["assessment"]["content_hash"] == first["content_hash"]
    assert view["assessment"]["stale"] is True


def test_the_frozen_copy_of_the_previous_version_survives(scoped, owner):
    first = _confirmed(scoped, owner)
    _proposed(scoped, owner, affects=[REQ_B])

    with session_scope() as s:
        row = s.get(Evidence, first["evidence_id"])
    assert row is not None and row.sha256 == first["content_hash"]


def test_status_leads_with_the_assessment_above_the_checklist(scoped, owner):
    before = _call("get_compliance_status", scoped, owner)
    assert before["risk_assessment"]["present"] is False
    assert "start_risk_assessment" in before["risk_assessment"]["next"]

    _confirmed(scoped, owner)
    after = _call("get_compliance_status", scoped, owner)
    assert after["risk_assessment"]["present"] is True
    assert after["risk_assessment"]["stale"] is False
    assert after["requirements"]["by_applicability"]["applicable"] >= 1


# ---- issue #27: a one-character 13(3) statement froze into a ten-year artefact -


def test_confirming_echoes_the_13_3_statements_it_is_sealing(scoped, owner):
    """The check is presence, not substance: it strips whitespace and accepts
    whatever remains. The run set `part_ii_approach = 'x'`, confirmed, and the
    technical file then reported the section satisfied.

    No threshold and no refusal — no mechanical test measures a reason, and the
    run said so itself. What was missing was that nobody saw the text before it
    sealed, and this is the last moment that is true.
    """
    _accepted(scoped, owner)
    out = _call("confirm_risk_assessment", scoped, owner, rationale="Reviewed by the team.")
    assert out["ok"] is True, out

    frozen = out["frozen_article_13_3_statements"]
    assert set(frozen) == {"part_i_1_approach", "part_ii_approach"}
    for k, v in frozen.items():
        assert "text" in v and "chars" in v, (k, v)
        assert v["chars"] == len(v["text"].strip())

    said = out["check_what_was_frozen"]
    assert "Annex VII(3)" in said
    assert "13(3)" in said


def test_a_thin_statement_is_visible_in_what_was_frozen(scoped, owner):
    """'x' is still accepted — that is the manufacturer's call — but it comes
    back with its length so the caller cannot relay 'recorded' without seeing
    what was recorded."""
    _started(scoped, owner, part_i_1_approach="Threat modelling per release.",
             part_ii_approach="x")
    _proposed(scoped, owner)
    _call("decide_risk", scoped, owner, risk_id="risk-001", decision="accept",
          treatment="mitigate", rationale="Real for our topology.")

    out = _call("confirm_risk_assessment", scoped, owner, rationale="Reviewed.")
    assert out["ok"] is True, out
    assert out["frozen_article_13_3_statements"]["part_ii_approach"]["chars"] == 1
    assert out["frozen_article_13_3_statements"]["part_ii_approach"]["text"] == "x"
