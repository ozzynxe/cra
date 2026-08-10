"""The Annex II checklist, and what tf.1 now reports — issue #4.

Article 13(18) requires the product to be *accompanied by* this information.
Before this it was one line in `tf.1`'s `needs`, satisfied by attaching a
document and hoping it said the right things — which is exactly the "we tracked
it in a spreadsheet" failure the product exists to replace.

The audience is what makes Annex II different from everything else here. The
technical file is for market surveillance authorities; this is what a *user*
receives. So the useful record is not "we provide it" but where they find it.
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
from cra.regulation import user_information  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


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


def _tf1(product, owner):
    tf = _call("assemble_technical_file", product, owner)
    return next(s for s in tf["slots"] if s["slot"] == "tf.1")


# ---- seeding --------------------------------------------------------------------


def test_an_unclassified_product_says_where_the_checklist_comes_from(product, owner):
    out = _call("list_user_information", product, owner)
    assert out["count"] == 0
    assert "classify_product" in out["note"]


def test_classifying_in_scope_seeds_every_item(scoped, owner):
    out = _call("list_user_information", scoped, owner)
    assert out["count"] == len(user_information()) == 15
    assert out["gaps_total"] == 15, "everything starts unsettled"


def test_reclassifying_does_not_discard_work(scoped, owner):
    """Same contract as the Annex I seeding: re-classifying must not throw away
    what somebody already recorded."""
    _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.1",
        provided=True,
        location="README, 'Contact' section",
    )
    _call(
        "classify_product",
        scoped,
        owner,
        product_class="important_class_i",
        in_scope=True,
        rationale="Reconsidered against Annex III.",
    )
    item = next(
        i
        for i in _call("list_user_information", scoped, owner)["items"]
        if i["item_id"] == "annex_ii.1"
    )
    assert item["provided"] is True
    assert item["location"].startswith("README")


# ---- working the list -------------------------------------------------------------


def test_providing_an_item_settles_it(scoped, owner):
    out = _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.7",
        provided=True,
        location="docs/support.md",
    )
    assert out["ok"] is True
    assert out["item"]["settled"] is True
    assert "still_a_gap" not in out


def test_provided_without_a_location_is_recorded_but_flagged(scoped, owner):
    """Not refused: "provided" is true or it is not, and the tool should not
    withhold a true statement over a missing pointer. Flagged, because an
    auditor's next question is always where."""
    out = _call(
        "update_user_information", scoped, owner, item_id="annex_ii.7", provided=True
    )
    assert out["ok"] is True
    assert out["item"]["settled"] is True
    assert "update_user_information(location=" in out["where"]


def test_ruling_an_item_out_without_a_reason_is_refused(scoped, owner):
    out = _call(
        "update_user_information", scoped, owner, item_id="annex_ii.9", not_applicable=True
    )
    assert out["ok"] is False
    assert "cannot be ruled out without a justification" in out["error"]


def test_a_conditional_item_says_why_the_reason_still_matters(scoped, owner):
    """Four items are conditional in the annex's own words, so ruling one out
    is often right — which is exactly why the reason has to be recorded, or
    "where applicable" becomes a way to empty the annex."""
    out = _call(
        "update_user_information", scoped, owner, item_id="annex_ii.9", not_applicable=True
    )
    assert "The annex qualifies this item" in out["error"]
    assert "decides to make available the software bill of materials" in out["error"]


def test_an_unconditional_item_is_refused_rather_than_asked_for_a_reason(scoped, owner):
    """This used to ask for a justification, quoting the Annex II chapeau.

    Asking implies a reason could make a required item optional. It cannot —
    eleven of the fifteen are stated unconditionally — and an end-to-end run
    took the invitation and emptied the whole annex with one sentence. So the
    refusal is now flat, and names the four items where ruling out is real.
    """
    out = _call(
        "update_user_information", scoped, owner, item_id="annex_ii.3", not_applicable=True
    )
    assert out["ok"] is False
    assert "unconditionally" in out["error"]


def test_a_justified_exclusion_settles(scoped, owner):
    out = _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.9",
        not_applicable=True,
        justification="We do not publish the SBOM to users; it goes to authorities on request.",
    )
    assert out["ok"] is True
    assert out["item"]["settled"] is True
    assert out["item"]["justification"].startswith("We do not publish")


def test_provided_and_not_applicable_are_mutually_exclusive(scoped, owner):
    """A newer statement wins rather than the call being refused: the caller
    has just said which is true."""
    _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.6",
        not_applicable=True,
        justification="The declaration ships as a copy, not a URL.",
    )
    out = _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.6",
        provided=True,
        location="https://acme.example/doc",
    )
    assert out["item"]["provided"] is True
    assert out["item"]["not_applicable"] is False
    assert "justification" not in out["item"]


def test_an_empty_update_is_refused(scoped, owner):
    assert _call("update_user_information", scoped, owner, item_id="annex_ii.1")["ok"] is False


def test_an_unknown_item_is_refused_with_the_id_shape(scoped, owner):
    out = _call("update_user_information", scoped, owner, item_id="annex_ii.99")
    assert out["ok"] is False
    assert "annex_ii.1" in out["error"]


def test_the_decision_is_audited(scoped, owner):
    _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.9",
        not_applicable=True,
        justification="Not published to users.",
    )
    with session_scope() as s:
        ev = (
            s.query(AuditEvent)
            .filter(
                AuditEvent.product_id == scoped,
                AuditEvent.op == "update_user_information",
            )
            .one()
        )
        assert ev.subject_id == "annex_ii.9"
        assert ev.payload["not_applicable"] is True


# ---- filters and evidence ----------------------------------------------------------


def test_the_conditional_filter_returns_the_four(scoped, owner):
    out = _call("list_user_information", scoped, owner, filter="conditional")
    assert {i["item_id"] for i in out["items"]} == {
        "annex_ii.6",
        "annex_ii.8.e",
        "annex_ii.8.f",
        "annex_ii.9",
    }
    assert all(i["conditional"] for i in out["items"])


def test_the_gaps_filter_shrinks_as_items_settle(scoped, owner):
    before = _call("list_user_information", scoped, owner, filter="gaps")["count"]
    _call(
        "update_user_information",
        scoped,
        owner,
        item_id="annex_ii.1",
        provided=True,
        location="README",
    )
    assert _call("list_user_information", scoped, owner, filter="gaps")["count"] == before - 1


def test_an_unknown_filter_is_refused(scoped, owner):
    assert _call("list_user_information", scoped, owner, filter="urgent")["ok"] is False


def test_evidence_can_be_attached_to_an_item(scoped, owner):
    out = _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="user_info:annex_ii.8.a",
        title="Secure commissioning guide",
        body="1. Change the default credentials...",
        source_ref="git:abc1234",
    )
    assert out["ok"] is True
    item = next(
        i
        for i in _call("list_user_information", scoped, owner)["items"]
        if i["item_id"] == "annex_ii.8.a"
    )
    assert item["evidence_count"] == 1


def test_evidence_for_an_item_that_does_not_exist_is_refused(scoped, owner):
    out = _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="user_info:annex_ii.99",
        title="x",
        body="y",
        source_ref="git:abc",
    )
    assert out["ok"] is False
    assert "list_user_information()" in out["error"]


# ---- tf.1 -----------------------------------------------------------------------------


def test_tf1_reports_item_level_coverage(scoped, owner):
    """#4's first 'Done when': item-level coverage instead of "nothing
    attached"."""
    slot = _tf1(scoped, owner)
    assert slot["annex_ii_coverage"]["total"] == 15
    assert slot["annex_ii_coverage"]["settled"] == 0
    assert len(slot["annex_ii_coverage"]["unsettled"]) == 15


def test_tf1_needs_both_its_own_evidence_and_the_checklist(scoped, owner):
    """tf.1 is not only Annex II — it also wants the general description, the
    software versions and, for hardware, photographs. Settling the checklist
    must not complete the slot on its own."""
    for item in user_information():
        _call(
            "update_user_information",
            scoped,
            owner,
            item_id=item.id,
            provided=True,
            location="docs/security.md",
        )
    slot = _tf1(scoped, owner)
    assert slot["annex_ii_coverage"]["settled"] == 15
    assert slot["complete"] is False
    assert "no general description attached" in slot["missing"]

    _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="technical_file:tf.1",
        title="General description",
        body="An API gateway...",
        source_ref="git:abc1234",
    )
    assert _tf1(scoped, owner)["complete"] is True


def test_an_unsettled_item_keeps_the_slot_open(scoped, owner):
    _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="technical_file:tf.1",
        title="General description",
        body="An API gateway...",
        source_ref="git:abc1234",
    )
    for item in user_information():
        if item.id == "annex_ii.8.f":
            continue
        _call(
            "update_user_information",
            scoped,
            owner,
            item_id=item.id,
            provided=True,
            location="docs/security.md",
        )
    slot = _tf1(scoped, owner)
    assert slot["complete"] is False
    assert slot["annex_ii_coverage"]["unsettled"] == ["annex_ii.8.f"]
    assert "1 Annex II item(s) unsettled" in slot["missing"]


def test_a_justified_exclusion_counts_as_settled_for_the_slot(scoped, owner):
    """Ruling an item out with a reason is a real answer, not a gap."""
    _call(
        "attach_evidence",
        scoped,
        owner,
        subject_ref="technical_file:tf.1",
        title="General description",
        body="An API gateway...",
        source_ref="git:abc1234",
    )
    for item in user_information():
        if item.id == "annex_ii.9":
            _call(
                "update_user_information",
                scoped,
                owner,
                item_id=item.id,
                not_applicable=True,
                justification="We do not publish the SBOM to users.",
            )
        else:
            _call(
                "update_user_information",
                scoped,
                owner,
                item_id=item.id,
                provided=True,
                location="docs/security.md",
            )
    slot = _tf1(scoped, owner)
    assert slot["complete"] is True
    assert slot["annex_ii_coverage"]["not_applicable"] == ["annex_ii.9"]


# ---- issue #22: "where applicable" emptied the whole annex ---------------------


def test_an_unconditional_annex_ii_item_cannot_be_ruled_out(scoped, owner):
    """Eleven of the fifteen items are stated unconditionally, so there is no
    lawful basis for ruling them out — and asking for a justification implies
    there is one. An end-to-end run emptied all fifteen with the phrase "where
    applicable", including the manufacturer's name and the vulnerability
    reporting contact."""
    out = _call(
        "update_user_information", scoped, owner,
        item_id="annex_ii.1", not_applicable=True,
        justification="Where applicable — this does not apply to our product.",
    )
    assert out["ok"] is False, "the manufacturer's details were ruled out"
    said = str(out.get("error", "")).lower()
    assert "unconditionally" in said
    assert "conditional" in said, "the refusal must name the way out"


def test_the_four_conditional_items_can_still_be_ruled_out(scoped, owner):
    """The annex qualifies four of them in its own words, so ruling one out is
    routine and must stay possible — with a reason."""
    from cra.regulation import user_information

    conditional = [i.id for i in user_information() if i.conditional]
    assert len(conditional) == 4, conditional
    out = _call(
        "update_user_information", scoped, owner,
        item_id=conditional[0], not_applicable=True,
        justification="No remote data processing is involved in this product.",
    )
    assert out["ok"] is True, out


def test_a_conditional_item_still_needs_a_reason(scoped, owner):
    from cra.regulation import user_information

    conditional = [i.id for i in user_information() if i.conditional][0]
    out = _call("update_user_information", scoped, owner,
                item_id=conditional, not_applicable=True)
    assert out["ok"] is False, out
