"""Article 13(3)'s last sentence, and the Article 13(20) short form.

Issues #5 and #6 — roadmap 1.4 and 1.5, the two items that finish Phase 1.

**13(3)** was filed as a bug rather than a feature, and the framing is right:
confirming used to freeze an assessment that did not contain everything the
paragraph requires of it, and that assessment is the artefact Annex VII(3)
cites. The risks and their `affects_requirements` answer Part I(2) — which of
the fourteen product requirements apply, and why. The paragraph asks for two
further things *in addition*, and neither is a per-risk determination.

**13(20)** permits a simplified declaration in place of a full copy on one
condition: it carries the exact internet address of the full one. That address
is the entire reason the short form is allowed, so an address-less simplified
declaration is not a shorter declaration — it is a non-compliant one.
"""

from __future__ import annotations

import json
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

SCOPE = {
    "method": "STRIDE",
    "intended_purpose": "An API gateway fronting internal services",
    "foreseeable_misuse": "Deployed on the public internet with no WAF",
    "conditions_of_use": "Customer-operated Kubernetes cluster",
    "support_duration_note": "Five years from GA",
}
HOW_APPLIED = {
    "part_i_1_approach": (
        "Threat modelling each release against the accepted risks; controls "
        "tracked as Annex I requirements with evidence per release."
    ),
    "part_ii_approach": (
        "SBOM on every build, daily advisory scanning, a published CVD policy, "
        "and the Article 14 clocks run from this tool."
    ),
}


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def scoped(owner):
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
    _call(
        "classify_product",
        pid,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Not listed in Annex III or IV.",
    )
    return pid


def _assess(product, owner, **overrides):
    args = {**SCOPE, **HOW_APPLIED, **overrides}
    _call("start_risk_assessment", product, owner, **args)
    _call(
        "propose_risks",
        product,
        owner,
        basis="repository at HEAD plus the deployment topology",
        risks=[
            {
                "title": "Unauthenticated access to the admin API",
                "asset": "administrative control plane",
                "threat": "an unauthenticated caller reconfigures routing",
                "affects_requirements": ["annex_i.i.2.d"],
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
        rationale="Real for our topology; mitigated by mTLS.",
    )


def _confirm(product, owner):
    return _call(
        "confirm_risk_assessment", product, owner, rationale="Reviewed by the team."
    )


# ---- Article 13(3), last sentence -------------------------------------------------


def test_confirming_without_the_part_i_1_statement_is_refused(scoped, owner):
    _assess(scoped, owner, part_i_1_approach="")
    out = _confirm(scoped, owner)
    assert out["ok"] is False
    assert "Annex I Part I(1)" in out["error"]
    assert "part_i_1_approach" in out["error"]


def test_confirming_without_the_part_ii_statement_is_refused(scoped, owner):
    _assess(scoped, owner, part_ii_approach="")
    out = _confirm(scoped, owner)
    assert out["ok"] is False
    assert "Annex I Part II" in out["error"]


def test_the_error_says_which_part_of_13_3_is_unmet(scoped, owner):
    """Not a bare validation message — the same standard the scope check
    already sets. A user who does not know 13(3) has a last sentence needs to
    be told what is being asked for and why the risks did not cover it."""
    _assess(scoped, owner, part_i_1_approach="", part_ii_approach="")
    error = _confirm(scoped, owner)["error"]
    assert "Article 13(3) requires the assessment to *also* indicate" in error
    assert "cover Part I(2) applicability; this is the rest of the paragraph" in error
    assert "appropriate level of cybersecurity based on the risks" in error
    assert "vulnerability handling requirements" in error


def test_both_present_confirms(scoped, owner):
    _assess(scoped, owner)
    assert _confirm(scoped, owner)["ok"] is True


def test_the_statements_are_inside_the_hashed_body(scoped, owner):
    """Annex VII(3) cites the frozen assessment. All of 13(3) has to be in the
    artefact, not two thirds of it with the rest as metadata."""
    _assess(scoped, owner)
    _confirm(scoped, owner)

    state = store_pg.load_state(scoped)
    with session_scope() as s:
        row = s.get(Evidence, state.risk_assessment.evidence_id)
    body = json.loads(row.inline_body)
    assert body["how_applied"]["annex_i_part_i_1"].startswith("Threat modelling")
    assert body["how_applied"]["annex_i_part_ii"].startswith("SBOM on every build")


def test_changing_a_statement_changes_the_content_hash(scoped, owner):
    """It is part of the assessment, so editing it has to move the hash a
    signature binds to — otherwise the two could disagree silently."""
    _assess(scoped, owner)
    _confirm(scoped, owner)
    first = store_pg.load_state(scoped).risk_assessment.content_hash

    _call(
        "start_risk_assessment",
        scoped,
        owner,
        part_ii_approach="SBOM per build, scanning, CVD policy, and a release gate.",
    )
    _call(
        "decide_risk",
        scoped,
        owner,
        risk_id="risk-001",
        decision="accept",
        treatment="mitigate",
        rationale="Unchanged.",
    )
    _confirm(scoped, owner)
    assert store_pg.load_state(scoped).risk_assessment.content_hash != first


def test_the_worksheet_asks_for_them_up_front(scoped, owner):
    """The point of returning a worksheet is that it names everything the
    paragraph wants. Discovering these when confirming is refused would be the
    worksheet failing at its job."""
    out = _call("start_risk_assessment", scoped, owner, method="STRIDE")
    assert "part_i_1_approach" in out["scope_gaps"]
    assert "part_ii_approach" in out["scope_gaps"]
    assert out["how_applied"] == {"annex_i_part_i_1": "", "annex_i_part_ii": ""}


# ---- Article 13(20), the simplified declaration -------------------------------------


def _full_declaration(product, owner):
    """Everything the full declaration rests on, then the declaration itself."""
    _assess(product, owner)
    _confirm(product, owner)
    _call("set_submitter_profile", product, owner, legal_name="Acme B.V.")
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
    _call(
        "set_support_period",
        product,
        owner,
        start="2026-01-01T00:00:00Z",
        end="2031-06-30T00:00:00Z",
        rationale="Five and a half years; platform supported to mid-2031.",
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
    assert _call("assemble_technical_file", product, owner, finalize=True)["ok"] is True
    out = _call(
        "generate_declaration_of_conformity",
        product,
        owner,
        standards_applied="EN 18031-1:2024",
    )
    assert out["ok"] is True, out
    return out


def test_the_short_form_needs_a_full_declaration_to_point_at(scoped, owner):
    """13(20) permits it *instead of a copy of the full one*, so there has to
    be a full one."""
    out = _call(
        "generate_simplified_declaration",
        scoped,
        owner,
        full_declaration_url="https://acme.example/doc",
    )
    assert out["ok"] is False
    assert "no full declaration to point at" in out["error"]


def test_an_address_less_short_form_is_refused(scoped, owner):
    """#6's 'Done when'. The address is the entire reason the short form is
    permitted, so without it this is not a simplified declaration."""
    _full_declaration(scoped, owner)
    out = _call("generate_simplified_declaration", scoped, owner, full_declaration_url="")
    assert out["ok"] is False
    assert "exact internet address" in out["error"]


@pytest.mark.parametrize(
    "bad",
    ["/declarations/acme", "acme.example/doc", "ftp://acme.example/doc", "localhost"],
)
def test_an_address_a_reader_could_not_type_is_refused(scoped, owner, bad):
    _full_declaration(scoped, owner)
    out = _call("generate_simplified_declaration", scoped, owner, full_declaration_url=bad)
    assert out["ok"] is False
    assert "exact" in out["error"] or "absolute" in out["error"]


def test_a_good_address_renders_the_short_form(scoped, owner):
    _full_declaration(scoped, owner)
    url = "https://acme.example/compliance/gateway-doc.pdf"
    out = _call("generate_simplified_declaration", scoped, owner, full_declaration_url=url)

    assert out["ok"] is True
    assert out["form"] == "simplified"
    assert out["full_declaration_url"] == url
    assert url in out["markdown"]
    assert "Simplified EU Declaration of Conformity" in out["markdown"]
    assert "Acme B.V." in out["markdown"]


def test_it_says_the_address_is_never_fetched(scoped, owner):
    """Same discipline as `disclosure_policy_url`. Claiming to have checked
    would be worse than not checking, and fetching a user-supplied URL
    server-side is an SSRF surface for no gain — a 200 proves only that
    something is served there."""
    _full_declaration(scoped, owner)
    out = _call(
        "generate_simplified_declaration",
        scoped,
        owner,
        full_declaration_url="https://acme.example/doc",
    )
    assert "never fetched" in out["address_not_checked"]
    assert "keeping it reachable is yours" in out["address_not_checked"]


def test_it_points_at_the_full_declaration_by_hash(scoped, owner):
    """So a re-issued full declaration is detectable rather than silently
    leaving the short form pointing at a superseded version."""
    full = _full_declaration(scoped, owner)
    out = _call(
        "generate_simplified_declaration",
        scoped,
        owner,
        full_declaration_url="https://acme.example/doc",
    )
    assert out["points_at_declaration_hash"] == full["content_hash"]
    assert "points at a superseded version" in out["next"]


def test_the_address_survives_on_the_record_and_the_trail(scoped, owner):
    """13(20) makes the address a required element, so it cannot live only in
    a rendered document somebody throws away."""
    _full_declaration(scoped, owner)
    url = "https://acme.example/doc"
    _call("generate_simplified_declaration", scoped, owner, full_declaration_url=url)

    assert store_pg.load_state(scoped).conformity_declaration_url == url
    with session_scope() as s:
        ev = (
            s.query(AuditEvent)
            .filter(
                AuditEvent.product_id == scoped,
                AuditEvent.op == "generate_simplified_declaration",
            )
            .one()
        )
        assert ev.payload["full_declaration_url"] == url


def test_a_steward_is_told_the_regime_does_not_apply(owner):
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Steward Lib",
            economic_operator_role="open_source_steward",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    out = _call(
        "generate_simplified_declaration",
        pid,
        owner,
        full_declaration_url="https://acme.example/doc",
    )
    assert out["ok"] is False
    assert "Article 24" in out["error"]
