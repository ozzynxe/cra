"""The risk assessment's derivations, which need no database.

Two things are tested here rather than in the integration suite because they
are pure functions and because they are the parts that must not regress:

  `apply_to_requirements` — what a confirmed assessment does to the checklist.
  `staleness`             — whether a confirmed assessment still describes the
                            product, derived rather than stored.

The handler-level guards (ordering, rationale, undecided risks) live in
`tests/integration/test_risk_assessment.py` because every mutation writes an
audit row, and that needs Postgres.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cra.regulation import requirements
from cra.schemas import ComplianceState, MemberInfo, RequirementItem, RiskAssessment, RiskItem, Role
from cra.schemas.enums import (
    Applicability,
    AssessmentStatus,
    Lifecycle,
    ProductClass,
    RiskStatus,
    RiskTreatment,
)
from cra.server import risk

UTC = timezone.utc
NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)

PART_I = [r.id for r in requirements() if r.part == "part_i"]
PART_II = [r.id for r in requirements() if r.part == "part_ii"]


def _state(**kw) -> ComplianceState:
    s = ComplianceState(
        product_id="p1",
        name="Acme Gateway",
        members={"u1": MemberInfo(role=Role.OWNER, user_id="u1", joined_at=NOW)},
        created_at=NOW,
        updated_at=NOW,
        **kw,
    )
    s.classification.in_scope = True
    s.classification.product_class = ProductClass.DEFAULT
    s.requirements = [
        RequirementItem(req_id=r.id, title=r.anchor, text=r.summary)
        for r in requirements()
    ]
    return s


def _risk(risk_id="risk-001", *, affects, status=RiskStatus.ACCEPTED) -> RiskItem:
    return RiskItem(
        risk_id=risk_id,
        title="Unauthenticated admin API",
        status=status,
        treatment=RiskTreatment.MITIGATE,
        affects_requirements=list(affects),
        decided_by="u1",
        decided_at=NOW,
        decision_rationale="confirmed by the maintainer",
    )


# ---- what a confirmed assessment does to the checklist -----------------------


def test_accepted_risks_make_their_requirements_applicable():
    s = _state()
    target = PART_I[3]
    out = risk.apply_to_requirements(s, [_risk(affects=[target])])

    item = next(i for i in s.requirements if i.req_id == target)
    assert item.applicability == Applicability.APPLICABLE
    assert item.risk_basis == ["risk-001"]
    assert {m["req_id"] for m in out["made_applicable"]} == {target}


def test_requirements_no_risk_names_stay_undetermined_never_ruled_out():
    """The failure mode this whole design exists to prevent.

    An AI-drafted assessment that quietly rules most of Part I out is worse
    than no assessment: `not_applicable` reads as a considered decision, and
    "the model did not mention it" is not a justification an auditor accepts.
    Silence must leave the requirement unanswered, and unanswered is a gap.
    """
    s = _state()
    named = PART_I[0]
    risk.apply_to_requirements(s, [_risk(affects=[named])])

    untouched = [i for i in s.requirements if i.req_id in PART_I and i.req_id != named]
    assert untouched, "expected other Part I requirements to exist"
    assert all(i.applicability == Applicability.UNDETERMINED for i in untouched)
    assert not any(i.applicability == Applicability.NOT_APPLICABLE for i in s.requirements)


def test_still_undetermined_reports_only_part_i():
    """Part II is a process obligation, not a risk-conditional one.

    Reporting it as something the risk assessment failed to settle would
    misstate why it is open.
    """
    s = _state()
    out = risk.apply_to_requirements(s, [_risk(affects=[PART_I[0]])])
    assert set(out["still_undetermined"]) <= set(PART_I)
    assert not set(out["still_undetermined"]) & set(PART_II)


def test_a_risk_reopens_a_requirement_that_had_been_ruled_out():
    """Ruled out, then an accepted risk says otherwise — the file must not hold
    both. The stale justification is cleared and the conflict is reported."""
    s = _state()
    target = PART_I[2]
    item = next(i for i in s.requirements if i.req_id == target)
    item.applicability = Applicability.NOT_APPLICABLE
    item.justification = "no network interface"

    out = risk.apply_to_requirements(s, [_risk(affects=[target])])

    assert item.applicability == Applicability.APPLICABLE
    assert item.justification == ""
    assert out["reopened"] == [
        {
            "req_id": target,
            "was_justified_as": "no network interface",
            "risk_basis": ["risk-001"],
        }
    ]


def test_two_risks_on_one_requirement_both_land_in_the_basis():
    s = _state()
    target = PART_I[1]
    risk.apply_to_requirements(
        s,
        [
            _risk("risk-001", affects=[target]),
            _risk("risk-002", affects=[target]),
        ],
    )
    item = next(i for i in s.requirements if i.req_id == target)
    assert item.risk_basis == ["risk-001", "risk-002"]


def test_applying_is_idempotent():
    s = _state()
    target = PART_I[1]
    r = _risk(affects=[target])
    risk.apply_to_requirements(s, [r])
    second = risk.apply_to_requirements(s, [r])

    item = next(i for i in s.requirements if i.req_id == target)
    assert item.risk_basis == ["risk-001"]
    assert second["made_applicable"] == []


# ---- staleness, derived ------------------------------------------------------


def _confirmed(s, **kw) -> RiskAssessment:
    ra = RiskAssessment(
        status=AssessmentStatus.CONFIRMED,
        method="STRIDE",
        content_hash="deadbeef",
        confirmed_at=NOW,
        confirmed_by="u1",
        basis_product_class=s.classification.product_class,
        basis_lifecycle=s.lifecycle,
        **kw,
    )
    s.risk_assessment = ra
    return ra


def test_an_assessment_that_was_never_confirmed_is_absent_not_stale():
    """The caller must not be able to conflate the two: 'no reasons to
    re-assess' on a product with no assessment would read as reassurance."""
    s = _state()
    assert risk.staleness(s) == []

    s.risk_assessment = RiskAssessment(status=AssessmentStatus.DRAFT, method="STRIDE")
    assert risk.staleness(s) == []


def test_a_confirmed_assessment_matching_the_product_is_not_stale():
    s = _state()
    _confirmed(s)
    assert risk.staleness(s) == []


def test_reclassification_makes_the_assessment_stale():
    s = _state()
    _confirmed(s)
    s.classification.product_class = ProductClass.IMPORTANT_CLASS_II
    reasons = {r["reason"] for r in risk.staleness(s)}
    assert "classification_changed" in reasons


def test_a_lifecycle_move_makes_the_assessment_stale():
    s = _state()
    _confirmed(s)
    s.lifecycle = Lifecycle.WITHDRAWN
    reasons = {r["reason"] for r in risk.staleness(s)}
    assert "lifecycle_changed" in reasons


def test_reaching_the_market_does_not_make_the_assessment_stale():
    """The one exempt transition.

    `place_on_market` sets `placed_on_market`, and it is the only writer of
    `lifecycle` in the codebase. Without the exemption, recording a first
    release would demand a re-confirm at the moment someone is shipping — for a
    move that was always the destination. The assessment was made *in order to*
    place the product on the market; arriving there does not invalidate it.

    Scoped to this one pair deliberately, which the case below guards.
    """
    s = _state()
    _confirmed(s)
    s.lifecycle = Lifecycle.PLACED_ON_MARKET
    assert "lifecycle_changed" not in {r["reason"] for r in risk.staleness(s)}


def test_the_exemption_does_not_leak_to_later_transitions():
    """Withdrawal and end-of-support change which obligations are live, so they
    must still prompt a fresh look."""
    for later in (Lifecycle.WITHDRAWN, Lifecycle.SUPPORT_PERIOD_ENDED):
        s = _state()
        ra = _confirmed(s)
        ra.basis_lifecycle = Lifecycle.PLACED_ON_MARKET.value
        s.lifecycle = later
        reasons = {r["reason"] for r in risk.staleness(s)}
        assert "lifecycle_changed" in reasons, later


def test_an_open_revision_is_reported_as_stale():
    s = _state()
    ra = _confirmed(s)
    ra.version = 2
    ra.status = AssessmentStatus.DRAFT
    ra.risks = [_risk(affects=[PART_I[0]], status=RiskStatus.PROPOSED)]

    reasons = {r["reason"] for r in risk.staleness(s)}
    assert "revision_in_progress" in reasons


# ---- the summary view --------------------------------------------------------


def test_the_view_says_what_is_missing_when_there_is_no_assessment():
    s = _state()
    view = risk._assessment_view(s)
    assert view["present"] is False
    assert "start_risk_assessment" in view["next"]


def test_the_view_carries_staleness_rather_than_a_stored_flag():
    s = _state()
    _confirmed(s)
    s.lifecycle = Lifecycle.WITHDRAWN

    view = risk._assessment_view(s)
    assert view["stale"] is True
    assert view["stale_reasons"]
    # Nothing on the model itself records it — recompute, always.
    assert "stale" not in s.risk_assessment.model_dump()


@pytest.mark.parametrize("count", [0, 1, 5])
def test_the_view_counts_risks_by_status(count):
    s = _state()
    ra = _confirmed(s)
    ra.risks = [
        _risk(f"risk-{i:03d}", affects=[PART_I[0]]) for i in range(1, count + 1)
    ]
    view = risk._assessment_view(s)
    assert view["total_risks"] == count
    if count:
        assert view["risks"][RiskStatus.ACCEPTED.value] == count
