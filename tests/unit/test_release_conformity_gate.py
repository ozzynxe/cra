"""Placing on the market checks the record is there, rather than hoarding it.

The retention work asked what happens to working state — audit rows, drafts,
requirement history — for a product that is never released. The answer that
avoids keeping everything forever on the chance it matters later is to check at
the transition: placing on the market is the single, code-controlled moment
working state becomes the record an authority may ask for, and it is where
`place_on_market` can insist the substance is present.

These blockers are therefore not about known vulnerabilities — the four scan
blockers already cover Annex I Pt I(2)(a). They are about the file the release
is supposed to be evidenced by.

Waivable, like the scan ones and by the same single `accepted_rationale`.
Refusing outright would be stricter than the regulation: I(2)(a) is about known
exploitable vulnerabilities specifically, not about all of Part I being
finished.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from cra.schemas.compliance import (  # noqa: E402
    ComplianceState,
    RequirementItem,
    RiskAssessment,
)
from cra.schemas.enums import (  # noqa: E402
    Applicability,
    AssessmentStatus,
    RequirementStatus,
)
from cra.server.releases import _conformity_blockers  # noqa: E402

NOW = datetime(2026, 8, 9, tzinfo=timezone.utc)


def _settled(req_id: str = "annex_i.i.2.a") -> RequirementItem:
    return RequirementItem(
        req_id=req_id,
        title="t",
        applicability=Applicability.APPLICABLE,
        status=RequirementStatus.VERIFIED,
        evidence_ids=["e1"],
    )


def _confirmed_assessment() -> RiskAssessment:
    return RiskAssessment(
        status=AssessmentStatus.CONFIRMED,
        content_hash="deadbeef",
        part_i_1_approach="Applied via threat modelling at design review.",
        part_ii_approach="Coordinated disclosure policy plus SBOM scanning.",
    )


def _state(*, assessment=None, requirements=()) -> ComplianceState:
    s = ComplianceState(product_id="p", name="n", created_at=NOW, updated_at=NOW)
    s.risk_assessment = assessment
    s.requirements = list(requirements)
    return s


def _codes(state) -> set[str]:
    return {b["blocker"] for b in _conformity_blockers(state)}


def test_a_clean_record_blocks_nothing():
    state = _state(assessment=_confirmed_assessment(), requirements=[_settled()])
    assert _conformity_blockers(state) == []


def test_no_risk_assessment_blocks():
    """Annex I Pt I applies *on the basis of* the Article 13(2) assessment."""
    assert "no_confirmed_risk_assessment" in _codes(
        _state(requirements=[_settled()])
    )


def test_a_drafted_but_unconfirmed_assessment_does_not_count():
    """A drafted risk determines nothing — the invariant, applied at release."""
    drafted = RiskAssessment(part_i_1_approach="x", part_ii_approach="y")
    assert drafted.content_hash is None
    assert "no_confirmed_risk_assessment" in _codes(
        _state(assessment=drafted, requirements=[_settled()])
    )


def test_a_revision_in_progress_blocks():
    """A confirmed assessment reopened for editing is stale, not current.

    `content_hash` alone is not enough — the frozen copy is a version behind
    the draft being worked on, and Annex VII(3) cites the frozen one.
    """
    reopened = RiskAssessment(
        status=AssessmentStatus.DRAFT,
        content_hash="deadbeef",
        part_i_1_approach="x",
        part_ii_approach="y",
    )
    assert "risk_assessment_stale" in _codes(
        _state(assessment=reopened, requirements=[_settled()])
    )


def test_missing_13_3_statements_block():
    """Reachable only for assessments confirmed before these became mandatory,
    which is exactly the population nobody goes back and rechecks."""
    legacy = RiskAssessment(status=AssessmentStatus.CONFIRMED, content_hash="deadbeef")
    assert "missing_13_3_statements" in _codes(
        _state(assessment=legacy, requirements=[_settled()])
    )


def test_an_undetermined_requirement_blocks():
    undetermined = RequirementItem(req_id="annex_i.i.2.b", title="t")
    assert undetermined.applicability == Applicability.UNDETERMINED
    codes = _codes(
        _state(assessment=_confirmed_assessment(), requirements=[undetermined])
    )
    assert "requirements_unsettled" in codes


def test_not_applicable_without_a_justification_blocks():
    """The flag is not the answer; an auditor reads the justification."""
    bare = RequirementItem(
        req_id="annex_i.i.2.c",
        title="t",
        applicability=Applicability.NOT_APPLICABLE,
        justification="   ",
    )
    assert "requirements_unsettled" in _codes(
        _state(assessment=_confirmed_assessment(), requirements=[bare])
    )


def test_it_names_the_requirements_rather_than_only_counting_them():
    items = [RequirementItem(req_id=f"annex_i.i.2.{c}", title="t") for c in "abc"]
    blocker = next(
        b
        for b in _conformity_blockers(
            _state(assessment=_confirmed_assessment(), requirements=items)
        )
        if b["blocker"] == "requirements_unsettled"
    )
    assert blocker["requirements"] == [i.req_id for i in items]
    assert "3 Annex I requirement(s)" in blocker["detail"]


def test_settled_means_what_it_means_in_the_technical_file():
    """Reuses `annex._is_gap` rather than a second definition.

    Two definitions of "settled" would drift, and the one that drifted would let
    a release assert a file the gap report calls incomplete.
    """
    from cra.server.annex import _is_gap
    from cra.server import releases

    assert releases._is_gap is _is_gap


def test_every_reason_travels_together():
    """Not one blocker at a time.

    Being told about the assessment, fixing it, and only then hearing the
    requirements are unsettled is the interaction that teaches people to reach
    straight for the override.
    """
    codes = _codes(_state(requirements=[RequirementItem(req_id="r", title="t")]))
    assert {"no_confirmed_risk_assessment", "requirements_unsettled"} <= codes
