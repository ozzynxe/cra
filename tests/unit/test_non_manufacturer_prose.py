"""Status prose may not address a non-manufacturer as if the duty were theirs.

Issue #52, the half that survived the first pass. That pass went looking for
*seeded checklists* — fourteen Annex I requirements presented to a steward as
outstanding — and fixed those, because a checklist is a structure and
structures are what a sweep finds.

What it did not look at was the sentences beside them. `_support_period_view`
told an importer "Article 13(8) requires a support period of at least five
years"; `_assessment_view` told them that without an Article 13(2) assessment
"every applicability decision rests on nothing". Both are true of a
manufacturer and neither is a duty of an importer's — 13(2) and 13(8) are
addressed to manufacturers, and an importer has no support period to
determine.

Prose is the easier half to get wrong, because it reads as background rather
than as an assertion, and because nothing structural changes when it is wrong.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cra.schemas import ComplianceState, EconomicOperatorRole
from cra.server.handlers import _support_period_view
from cra.server.risk import _assessment_view

_NOT_MANUFACTURERS = [
    r.value for r in EconomicOperatorRole if r is not EconomicOperatorRole.MANUFACTURER
]


def _state(role: str) -> ComplianceState:
    now = datetime.now(timezone.utc)
    return ComplianceState(
        product_id="p",
        name="Thing",
        economic_operator_role=role,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.parametrize("role", _NOT_MANUFACTURERS)
def test_the_support_period_is_not_presented_as_their_requirement(role):
    why = _support_period_view(_state(role))["why_it_matters"]
    assert "manufacturer" in why
    assert role in why
    assert "not your obligation" in why
    # The bare requirement sentence, addressed to whoever is reading.
    assert "Article 13(8) requires a support period" not in why


@pytest.mark.parametrize("role", _NOT_MANUFACTURERS)
def test_the_risk_assessment_is_not_presented_as_their_requirement(role):
    why = _assessment_view(_state(role))["why_it_matters"]
    assert "manufacturer" in why
    assert role in why
    assert "rests on nothing" not in why
    # Article 21 is the route by which it *would* become theirs, and the one
    # thing a non-manufacturer weighing a modification actually needs told.
    assert "Article 21" in why


def test_a_manufacturer_still_gets_the_plain_statement():
    """The other direction, and the one that matters most.

    A qualification worth adding for an importer is worth *not* adding for a
    manufacturer: prose that hedged every case would make the real duty
    indistinguishable from somebody else's. Same reasoning as the release gate
    reading clean for a clean release.
    """
    s = _state(EconomicOperatorRole.MANUFACTURER.value)
    assert "Article 13(8) requires a support period" in _support_period_view(s)["why_it_matters"]
    assert "rests on nothing" in _assessment_view(s)["why_it_matters"]
    for view in (_support_period_view(s), _assessment_view(s)):
        assert "not your obligation" not in view["why_it_matters"]


@pytest.mark.parametrize("role", _NOT_MANUFACTURERS)
def test_the_next_step_is_still_offered(role):
    """Not their duty is not "don't". An importer weighing a substantial
    modification, or tracking what a supplier committed to, has a real reason
    to record both — #52 settled that recording is legitimate and only the
    attribution was wrong."""
    assert "set_support_period(" in _support_period_view(_state(role))["why_it_matters"]
    assert _assessment_view(_state(role))["next"] == "start_risk_assessment(product_id)"
