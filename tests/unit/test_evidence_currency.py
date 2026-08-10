"""Whether a requirement's evidence still describes what ships.

Annex I attaches to "the product with digital elements *as placed on the
market*", so a test report is a claim about one build rather than a permanent
fact. `annex.evidence_currency` is the derivation that says so, and this file
guards the three answers it can give and the one distinction that carries the
most weight:

**`unversioned` is not `stale`.** Evidence written before releases existed, or
before this product recorded one, has no version on it. Calling that stale
would turn every existing requirement into a gap the moment anybody records a
release, and would assert something nobody checked. Stale means "we know this
covers an older build". Unversioned means "we do not know", and those are
different sentences.

Pure — no database. `evidence_currency` takes the evidence map the caller
already had to build.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.schemas import ComplianceState, Release, RequirementItem  # noqa: E402
from cra.schemas.enums import Applicability, RequirementStatus  # noqa: E402
from cra.server import annex  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 8, 8, tzinfo=UTC)
REQ = "annex_i.i.2.e"


class _Row:
    """The two fields `evidence_currency` reads off an Evidence row."""

    def __init__(self, version=None):
        self.applies_to_version = version


def _state(*versions: str, status=RequirementStatus.VERIFIED, evidence=("e1",)):
    s = ComplianceState(product_id="p", name="n", created_at=NOW, updated_at=NOW)
    s.requirements = [
        RequirementItem(
            req_id=REQ,
            title="Annex I Pt I(2)(e)",
            applicability=Applicability.APPLICABLE,
            status=status,
            evidence_ids=list(evidence),
        )
    ]
    for i, v in enumerate(versions):
        s.releases.append(
            Release(
                version=v,
                released_at=NOW + timedelta(days=i),
                recorded_at=NOW + timedelta(days=i),
            )
        )
    return s


def _currency(state, *versions):
    rows = [_Row(v) for v in versions]
    return annex.evidence_currency(state, {f"requirement:{REQ}": rows})


# ---- the three verdicts --------------------------------------------------------


def test_evidence_for_the_current_release_is_current():
    verdict = _currency(_state("1.0", "2.0"), "2.0")
    assert verdict[REQ]["state"] == annex.CURRENT


def test_evidence_only_for_an_older_release_is_stale():
    verdict = _currency(_state("1.0", "2.0"), "1.0")[REQ]
    assert verdict["state"] == annex.STALE
    assert verdict["current_release"] == "2.0"
    assert verdict["evidenced_against"] == ["1.0"]
    assert "as placed on the market" in verdict["detail"]


def test_untagged_evidence_is_unversioned_not_stale():
    """The distinction the whole design rests on. Every row written before
    `applies_to_version` existed is NULL, and turning those into gaps on deploy
    would assert something nobody checked."""
    verdict = _currency(_state("1.0"), None)[REQ]
    assert verdict["state"] == annex.UNVERSIONED
    assert verdict["state"] != annex.STALE


def test_one_current_artefact_is_enough():
    """Requirements accrete evidence over releases. Keeping the old artefacts
    is correct — the question is whether *something* covers what ships now."""
    assert _currency(_state("1.0", "2.0"), "1.0", "2.0")[REQ]["state"] == annex.CURRENT


def test_a_mix_of_old_and_untagged_reads_as_unversioned():
    """Not stale: an untagged artefact might well cover the current release,
    and the honest answer is that the tool cannot tell."""
    assert _currency(_state("1.0", "2.0"), "1.0", None)[REQ]["state"] == annex.UNVERSIONED


# ---- when the question does not apply -------------------------------------------


def test_no_releases_means_no_verdicts_at_all():
    """Nothing for evidence to be current *against*. Returning `{}` is what
    keeps every existing product's behaviour byte-identical."""
    assert annex.evidence_currency(_state(), {f"requirement:{REQ}": [_Row(None)]}) == {}


def test_a_requirement_with_no_evidence_is_left_to_is_gap():
    """It is already a gap for a better reason. Adding a currency verdict would
    report the same problem twice in different words."""
    assert _currency(_state("1.0")) == {}


def test_latest_release_is_the_last_recorded_not_the_highest():
    """Version strings are the manufacturer's own and are never parsed. A tool
    that sorted them would eventually call the wrong release current — '9.0'
    after '10.0' is the classic, and date-based and codename schemes have no
    order at all."""
    s = _state("10.0", "9.0")
    assert annex.latest_release(s).version == "9.0"
    assert _currency(s, "9.0")[REQ]["state"] == annex.CURRENT


# ---- what it does to a gap -------------------------------------------------------


def test_stale_evidence_makes_a_verified_requirement_a_gap():
    """#14's 'Done when': shipping a new version makes requirements evidenced
    only against the old one visibly unsettled."""
    item = _state("1.0", "2.0").requirements[0]
    assert not annex._is_gap(item)
    assert annex._is_gap(item, {"state": annex.STALE})


def test_unversioned_evidence_does_not_make_a_gap():
    item = _state("1.0").requirements[0]
    assert not annex._is_gap(item, {"state": annex.UNVERSIONED})


def test_currency_cannot_rescue_a_requirement_that_was_already_a_gap():
    """`current` says the evidence is about the right build, not that the
    requirement is answered. A not-started requirement stays a gap."""
    item = _state("1.0", status=RequirementStatus.NOT_STARTED).requirements[0]
    assert annex._is_gap(item, {"state": annex.CURRENT})


def test_is_gap_is_unchanged_when_no_currency_is_supplied():
    """It stays a pure function of the item wherever no release context is at
    hand, so every existing caller behaves exactly as before."""
    for status in RequirementStatus:
        item = _state("1.0", status=status).requirements[0]
        assert annex._is_gap(item) == annex._is_gap(item, None)


@pytest.mark.parametrize("verdict", [annex.CURRENT, annex.UNVERSIONED, annex.STALE])
def test_an_unjustified_not_applicable_is_a_gap_whatever_the_evidence_says(verdict):
    """Applicability is decided before evidence is relevant at all."""
    s = _state("1.0")
    s.requirements[0].applicability = Applicability.NOT_APPLICABLE
    s.requirements[0].justification = ""
    assert annex._is_gap(s.requirements[0], {"state": verdict})
