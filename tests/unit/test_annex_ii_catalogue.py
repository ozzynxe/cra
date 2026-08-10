"""The Annex II catalogue, against the published text.

Fourth time this shape of work has been done — `annex_i.yaml`,
`annex_vii.yaml`, `product_classes.yaml`, now this — and the failure it guards
against is the one `annex_i.yaml`'s own header records happening: a catalogue
whose *summaries* were faithful while every anchor was wrong by one letter, so
technical files cited provisions that do not exist.

These tests therefore check structure and anchors hard, and paraphrases
loosely. A test asserting exact prose would be a second transcription to keep
in step with the first, which is not a check — it is a copy.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.regulation import _annex_ii, provenance, user_information  # noqa: E402


@pytest.fixture(scope="module")
def items():
    return user_information()


# ---- shape ---------------------------------------------------------------------


def test_nine_numbered_points_with_point_eight_flattened(items):
    """Annex II is nine points; point 8 carries six lettered sub-points, which
    are separate entries here for the same reason Annex I Pt I(2)(a)-(m) are:
    each is a distinct thing a reader has to be able to find."""
    top = [i for i in items if re.fullmatch(r"annex_ii\.\d", i.id)]
    sub = [i for i in items if re.fullmatch(r"annex_ii\.8\.[a-f]", i.id)]
    assert len(top) == 9
    assert len(sub) == 6
    assert len(items) == 15


def test_ids_and_anchors_agree(items):
    """The failure mode annex_i.yaml records: summaries right, anchors wrong,
    so the file cites provisions that do not exist."""
    for i in items:
        tail = i.id.removeprefix("annex_ii.")
        if "." in tail:
            number, letter = tail.split(".")
            assert i.anchor == f"Annex II({number})({letter})", i.id
        else:
            assert i.anchor == f"Annex II({tail})", i.id


def test_published_order_is_preserved(items):
    """Point 8's sub-points sit between 8 and 9, as they do in the annex."""
    assert [i.id for i in items] == [
        "annex_ii.1",
        "annex_ii.2",
        "annex_ii.3",
        "annex_ii.4",
        "annex_ii.5",
        "annex_ii.6",
        "annex_ii.7",
        "annex_ii.8",
        "annex_ii.8.a",
        "annex_ii.8.b",
        "annex_ii.8.c",
        "annex_ii.8.d",
        "annex_ii.8.e",
        "annex_ii.8.f",
        "annex_ii.9",
    ]


def test_every_item_has_a_summary(items):
    for i in items:
        assert i.summary.strip()
        assert not i.summary.strip().endswith(","), f"{i.id}: truncated mid-clause"


# ---- the conditional four ---------------------------------------------------------


def test_exactly_four_items_are_conditional(items):
    """The chapeau says the product shall *at minimum* be accompanied by these,
    so mandatory is the default. Four carry their own qualifier in the text:
    6 "where applicable", 8(e) only where automatic updates apply, 8(f) only
    for products intended for integration, and 9 only if the manufacturer
    chooses to publish the SBOM."""
    conditional = {i.id for i in items if i.conditional}
    assert conditional == {
        "annex_ii.6",
        "annex_ii.8.e",
        "annex_ii.8.f",
        "annex_ii.9",
    }


def test_every_conditional_item_states_its_condition(items):
    """`conditional` on its own would be an assertion. The condition is what
    lets a reader check the claim against the annex."""
    for i in items:
        if i.conditional:
            assert i.condition.strip(), i.id
        else:
            assert not i.condition.strip(), f"{i.id}: condition without conditional"


def test_the_unconditional_ones_are_not_quietly_softened(items):
    """A drift check with teeth: if someone later marks a mandatory item
    conditional, this fails. Eleven of fifteen are unqualified in the text."""
    assert sum(1 for i in items if not i.conditional) == 11


# ---- provenance -------------------------------------------------------------------


def test_the_catalogue_carries_its_own_verification(items):
    raw = _annex_ii()
    assert raw["celex"] == "32024R2847"
    assert raw["source_verified"] is True
    assert raw["verified_at"]
    assert "publications.europa.eu" in raw["verified_against"], (
        "eur-lex.europa.eu answers a non-browser client with HTTP 202 and an "
        "empty body, which reads as an empty document rather than a refusal"
    )


def test_provenance_covers_annex_ii_too(items):
    """#4's second 'Done when'. `provenance()` is returned by every tool that
    reads a catalogue, so a new catalogue file that it does not consult would
    let an unverified annex ride along under someone else's verification."""
    p = provenance()
    assert p["source_verified"] is True
    assert p["caveat"]


def test_provenance_reports_the_oldest_verification_date():
    """Reporting the newest would let a freshly transcribed annex make an older
    one look re-checked — which is the direction that misleads."""
    from cra.regulation import _annex_i, _annex_vii, _classes

    dates = [
        f.get("verified_at")
        for f in (_annex_i(), _classes(), _annex_vii(), _annex_ii())
    ]
    assert provenance()["verified_at"] == min(dates)
    assert len(set(dates)) > 1, "this test is vacuous if every file shares a date"


def test_the_caveat_is_never_null_even_when_verified():
    """The standing rule: verification means the anchors exist and the
    paraphrases are faithful. It does not make them the text of the law."""
    assert provenance()["caveat"]


# ---- the paraphrases point at the right subject matter ------------------------------


@pytest.mark.parametrize(
    "item_id,must_mention",
    [
        ("annex_ii.1", ["name", "address"]),
        ("annex_ii.2", ["single point of contact", "disclosure"]),
        ("annex_ii.3", ["identification"]),
        ("annex_ii.4", ["intended purpose"]),
        ("annex_ii.5", ["foreseeable"]),
        ("annex_ii.6", ["declaration of conformity"]),
        ("annex_ii.7", ["support period"]),
        ("annex_ii.8.a", ["commissioning"]),
        ("annex_ii.8.b", ["security of data"]),
        ("annex_ii.8.c", ["updates"]),
        ("annex_ii.8.d", ["decommissioning", "removed"]),
        ("annex_ii.8.e", ["automatic", "turned off"]),
        ("annex_ii.8.f", ["integration", "integrator"]),
        ("annex_ii.9", ["software bill of materials"]),
    ],
)
def test_each_summary_is_about_its_own_provision(items, item_id, must_mention):
    """Loose on purpose — asserting exact prose would be a second transcription
    to keep in step with the first. This catches an item being renumbered into
    the wrong slot, which is the error that actually happened to Annex I."""
    item = next(i for i in items if i.id == item_id)
    text = item.summary.lower()
    for phrase in must_mention:
        assert phrase.lower() in text, f"{item_id} does not mention {phrase!r}"


def test_the_cross_references_to_article_13_are_recorded(items):
    """13(16) and 13(17) each say their information must *also* be included in
    Annex II. Recording which items those are keeps two obligations from being
    read as one."""
    by_id = {i.id: i for i in items}
    assert by_id["annex_ii.1"].also_required_by == "Article 13(16)"
    assert by_id["annex_ii.2"].also_required_by == "Article 13(17)"
