"""The regulation catalogue and the EUR-Lex resolver.

The catalogue tests pin *structure and provenance*, not wording. The wording is
an unverified paraphrase and the tests say so — asserting a summary string here
would create a false sense that it had been checked against the law.
"""

from __future__ import annotations

from cra.regulation import (
    eurlex,
    out_of_scope_hints,
    product_class,
    product_classes,
    provenance,
    requirements,
    requirements_for_part,
)
from cra.schemas.enums import ConformityRoute, ProductClass

import pytest


# ---- provenance --------------------------------------------------------------


def test_the_catalogue_says_when_it_was_verified_and_against_what():
    """Verified as of a date, against a named source — not verified full stop.

    Article 7(4) delegated acts can amend the annexes, so the claim this
    catalogue can honestly make is "reconciled on <date>", and the date has to
    travel with it.
    """
    p = provenance()
    assert p["source_verified"] is True
    assert p["verified_at"] == "2026-08-06"
    assert "publications.europa.eu" in p["verified_against"]
    assert p["celex"] == "32024R2847"
    assert p["url"].endswith("CELEX:32024R2847")


def test_a_verified_catalogue_still_refuses_to_be_quoted():
    """The assertion that matters most in this file.

    Verification establishes that the anchors point at provisions that exist
    and that the summaries say what those provisions say. It does not turn a
    paraphrase into the text of the law. A caveat of None would read as "this
    is the regulation", which is the one claim the catalogue must never make —
    so there is a caveat in both states, and it is never empty.
    """
    p = provenance()
    assert p["caveat"]
    assert "paraphrases, not quotations" in p["caveat"]
    assert "7(4)" in p["caveat"]


def test_provenance_makes_no_network_call_by_default():
    """No tool may put a remote fetch on its hot path — and an offline server
    must never start reporting the CRA as repealed."""
    assert "in_force" not in provenance()


def test_the_catalogue_records_that_the_lists_are_amendable():
    """Article 7(4) delegated acts can move products between classes, so a
    classification is true as of a date rather than permanently."""
    assert "7(4)" in provenance()["amendable_by"]


# ---- Annex I -----------------------------------------------------------------


def test_both_parts_are_present_and_distinct():
    part_i = requirements_for_part("part_i")
    part_ii = requirements_for_part("part_ii")
    assert len(part_i) == 14
    assert len(part_ii) == 8
    assert len(requirements()) == len(part_i) + len(part_ii)
    assert not ({r.id for r in part_i} & {r.id for r in part_ii})


def test_requirement_ids_are_unique_and_stable_shaped():
    ids = [r.id for r in requirements()]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("annex_i.") for i in ids)


def test_every_requirement_carries_an_anchor_a_human_can_look_up():
    for r in requirements():
        assert r.anchor.startswith("Annex I Pt"), r.id
        assert r.summary
        assert r.citation_url().endswith("CELEX:32024R2847")


def test_the_sbom_requirement_is_where_record_sbom_files_evidence():
    """`record_sbom` hardcodes this id; a catalogue renumbering must break a
    test rather than silently orphan the evidence."""
    ids = {r.id for r in requirements()}
    assert "annex_i.ii.1" in ids


def test_part_ii_requirements_are_processes_not_properties():
    """Annex I Pt II describes things the manufacturer does over time, which is
    why evidence there is a policy *plus* a record of it being followed."""
    part_ii = requirements_for_part("part_ii")
    assert any("disclosure" in r.summary.lower() for r in part_ii)
    assert any("software bill of materials" in r.summary.lower() for r in part_ii)


# ---- product classes ---------------------------------------------------------


def test_every_class_maps_to_a_real_conformity_route():
    routes = {r.value for r in ConformityRoute}
    for c in product_classes():
        assert c.conformity_route in routes, c.id


def test_class_ids_cover_the_stored_enum():
    stored = {p.value for p in ProductClass} - {"unknown", "out_of_scope"}
    assert {c.id for c in product_classes()} == stored


def test_notified_body_is_required_exactly_where_the_route_says_so():
    """The most expensive field in the file. A product wrongly marked as not
    needing a notified body looks settled to everyone who reads it after."""
    for c in product_classes():
        needs_body = c.conformity_route in (
            ConformityRoute.NOTIFIED_BODY.value,
            ConformityRoute.NOTIFIED_BODY_OR_CERTIFICATION.value,
        )
        assert c.notified_body_required is needs_body, c.id


def test_default_class_has_no_categories_and_self_assesses():
    d = product_class("default")
    assert d.categories == ()
    assert d.conformity_route == ConformityRoute.SELF_ASSESSMENT.value
    assert d.notified_body_required is False


def test_class_i_self_assessment_is_conditional_not_free():
    """Internal control is available to Annex III class I only where standards
    are applied in full — a distinct route, because a user who does not meet
    the condition is in notified-body territory without the product changing.
    """
    c = product_class("important_class_i")
    assert c.conformity_route == ConformityRoute.SELF_ASSESSMENT_WITH_STANDARDS.value
    assert "in full" in c.description


def test_the_annex_iii_classes_are_populated():
    assert len(product_class("important_class_i").categories) >= 15
    assert len(product_class("important_class_ii").categories) >= 4
    assert len(product_class("critical").categories) >= 3


def test_out_of_scope_hints_include_the_saas_boundary():
    """The boundary software makers most often get wrong in their own favour."""
    notes = " ".join(h["note"] for h in out_of_scope_hints()).lower()
    assert "remote data processing" in notes
    assert any(h.get("anchor") for h in out_of_scope_hints())


def test_an_unknown_class_raises():
    with pytest.raises(KeyError):
        product_class("extremely_important")


# ---- EUR-Lex status parsing --------------------------------------------------


IN_FORCE_META = (
    '<meta property="eli:in_force" resource="http://x/InForce-inForce"/>'
)
REPEALED_META = (
    '<meta property="eli:in_force" resource="http://x/InForce-notInForce"/>'
    '<meta property="eli:date_no_longer_in_force" content="2029-01-01"/>'
)


def test_eli_metadata_is_the_primary_signal():
    status, detail = eurlex.parse_status(IN_FORCE_META)
    assert status == eurlex.STATUS_IN_FORCE
    assert "ELI metadata" in detail


def test_a_repeal_reports_its_end_of_validity():
    status, detail = eurlex.parse_status(REPEALED_META)
    assert status == eurlex.STATUS_NOT_IN_FORCE
    assert "2029-01-01" in detail


def test_the_negative_phrase_is_tested_before_the_positive_one():
    """"in force" is a substring of "no longer in force". Get the order wrong
    and every repealed instrument reads as current — the exact direction of
    error a compliance tool must not make."""
    status, detail = eurlex.parse_status("Status: No longer in force")
    assert status == eurlex.STATUS_NOT_IN_FORCE
    status, _ = eurlex.parse_status("Status: In force")
    assert status == eurlex.STATUS_IN_FORCE


def test_metadata_beats_contradictory_status_text():
    html = REPEALED_META + "<p>Status: In force</p>"
    assert eurlex.parse_status(html)[0] == eurlex.STATUS_NOT_IN_FORCE


def test_an_unrecognisable_page_is_unknown_not_a_guess():
    assert eurlex.parse_status("<html>maintenance</html>")[0] == eurlex.STATUS_UNKNOWN


# ---- resolver behaviour ------------------------------------------------------


def test_a_network_failure_degrades_to_unknown_never_to_repealed(monkeypatch):
    """This container has no outbound network, which is exactly the condition
    being tested: an offline server must not report the CRA as repealed."""
    eurlex.clear_cache()
    result = eurlex.in_force("32024R2847")
    assert result.status in (eurlex.STATUS_IN_FORCE, eurlex.STATUS_UNKNOWN)
    assert result.status != eurlex.STATUS_NOT_IN_FORCE
    assert result.url.endswith("CELEX:32024R2847")


def test_the_result_is_cached_so_no_tool_call_refetches(monkeypatch):
    eurlex.clear_cache()
    calls = []

    def _fake(celex):
        calls.append(celex)
        return eurlex.STATUS_IN_FORCE, "In force"

    monkeypatch.setattr(eurlex, "_fetch", _fake)
    eurlex.in_force("32024R2847")
    eurlex.in_force("32024R2847")
    assert calls == ["32024R2847"]

    eurlex.in_force("32024R2847", refresh=True)
    assert len(calls) == 2
    eurlex.clear_cache()


def test_ignorance_is_cached_far_more_briefly_than_a_repeal():
    """`unknown` usually means the network was down; the next call should try
    again rather than inherit the outage."""
    assert eurlex._ttl(eurlex.STATUS_UNKNOWN) < eurlex._ttl(eurlex.STATUS_IN_FORCE)
    assert eurlex._ttl(eurlex.STATUS_IN_FORCE) < eurlex._ttl(eurlex.STATUS_NOT_IN_FORCE)


def test_celex_is_normalised():
    assert eurlex.normalise_celex(" 32024r2847 ") == "32024R2847"


def test_no_celex_is_unknown_and_makes_no_call():
    assert eurlex.in_force("").status == eurlex.STATUS_UNKNOWN


def test_citation_urls_do_not_fake_article_precision():
    """ELI supports sub-document addressing, but a link that lands on the whole
    regulation while claiming to point at Annex I Pt I(2)(b) is worse than an
    honest one — the reader believes they checked something they did not."""
    plain = eurlex.citation_url("32024R2847")
    assert plain.endswith("CELEX:32024R2847")
    assert "#" not in plain
