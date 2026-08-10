"""The published coverage page.

Two columns: what the CRA requires of a manufacturer, and what this tool does
about it. Most of what is asserted here protects the boundary between them.

The page is generated rather than written for one reason. A list of what a
product covers gets updated when a feature ships; a list of what it does not
cover only ever gets shorter by neglect. Rendering both halves from
`docs/coverage.yaml` plus the regulation catalogue means the staleness check
below is the thing standing between a prospect and a page that flatters us.
"""

from __future__ import annotations

import html as _html
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.regulation import requirements, technical_file_slots  # noqa: E402

TARGET = ROOT / "www" / "coverage.html"
SOURCE = ROOT / "docs" / "coverage.yaml"


@pytest.fixture(scope="module")
def html() -> str:
    return TARGET.read_text()


@pytest.fixture(scope="module")
def plain(html) -> str:
    """The page as words.

    Tags become a space so block boundaries do not weld sentences together —
    which then leaves `<em>x</em>,` reading as "x ," — so the space before
    punctuation is taken back out. Without that, an assertion could only match
    text that happened to carry no inline markup, which is the text least worth
    pinning."""
    text = re.sub(r"\s+", " ", _html.unescape(re.sub(r"<[^>]+>", " ", html)))
    return re.sub(r"\s+([,.;:)])", r"\1", text)


@pytest.fixture(scope="module")
def data() -> dict:
    return yaml.safe_load(SOURCE.read_text())


def flat(text: str) -> str:
    """A YAML string as it will read once rendered.

    The renderer turns `backticks` into code spans and *asterisks* into
    emphasis, both of which this file's `plain` fixture then strips back to
    bare words. Mirroring that here is what lets a test compare the source and
    the page directly instead of asserting on fragments that happen to avoid
    markup."""
    return re.sub(r"\s+", " ", re.sub(r"[`*]", "", text)).strip()


# ---- the committed page tracks its sources -----------------------------------


def test_the_committed_page_is_not_stale():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render_coverage.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


# ---- the list is complete ------------------------------------------------------


def test_every_annex_i_requirement_has_an_answer(data):
    """A requirement with no entry would be silently absent from the page, and
    absence on this page reads as 'not our problem' rather than 'we forgot'.
    Keyed by catalogue id so a renumbering fails here rather than shipping."""
    catalogue = {r.id for r in requirements()}
    assert catalogue == set(data["annex_i"]), "docs/coverage.yaml is out of step"


def test_every_technical_file_slot_has_an_answer(data):
    catalogue = {s.id for s in technical_file_slots()}
    assert catalogue == set(data["annex_vii"])


def test_all_twenty_two_requirements_reach_the_page(plain):
    """With the catalogue's own anchors and summaries, not a retyped table —
    a paraphrased Annex I on a public page is a wrong citation."""
    reqs = requirements()
    assert len(reqs) == 22
    for r in reqs:
        assert r.anchor in plain, r.anchor
        assert re.sub(r"\s+", " ", r.summary) in plain, r.anchor


def test_all_eight_annex_vii_slots_reach_the_page(plain):
    slots = technical_file_slots()
    assert len(slots) == 8
    for s in slots:
        assert s.anchor in plain and s.title in plain


def test_article_13_is_complete_except_the_commission_power(data):
    """13(24) is a Commission power to specify the SBOM format, not a
    manufacturer obligation. Every other paragraph is a duty and is listed."""
    anchors = {r["anchor"] for r in data["sections"][0]["rows"]}
    expected = {f"13({n})" for n in range(1, 26)} - {"13(24)"}
    assert anchors == expected


def test_every_row_answers_both_halves(data, plain):
    for section in data["sections"]:
        for row in section["rows"]:
            assert row["obligation"].strip(), row["anchor"]
            assert row["support"].strip(), row["anchor"]
            assert flat(row["obligation"]) in plain
            assert flat(row["support"]) in plain


# ---- what we do not do is on the page, in plain words --------------------------


def test_obligations_with_no_support_say_so(data):
    """The rule the YAML header sets: where nothing exists, the answer starts
    with "Nothing". An omitted row implies coverage and a euphemism does the
    same thing more slowly."""
    for section in data["sections"]:
        for row in section["rows"]:
            if row.get("tools"):
                continue
            assert row["support"].strip().startswith("Nothing"), (
                f'{row["anchor"]}: no tools, so the support text has to begin '
                f'"Nothing" — got {row["support"][:60]!r}'
            )


def test_the_gaps_we_know_about_are_named(plain):
    """Specific admissions, each traceable to something absent from the tool
    surface. If one of these is fixed, this test is the reminder to update the
    page — which is the correct direction for it to fail in."""
    for claim in (
        # No upstream-report record on confirm_advisory.
        "it does not prompt for the upstream report",
        # disclosure_policy_url is stored and never fetched.
        "a URL that 404s satisfies the field and not the requirement",
        # No non-conformity workflow.
        "There is no non-conformity record",
        # No authority-request workflow.
        "no record that a request was received",
    ):
        assert re.sub(r"\s+", " ", claim) in plain, claim


def test_the_support_period_row_states_both_halves_of_13_8(plain):
    """Replaced "the support period itself has no tool", which this page
    carried against three separate rows until `set_support_period` shipped.

    The claim that took its place has to keep the part people forget: 13(8) is
    a five-year floor *and* a requirement that the information taken into
    account goes in the technical documentation. A row that advertised only
    the date would describe a tool that fills Annex VII(4) without meeting it.
    """
    assert "recorded with its reasoning" in plain
    assert "a date alone leaves Annex VII(4) unmet" in plain
    assert "measured in calendar years, not elapsed days" in plain
    # The exception, and that it has to be claimed rather than backed into.
    assert "refused unless you state the expected use time" in plain


def test_the_annex_ii_row_states_the_limit_it_cannot_cross(plain):
    """Replaced "It is not modelled item by item", which was the last of the
    six admissions this file was written around.

    A checklist tracks whether each item is *claimed* to accompany the product.
    It cannot read the manual and tell you whether the claim is true, and the
    row has to say so — otherwise fifteen green ticks read as a verified Annex
    II rather than a recorded one."""
    assert "cannot do is read your manual and tell you whether it is true" in plain
    assert "ruled out with a justification" in plain
    assert '"where applicable" becomes a way to empty the annex' in plain


def test_the_simplified_declaration_row_does_not_imply_a_check(plain):
    """It records an address and never fetches it. Saying so is the point —
    the alternative reads as though the tool verified the full declaration is
    published there, which it cannot and must not appear to."""
    assert "records the address exactly as given and never fetches it" in plain
    assert "cannot confirm what is published there" in plain


def test_the_13_3_row_says_the_risks_are_not_the_whole_paragraph(plain):
    """The distinction that made #5 a bug: the risks answer Part I(2), and
    13(3) asks for two further statements the risk list cannot produce."""
    assert "the risks answer Part I(2)" in plain
    assert "confirming is refused without it" in plain


def test_the_end_of_support_row_does_not_overclaim(plain):
    """13(19) has two halves and the tool only does one. It can warn the people
    on the product; it cannot put a notice inside somebody else's software."""
    assert "warned at 180, 90, 30 and 7 days" in plain
    assert "cannot display a notice inside your product" in plain


def test_the_awareness_route_is_on_the_reporting_row(plain):
    """Article 14 triggers on awareness, and the daily scan is the one thing
    here that can create it rather than merely record it. Two things have to
    travel together on that row, or the claim becomes a liability:

    a feed match is a candidate and not a record — `advisories.py` writes no
    Vulnerability and above all no Incident, because version ranges over-match
    and a false positive would reach a CSIRT — and awareness anchors on
    `notified_at`, when the tool told you, so confirming late cannot understate
    how long you had known.
    """
    assert "A feed match is a candidate, never a record" in plain
    assert "Awareness then anchors on when the tool told you" in plain
    assert "cannot quietly understate how long you had known" in plain


def test_the_scan_is_not_sold_as_a_guarantee_of_awareness(plain):
    """It runs daily against one catalogue. Most awareness will arrive from
    somewhere else entirely, and a reader who took this row for monitoring
    would be relying on it for a 24-hour statutory clock."""
    assert "however that happened — a researcher, a customer, your own testing" in plain
    assert "nothing here is a guarantee that you will find out in time" in plain


def test_it_does_not_claim_to_file_or_certify(plain):
    assert "The tool never submits anything" in plain
    assert "Recording a submission is not a submission." in plain
    assert "only that body can assess conformity" in plain


def test_the_kev_distinction_survives(plain):
    """Art 3(41) 'exploitable' is a wider set than Art 3(42) 'actively
    exploited'. KEV is the latter, so a clean scan does not answer Annex I
    Pt I(2)(a) — and the page must not let a reader think it does."""
    assert "KEV lists what is actively exploited, which is a narrower set" in plain
    assert "a clean KEV result does not answer this requirement on its own" in plain


def test_the_scan_describes_scoring_without_claiming_it_decides(plain):
    """EPSS orders the queue and answers nothing.

    Art 3(41) turns on *potential* to be exploited, which is exactly the
    question a likelihood score looks like it answers — so this row is the one
    place a reader is most likely to take a prediction for a determination.
    Every clause here corresponds to a constraint held by a test in
    `test_epss.py` or `test_epss_reopen.py`; the page may not promise something
    the code does not do, and may not go quiet about the limits the code is
    careful to keep."""
    assert "Candidates are ordered by EPSS" in plain
    assert "There is no threshold anywhere" in plain
    assert "5% sounds negligible and can be the 92nd percentile" in plain
    assert "has not scored is shown as unscored rather than as a low score" in plain
    assert "EPSS informs that judgement and never makes it" in plain


def test_the_twelve_evidence_only_requirements_share_one_answer(data, plain):
    """Written once in the YAML. Twelve separately worded answers would drift
    into twelve slightly different claims about the same thing."""
    stock = [k for k, v in data["annex_i"].items() if v["support"] == "evidence"]
    assert len(stock) == 12
    assert flat(data["evidence_answer"]) in plain


def test_the_limit_of_evidence_tracking_is_stated_once(plain):
    """The caveat lives in the Part I lede rather than against all twelve rows.
    Repeating it was three hundred words of identical text that buried I(1) and
    I(2)(a), where the answer is genuinely different — but dropping it from the
    page entirely would be the more expensive mistake, so it is pinned here."""
    assert "It cannot make the software behave this way" in plain
    assert "a tick against one of these means only that somebody attached a document" in plain


# ---- the two columns cannot be confused ---------------------------------------


def test_every_row_labels_which_half_is_which(html):
    """The left column paraphrases a regulation and the right makes a claim
    about our software. Labelling once per section would leave anyone who
    scrolled with no way to tell them apart."""
    rows = html.count("<dt>")
    assert rows == 61
    assert html.count(">The obligation<") == rows
    assert html.count(">What Skarp CRA does<") == rows


def test_the_page_says_the_summaries_are_paraphrases(plain):
    assert "Every obligation summary is a paraphrase, never a quotation." in plain
    assert "not instead of it" in plain


# ---- it is a page --------------------------------------------------------------


def test_exactly_one_h1(html):
    assert len(re.findall(r"<h1[ >]", html)) == 1


def test_it_is_indexable(html):
    assert 'content="noindex"' not in html


def test_it_loads_nothing_from_another_host(html):
    """The footer publishes this claim site-wide. The one external link is the
    citation to the regulation, which is a link and not a load."""
    subresources = re.findall(
        r'<(?:script|link|img|iframe)[^>]*\b(?:src|href)="([^"]+)"', html
    )
    assert [s for s in subresources if s.startswith(("http:", "https:", "//"))] == []
