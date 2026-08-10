"""The public sample report.

Two jobs here. One: keep the committed page in step with the renderer, because
a marketing page that depicts the product is a claim about the product, and
this is the only claim on the site nothing else would catch going stale.

Two, and the reason this file is longer than it looks like it should be: make
sure the sample cannot be mistaken for a real report. The print rules strip the
masthead, footer and navigation from both, so a printed sample differs from a
printed real report only in its content — and this one describes a product that
does not exist. Every marker asserted below is one that survives printing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.regulation import technical_file_slots  # noqa: E402
from cra.server import sample_report  # noqa: E402

TARGET = ROOT / "www" / "sample-report.html"


@pytest.fixture(scope="module")
def html() -> str:
    return sample_report.render()


# ---- the committed page tracks the renderer ---------------------------------


def test_the_committed_page_is_not_stale():
    """`--check` is the whole point of generating this page rather than writing
    it: the failure it produces is the one nobody would otherwise notice."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render_sample_report.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_it_is_rendered_by_the_same_function_as_the_real_report():
    """Not a copy of the markup — the function itself. A second renderer is a
    second thing to get out of step with Annex VII."""
    from cra.server import console

    assert callable(console.report_article)
    assert "report_article" in Path(
        ROOT / "src" / "cra" / "server" / "sample_report.py"
    ).read_text()


# ---- it cannot be passed off as a real report --------------------------------


def test_it_carries_no_content_hash():
    """The hash is what ties a printed copy to real state. A plausible-looking
    one on a fictional product is a forgery of the only field that could expose
    the forgery."""
    _, out, _ = sample_report._payloads()
    assert "content_hash" not in out
    assert "assembled_at" not in out


def test_no_sixty_four_character_hex_string_appears_anywhere(html):
    """Belt and braces on the above: whatever else changes, nothing on this
    page may look like a sha256 digest."""
    assert not re.search(r"\b[0-9a-f]{64}\b", html)


def test_the_word_sample_survives_printing(html):
    """`@media print` hides `.masthead`, `.sitefoot`, `nav`, `.btn` and
    `.no-print`. Each marker asserted here sits outside all of those, inside
    `<article class="report">` — the part that prints."""
    article = html[html.index("<article class='report'>"):]
    assert "SAMPLE — not generated from recorded state" in article
    assert "sample" in article.lower()
    # The statement block: `@media print` forces its border black precisely so
    # a caveat survives the loss of colour.
    assert "This is a sample document. It describes a product that does not exist." in article
    assert "must not be filed or forwarded" in article


def test_the_product_name_says_sample_in_the_heading(html):
    assert "sample" in sample_report.SAMPLE_NAME.lower()
    assert f"<h1>{sample_report.SAMPLE_NAME}" in html.replace("&mdash;", "—").replace(
        "&#x27;", "'"
    ) or sample_report.SAMPLE_NAME.split(" — ")[0] in html


def test_the_gap_caveat_is_still_there(html):
    """The sample marker is added above the real caveat, never instead of it —
    a reader has to learn both that this is fictional and that a gap means
    'not recorded here'."""
    assert "It does not mean the requirement is unmet." in html


# ---- it depicts the real regulation ------------------------------------------


def test_every_annex_vii_slot_is_shown(html):
    """Eight slots, from the catalogue rather than a list in a template."""
    slots = technical_file_slots()
    assert len(slots) == 8
    for slot in slots:
        assert slot.anchor in html
        assert slot.title in html


def test_it_shows_both_a_filled_and_an_empty_section(html):
    """A sample where everything is missing sells nothing, and one where
    everything is present misrepresents a gap report."""
    assert "RECORDED" in html
    assert "NOT RECORDED" in html


def test_a_renumbered_slot_catalogue_fails_loudly(monkeypatch):
    """Rather than silently rendering every section as a gap."""
    monkeypatch.setattr(sample_report, "_FILLED_SLOTS", {"tf.does-not-exist"})
    with pytest.raises(RuntimeError, match="not in the catalogue"):
        sample_report._slot_views()


def test_a_renumbered_requirement_catalogue_fails_loudly(monkeypatch):
    monkeypatch.setattr(
        sample_report, "_REQUIREMENT_STATE", {"annex_i.nope": ("applicable", "verified", 1)}
    )
    with pytest.raises(RuntimeError, match="not in the catalogue"):
        sample_report._requirement_views()


# ---- it shows the whole product, not one page of it --------------------------


def test_it_shows_the_statutory_reporting_clocks(html):
    """The Article 14 clocks are most of what the product does, and the first
    sample omitted them entirely."""
    assert "overdue" in html.lower()
    assert "Early warning" in html and "Notification" in html
    # Rendered by the real card, so it carries the alert frame.
    assert "card alert" in html


def test_it_shows_all_twenty_two_requirements_with_their_real_text(html):
    """Anchors and wording from the published catalogue, not a table someone
    typed — a paraphrased Annex I on a marketing page is a wrong citation."""
    import html as _html

    from cra.regulation import requirements

    plain = _html.unescape(html)
    reqs = requirements()
    assert len(reqs) == 22
    for r in reqs:
        assert r.anchor in plain
        assert r.summary in plain


def test_it_shows_gaps_being_identified(html):
    """The point of the page: every status word a requirement can carry, so a
    reader sees what "identifying a gap" actually looks like."""
    for word in ("Verified", "Implemented", "In progress", "Not started", "Undetermined"):
        assert f">{word}<" in html, word
    assert "Not applicable" in html
    assert "would leave a hole in the technical file" in html


def test_the_figures_agree_with_the_table_under_them(html):
    """A headline figure that contradicts the rows beneath it is the one error
    a sceptical reader is guaranteed to find."""
    status, _, reqs = sample_report._payloads()
    counts = status["requirements"]
    assert sum(counts["by_applicability"].values()) == len(reqs) == counts["total"]
    assert sum(counts["by_status"].values()) == len(reqs)
    applicable = counts["by_applicability"]["applicable"]
    assert f"{applicable} <small>of {counts['total']}</small>" in html


def test_it_shows_the_stale_risk_assessment_caveat(html):
    """Staleness is a feature — it stops a file looking settled after the
    product moved underneath it."""
    assert "risk assessment is marked stale" in html
    assert "This does not mean nothing is due." in html


def test_it_says_what_the_browser_does_not_do(html):
    """Rather than mocking up screens for work that happens in the agent."""
    assert "The rest happens in the agent" in html
    assert "read-only" in html


def test_only_the_report_prints(html):
    """Sections 1 and 2 are no-print, so printing this page yields the report
    alone — exactly what printing the real console yields. A printed
    requirements table would carry no sample marking at all."""
    for chunk in html.split("<section class=\"wrap")[1:]:
        head = chunk[: chunk.index(">")]
        assert "no-print" in head, f"printable section: {chunk[:120]}"


# ---- it is a public page ------------------------------------------------------


def test_it_is_indexable_and_public():
    response = sample_report.page()
    body = response.body.decode()
    assert response.status_code == 200
    assert 'content="noindex"' not in body
    # No signed-in chrome: there is no viewer.
    assert "Sign out" not in body


def test_it_loads_nothing_from_another_host():
    """The footer publishes this claim site-wide; a generated page is exactly
    where an external asset would sneak in unnoticed."""
    body = sample_report.page().body.decode()
    external = [
        u for u in re.findall(r'(?:src|href)="(https?://[^"]+)"', body)
        if "cra.skarp.app" not in u
    ]
    assert external == []
