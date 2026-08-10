"""EPSS: the four constraints, held in place.

EPSS is a *prediction* wired into a system whose other inputs are facts. KEV
says exploitation was observed; an SBOM says a component ships. EPSS says a
model thinks something is likely, and the risk it carries into this codebase is
that a number which looks authoritative gets used to decide something it cannot
decide.

Issue #16 settled four constraints before any of it was built. Each one is a
test here, because each describes a way this feature could quietly become
harmful rather than a way it could break:

1. No default threshold — any cutoff is a compliance policy, not a fact.
2. A missing score is unknown, never low.
3. Never a justification on its own.
4. Store the provenance, or the score cannot be explained later.

`CVE-2020-8203` runs through several of these as the standing counter-example:
0.05213 probability at the 91.7th percentile. Anyone reading probability alone
files it under "negligible", and they are wrong.
"""

from __future__ import annotations

import gzip
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.advisories import build_findings  # noqa: E402
from cra.advisories import feeds  # noqa: E402
from cra.advisories.match import Finding  # noqa: E402

HEADER = "#model_version:v2026.06.15,score_date:2026-08-07T12:03:11Z\ncve,epss,percentile\n"

# Real rows from the live feed, so the numbers under test are the ones the
# model actually produces.
ROWS = (
    "CVE-1999-0001,0.03351,0.8753\n"
    "CVE-2020-8203,0.05213,0.91707\n"
    "CVE-2021-44228,0.99999,1.0\n"
)


def _feed(body: str = HEADER + ROWS) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as fh:
        fh.write(body.encode())
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _clean_cache():
    feeds._epss_cache = feeds.EpssCatalogue()
    yield
    feeds._epss_cache = feeds.EpssCatalogue()


@pytest.fixture
def served(monkeypatch):
    """Serve a feed body, and report how many times it was fetched."""

    def _serve(body: bytes | str = None):
        payload = _feed() if body is None else (body if isinstance(body, bytes) else _feed(body))
        calls = []

        def fake(url):
            calls.append(url)
            return payload

        monkeypatch.setattr(feeds, "_raw", fake)
        return calls

    return _serve


# ---- the feed reader ----------------------------------------------------------


def test_it_reads_scores_and_provenance(served):
    served()
    cat = feeds.epss_catalogue(force=True)
    assert cat.ok
    assert cat.model_version == "v2026.06.15"
    assert cat.score_date == "2026-08-07T12:03:11Z"

    scores = feeds.epss_scores(["CVE-2021-44228"])
    assert scores["CVE-2021-44228"].probability == pytest.approx(0.99999)
    assert scores["CVE-2021-44228"].percentile == pytest.approx(1.0)


def test_constraint_2_a_missing_score_is_absent_not_zero(served):
    """The feed omits CVEs the model has not scored. `epss_scores` must return
    a sparse dict, because the alternative — a score per input, defaulting to
    0.0 — turns "not assessed" into "assessed, negligible" and sorts unscored
    CVEs to the bottom of the queue looking safe."""
    served()
    scores = feeds.epss_scores(["CVE-2021-44228", "CVE-2026-9999999"])
    assert "CVE-2021-44228" in scores
    assert "CVE-2026-9999999" not in scores
    assert scores.get("CVE-2026-9999999") is None


def test_a_failed_fetch_keeps_the_previous_feed(served, monkeypatch):
    """Same rule as KEV. An emptied catalogue would blank every score on the
    next scan, which is not false but silently drops the ordering signal from a
    queue somebody is working."""
    served()
    assert feeds.epss_catalogue(force=True).ok

    monkeypatch.setattr(feeds, "_raw", lambda url: None)
    cat = feeds.epss_catalogue(force=True)
    assert cat.ok, "a dead fetch must not clear a good catalogue"
    assert feeds.epss_scores(["CVE-2021-44228"])


def test_a_feed_without_provenance_is_refused(served):
    """Constraint 4. A score whose model version and date are unknown cannot be
    reproduced or explained, so it is worth less than no score at all."""
    served(HEADER.split("\n", 1)[1] + ROWS)  # header line stripped
    assert not feeds.epss_catalogue(force=True).ok


def test_a_corrupt_feed_does_not_raise(served):
    served(b"this is not gzip")
    assert not feeds.epss_catalogue(force=True).ok
    assert feeds.epss_scores(["CVE-2021-44228"]) == {}


def test_it_does_not_refetch_within_the_ttl(served, monkeypatch):
    monkeypatch.setenv("CRA_EPSS_TTL_SECONDS", "3600")
    calls = served()
    feeds.epss_catalogue(force=True)
    feeds.epss_catalogue()
    feeds.epss_catalogue()
    assert len(calls) == 1


def test_no_cve_list_is_ever_sent_out(served):
    """The whole reason the full file is mirrored rather than the per-CVE API
    being queried: asking `api.first.org` about the CVEs in a customer's SBOM
    would disclose exactly what the mirror avoids."""
    calls = served()
    feeds.epss_catalogue(force=True)
    feeds.epss_scores(["CVE-2021-44228", "CVE-2020-8203"])
    assert len(calls) == 1
    assert "first.org" not in calls[0]
    assert "CVE-" not in calls[0]


# ---- ordering ------------------------------------------------------------------


def _finding(advisory_id, *, exploited=False, pct=None, prob=None):
    return Finding(
        advisory_id=advisory_id,
        component_name="c",
        component_version="1",
        component_ecosystem="PyPI",
        exploited=exploited,
        epss_percentile=pct,
        epss_probability=prob,
    )


def test_constraint_1_exploited_outranks_any_prediction():
    """A KEV listing is observed exploitation carrying a 24-hour clock. EPSS is
    a model's guess. Letting 0.99 outrank a listing would put a backlog item
    above a reporting duty."""
    low_but_exploited = _finding("A", exploited=True, pct=0.01)
    high_prediction = _finding("B", pct=0.999)
    assert sorted([high_prediction, low_but_exploited], key=lambda f: f.rank())[0] is (
        low_but_exploited
    )


def test_unscored_sorts_after_scored_not_as_zero():
    """Constraint 2 again, at the ordering layer. An unscored CVE placed as
    though it were 0.0 sits below a genuinely negligible one and reads as
    triaged."""
    scored_low = _finding("A", pct=0.02)
    unscored = _finding("B", pct=None)
    order = sorted([unscored, scored_low], key=lambda f: f.rank())
    assert order == [scored_low, unscored]


def test_the_queue_is_ordered_by_percentile_not_probability():
    """The CVE-2020-8203 case. Ordering on probability would bury a 92nd-
    percentile CVE beneath things that are unremarkable among their peers."""
    modest_probability_high_rank = _finding("A", prob=0.05213, pct=0.91707)
    higher_probability_lower_rank = _finding("B", prob=0.08, pct=0.40)
    order = sorted(
        [higher_probability_lower_rank, modest_probability_high_rank],
        key=lambda f: f.rank(),
    )
    assert order[0] is modest_probability_high_rank


# ---- joining to findings --------------------------------------------------------


class _Comp:
    name, version, ecosystem, purl = "left-pad", "1.0.0", "npm", None

    def key(self):
        return (self.name, self.version, self.ecosystem)


class _Parsed:
    components = [_Comp()]
    coverage_note = None


class _Osv:
    by_component = {_Comp().key(): ["GHSA-xxxx"]}
    ok = True


class _Kev:
    ok = True
    entries: dict = {}

    def __contains__(self, cve):
        return False

    def get(self, cve):
        return None


def _build(epss, cat=None):
    return build_findings(
        parsed=_Parsed(),
        osv_result=_Osv(),
        kev=_Kev(),
        advisory_details={"GHSA-xxxx": {"aliases": ["CVE-2020-8203"], "summary": "s"}},
        epss=epss,
        epss_catalogue=cat,
    )


def test_a_score_reaches_the_finding_through_a_ghsa_alias():
    """OSV answers with GHSA ids and EPSS is keyed on CVE. Without the alias
    hop every score would be null."""
    score = feeds.EpssScore("CVE-2020-8203", 0.05213, 0.91707)
    result = _build({"CVE-2020-8203": score})
    assert result.findings[0].epss_percentile == pytest.approx(0.91707)
    assert result.findings[0].epss_cve_id == "CVE-2020-8203"


def test_the_worst_alias_wins():
    """One advisory can alias several CVEs scoring differently. Taking the
    highest errs toward a human looking."""
    result = build_findings(
        parsed=_Parsed(),
        osv_result=_Osv(),
        kev=_Kev(),
        advisory_details={
            "GHSA-xxxx": {"aliases": ["CVE-2020-8203", "CVE-2021-44228"], "summary": ""}
        },
        epss={
            "CVE-2020-8203": feeds.EpssScore("CVE-2020-8203", 0.05, 0.91),
            "CVE-2021-44228": feeds.EpssScore("CVE-2021-44228", 0.99999, 1.0),
        },
    )
    assert result.findings[0].epss_percentile == pytest.approx(1.0)


def test_no_scores_leaves_findings_intact_and_unscored():
    """Constraint 2 at the scan layer: an EPSS outage must not suppress or
    alter a finding, only leave it unranked."""
    result = _build({})
    assert len(result.findings) == 1
    assert result.findings[0].epss_percentile is None
    assert result.epss_ok is False


def test_epss_failure_does_not_make_the_scan_incomplete():
    """`sources_ok` is about whether the scan happened. KEV and OSV decide
    that; EPSS only orders what they found. Folding it in would mean a scoring
    outage suppressed a KEV hit."""
    result = _build({})
    assert result.sources_ok is True
    assert result.epss_ok is False


def test_provenance_travels_with_the_scores():
    """Constraint 4."""

    class _Cat:
        ok = True
        model_version = "v2026.06.15"
        score_date = "2026-08-07T12:03:11Z"

    result = _build({}, cat=_Cat())
    assert result.epss_model_version == "v2026.06.15"
    assert result.epss_score_date == "2026-08-07T12:03:11Z"
