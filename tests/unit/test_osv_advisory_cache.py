"""One advisory record is the same for everyone who matches it.

`scan_product` dedupes advisory fetches within a single product and then throws
the result away, so the nightly sweep re-fetched `/v1/vulns/{id}` once per
product per advisory. A hundred products shipping the same library meant a
hundred identical GETs for the same handful of records, every night. The work
scaled with `products x advisories` when the distinct advisories are what it
actually depends on, which made the nightly sweep by far the heaviest thing
this service does.

The duplication happens *within* one pass, so an in-memory cache captures it.

The part worth guarding hardest is the negative case: caching a failed fetch
would turn one network blip into a day of missing detail across every product,
which is the "absence of knowledge as knowledge of absence" trap the rest of
this module is built to avoid.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from cra.advisories import feeds  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_cache():
    feeds._advisory_cache.entries.clear()
    feeds._advisory_cache.fetched.clear()
    feeds._advisory_cache.hits = 0
    feeds._advisory_cache.misses = 0
    yield


def _counting_get(monkeypatch, result):
    calls = []

    def fake(url, *, data=None):
        calls.append(url)
        return result() if callable(result) else result

    monkeypatch.setattr(feeds, "_get", fake)
    return calls


def test_the_same_advisory_is_fetched_once(monkeypatch):
    calls = _counting_get(monkeypatch, {"id": "GHSA-x", "summary": "s"})
    for _ in range(50):
        assert feeds.osv_advisory("GHSA-x")["id"] == "GHSA-x"
    assert len(calls) == 1, f"expected one fetch, made {len(calls)}"


def test_different_advisories_are_fetched_separately(monkeypatch):
    calls = _counting_get(monkeypatch, lambda: {"id": "any"})
    feeds.osv_advisory("GHSA-a")
    feeds.osv_advisory("GHSA-b")
    assert len(calls) == 2


def test_a_failed_fetch_is_never_cached(monkeypatch):
    """The trap. One blip must not become a day of silence."""
    calls = _counting_get(monkeypatch, None)
    assert feeds.osv_advisory("GHSA-down") is None
    assert feeds.osv_advisory("GHSA-down") is None
    assert len(calls) == 2, "a failure was cached — a blip would persist for the TTL"


def test_recovery_after_a_failure_is_immediate(monkeypatch):
    state = {"fail": True}

    def flaky(url, *, data=None):
        return None if state["fail"] else {"id": "GHSA-x", "summary": "back"}

    monkeypatch.setattr(feeds, "_get", flaky)
    assert feeds.osv_advisory("GHSA-x") is None
    state["fail"] = False
    assert feeds.osv_advisory("GHSA-x")["summary"] == "back"


def test_the_ttl_expires_an_entry(monkeypatch):
    calls = _counting_get(monkeypatch, {"id": "GHSA-x"})
    feeds.osv_advisory("GHSA-x")
    # Age the entry past its window rather than sleeping.
    feeds._advisory_cache.fetched["GHSA-x"] -= feeds._advisory_ttl() + 1
    feeds.osv_advisory("GHSA-x")
    assert len(calls) == 2


def test_the_cache_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("CRA_OSV_ADVISORY_TTL_SECONDS", "0")
    calls = _counting_get(monkeypatch, {"id": "GHSA-x"})
    feeds.osv_advisory("GHSA-x")
    feeds.osv_advisory("GHSA-x")
    assert len(calls) == 2


def test_a_nonsense_ttl_falls_back_rather_than_crashing(monkeypatch):
    monkeypatch.setenv("CRA_OSV_ADVISORY_TTL_SECONDS", "one day")
    assert feeds._advisory_ttl() == 24 * 3600


def test_it_is_bounded(monkeypatch):
    monkeypatch.setenv("CRA_OSV_ADVISORY_CACHE_MAX", "100")
    _counting_get(monkeypatch, lambda: {"id": "x"})
    for i in range(400):
        feeds.osv_advisory(f"GHSA-{i}")
    assert len(feeds._advisory_cache.entries) <= 100
    assert len(feeds._advisory_cache.fetched) == len(feeds._advisory_cache.entries)


def test_the_win_is_measured_across_products_not_within_one(monkeypatch):
    """What the sweep actually does: many products, overlapping components.

    Ten products each matching the same three advisories used to be thirty
    fetches. It is now three.
    """
    calls = _counting_get(monkeypatch, lambda: {"id": "shared"})
    for _product in range(10):
        for advisory in ("GHSA-a", "GHSA-b", "GHSA-c"):
            feeds.osv_advisory(advisory)
    assert len(calls) == 3
    assert feeds._advisory_cache.hits == 27
