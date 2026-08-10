"""Article 13(13) retention is a rule, not the number it used to be.

    Manufacturers shall keep the technical documentation and the EU
    declaration of conformity at the disposal of the market surveillance
    authorities for at least 10 years after the product with digital elements
    has been placed on the market **or for the support period, whichever is
    longer**.

Three things were wrong before 2026-08-09 and each is pinned below: the period
was a flat ten years, so it was short for any product supported longer; it was
cited to Annex VII, which lists what the file contains and says nothing about
keeping it; and it was reported for products that had never been placed on the
market, where the clock has not started at all.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from cra.regulation import technical_file_retention  # noqa: E402
from cra.schemas.compliance import ComplianceState, Release, SupportPeriod  # noqa: E402
from cra.server.conformity import retention_status  # noqa: E402


def _utc(y, m, d) -> datetime:
    return datetime(y, m, d, tzinfo=timezone.utc)


def _state(*, releases=(), support_end=None) -> ComplianceState:
    now = _utc(2026, 1, 1)
    s = ComplianceState(product_id="p", name="n", created_at=now, updated_at=now)
    s.releases = list(releases)
    s.support_period = SupportPeriod(end=support_end)
    return s


def _release(version: str, at: datetime) -> Release:
    return Release(version=version, released_at=at, recorded_at=at)


def test_the_rule_is_cited_to_article_13_13_not_annex_vii():
    """Annex VII is the list of contents. The duty to keep is Article 13(13)."""
    rule = technical_file_retention()
    assert rule["anchor"] == "Article 13(13)"
    assert "Annex VII" not in rule["anchor"]


def test_a_product_not_placed_on_market_has_no_clock():
    out = retention_status(_state())
    assert out["until"] is None
    assert out["basis"] == "not_yet_placed_on_market"


def test_ten_years_runs_from_placing_on_the_market():
    out = retention_status(_state(releases=[_release("1.0", _utc(2026, 4, 18))]))
    assert out["until"].startswith("2036-04-18")
    assert out["basis"] == "ten_years_from_placing_on_market"


def test_a_longer_support_period_wins():
    """The half that a flat ten years got wrong, and got wrong short."""
    out = retention_status(
        _state(
            releases=[_release("1.0", _utc(2026, 4, 18))],
            support_end=_utc(2042, 1, 1),
        )
    )
    assert out["until"].startswith("2042-01-01")
    assert out["basis"] == "support_period"
    assert out["until"][:4] > "2036", "a 16-year support period must not report 10 years"


def test_a_shorter_support_period_does_not_shorten_it():
    out = retention_status(
        _state(
            releases=[_release("1.0", _utc(2026, 4, 18))],
            support_end=_utc(2031, 4, 18),
        )
    )
    assert out["until"].startswith("2036-04-18")
    assert out["basis"] == "ten_years_from_placing_on_market"


def test_the_latest_release_is_the_anchor():
    """Each placing carries its own ten years; the newest binds longest."""
    out = retention_status(
        _state(
            releases=[
                _release("1.0", _utc(2026, 1, 1)),
                _release("2.0", _utc(2029, 6, 1)),
            ]
        )
    )
    assert out["until"].startswith("2039-06-01")


def test_ten_years_is_calendar_arithmetic_not_3650_days():
    """Two leap days sit inside a decade; days-based arithmetic lands early."""
    placed = _utc(2026, 4, 18)
    out = retention_status(_state(releases=[_release("1.0", placed)]))
    until = datetime.fromisoformat(out["until"])
    assert until == _utc(2036, 4, 18)
    assert until != placed + timedelta(days=3650)
