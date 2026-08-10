"""The Article 13(8) floor, and the one exception to it.

13(8) is two obligations wearing one number. The five-year minimum is the
famous half; the other is that *the information taken into account* in
determining the period goes in the technical documentation, which is what Annex
VII(4) is. A date on its own satisfies neither, and the failure it produces is
the worst kind — a section that reports filled.

The exception is the interesting part to get right. "The support period shall
be at least five years. Where the product with digital elements is expected to
be in use for less than five years, the support period shall correspond to the
expected use time." So a shorter period is not unlawful; it is a *claim about
the product's expected life*, and the tool's job is to make sure it is made
rather than backed into by picking a nearer date.

The escalation ladder is here too, since it is pure.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.server import deadline_sweeper as sweeper  # noqa: E402
from cra.server.scoping import _meets_months, _years_between  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 8, 8, tzinfo=UTC)


# ---- the floor is calendar arithmetic, not elapsed days --------------------------


def test_exactly_five_calendar_years_meets_the_floor():
    """The bug this test exists for, found by the integration suite.

    Five calendar years from 2026-01-01 is 1826 days. Five *average* Gregorian
    years is 1826.21. So a floor checked by dividing elapsed days by 365.2425
    refuses a period of exactly five years — for a reason nobody could explain
    to a user, at precisely the boundary the paragraph is about.

    `deadlines.add_months` already documents this reasoning for "one month" on
    the Article 14 final report. A legal period is measured in calendar units.
    """
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2031, 1, 1, tzinfo=UTC)
    assert _meets_months(start, end, 60)
    assert _years_between(start, end) < 5.0, "the approximation that misled"


def test_a_day_short_of_five_years_does_not():
    assert not _meets_months(
        datetime(2026, 1, 1, tzinfo=UTC), datetime(2030, 12, 31, tzinfo=UTC), 60
    )


def test_a_leap_day_start_clamps_rather_than_overshooting():
    """29 February plus five years has no 29 February to land on. Clamping to
    the 28th is `add_months`'s existing behaviour and the right direction — the
    alternative rolls into March and refuses a period the user would call five
    years."""
    assert _meets_months(
        datetime(2024, 2, 29, tzinfo=UTC), datetime(2029, 2, 28, tzinfo=UTC), 60
    )


def test_the_approximation_is_kept_for_display_only():
    """`_years_between` still exists because the response says "5.0 years",
    which is what a person wants to read. It must never decide anything."""
    import inspect

    from cra.server import scoping

    assert "display only" in inspect.getdoc(scoping._years_between).lower()
    body = inspect.getsource(scoping.set_support_period)
    assert "_meets_months(" in body
    assert "span <" not in body, "the floor must not be decided on the approximation"


# ---- the end-of-support ladder --------------------------------------------------


def _rung(days_out: float, already: set[str] | None = None):
    return sweeper.eos_rung(
        end_at=NOW + timedelta(days=days_out),
        now=NOW,
        already_sent=already or set(),
    )


@pytest.mark.parametrize(
    "days_out,expected",
    [
        (400, None),          # beyond the widest rung: nothing yet
        (180, "eos:T-180d"),
        (120, "eos:T-180d"),  # crossed 180, not yet 90
        (90, "eos:T-90d"),
        (29, "eos:T-30d"),
        (3, "eos:T-7d"),
        (-1, "eos:ended"),
        (-400, "eos:ended"),
    ],
)
def test_the_ladder_reports_the_most_urgent_crossed_rung(days_out, expected):
    assert _rung(days_out) == expected


def test_a_sent_rung_is_not_sent_again():
    assert _rung(90, already={"eos:T-90d"}) is None


def test_sending_an_urgent_rung_retires_the_gentler_ones():
    """A sweeper down for a month should say "30 days left", not replay the
    ladder. Having warned at 30, mailing "90 days left" afterwards would read
    as a system that has lost track."""
    assert _rung(29, already={"eos:T-180d", "eos:T-90d"}) == "eos:T-30d"


def test_the_ended_rung_fires_once():
    """A product out of support needs one unmistakable message, not a daily
    reminder — the status is what answers the question from then on."""
    assert _rung(-30, already={"eos:ended"}) is None


def test_eos_kinds_cannot_collide_with_obligation_rungs():
    """Both write to `notification_log.kind` and dedupe reads that column.
    "T-7d" means one thing on a final report and something very different on a
    support period; a collision would silence a real alert."""
    from cra.deadlines import ESCALATION_LADDER, rung_label

    obligation_kinds = {
        rung_label(r) for ladder in ESCALATION_LADDER.values() for r in ladder
    }
    eos_kinds = {sweeper.eos_kind(r) for r in sweeper._EOS_LADDER}
    assert not (obligation_kinds & eos_kinds)
    assert all(k.startswith("eos:") for k in eos_kinds)
