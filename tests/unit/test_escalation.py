"""The escalation ladder.

Pure logic, no I/O. The properties worth pinning are the two that make the
difference between a tool people keep enabled and one they filter to spam:
never nag twice for the same rung, and never nag *less* urgently than last
time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cra.deadlines import (
    ESCALATION_LADDER,
    due_rung,
    rung_label,
    sweep_lookahead,
)
from cra.schemas.enums import ReportStage

UTC = timezone.utc
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def _rung(stage, hours_out, sent=()):
    return due_rung(
        stage=stage,
        due_at=NOW + timedelta(hours=hours_out),
        now=NOW,
        already_sent=set(sent),
    )


def test_labels_are_readable_and_stable():
    """These strings are persisted for deduplication, so renaming one silently
    re-sends every alert on that rung."""
    assert rung_label(12) == "T-12h"
    assert rung_label(6) == "T-6h"
    assert rung_label(24) == "T-1d"
    assert rung_label(7 * 24) == "T-7d"
    assert rung_label(None) == "overdue"


def test_every_ladder_ends_in_a_single_overdue_rung():
    for stage, ladder in ESCALATION_LADDER.items():
        assert ladder[-1] is None, stage
        assert ladder.count(None) == 1, stage


def test_ladders_run_from_least_to_most_urgent():
    for stage, ladder in ESCALATION_LADDER.items():
        finite = [r for r in ladder if r is not None]
        assert finite == sorted(finite, reverse=True), stage


def test_the_ladder_is_proportional_to_the_window():
    """12 hours' notice is generous on a 24-hour clock and useless on a
    14-day one; 7 days' notice on a 24-hour clock is impossible."""
    assert max(r for r in ESCALATION_LADDER[ReportStage.EARLY_WARNING] if r) == 12
    assert max(r for r in ESCALATION_LADDER[ReportStage.FINAL] if r) == 7 * 24


def test_the_lookahead_covers_the_longest_first_rung():
    """An obligation must never become visible to the sweeper only after its
    first alert was already due."""
    widest = max(r for ladder in ESCALATION_LADDER.values() for r in ladder if r)
    assert sweep_lookahead() >= timedelta(hours=widest)


# ---- firing ------------------------------------------------------------------


@pytest.mark.parametrize(
    "hours_out,expected",
    [
        (20, None),        # nothing crossed yet
        (12, "T-12h"),     # exactly on the rung counts
        (11, "T-12h"),
        (6.5, "T-12h"),
        (6, "T-6h"),
        (3, "T-6h"),
        (2, "T-2h"),
        (0.25, "T-2h"),
        (-0.5, "overdue"),
        (-500, "overdue"),
    ],
)
def test_the_most_urgent_crossed_rung_fires(hours_out, expected):
    assert _rung(ReportStage.EARLY_WARNING, hours_out) == expected


def test_a_rung_never_fires_twice():
    assert _rung(ReportStage.EARLY_WARNING, 3, sent=["T-6h"]) is None
    assert _rung(ReportStage.EARLY_WARNING, -1, sent=["overdue"]) is None


def test_sending_a_rung_retires_the_gentler_ones_below_it():
    """Having warned at six hours, mailing "12 hours left" an hour later would
    read as a system that has lost track of the deadline."""
    assert _rung(ReportStage.EARLY_WARNING, 5, sent=["T-6h"]) is None
    # ...but the next rung down still fires when it is genuinely reached.
    assert _rung(ReportStage.EARLY_WARNING, 1.5, sent=["T-12h", "T-6h"]) == "T-2h"


def test_a_late_sweep_sends_one_current_alert_not_a_backlog():
    """Down for a day, then a 90-minute-to-go obligation: the user needs "90
    minutes left", not three mails recounting a clock they are already losing."""
    assert _rung(ReportStage.EARLY_WARNING, 1.5) == "T-2h"


def test_overdue_fires_once_and_then_stops():
    """Hourly mail about a missed deadline gets the sender filtered, taking the
    *next* deadline's alerts with it."""
    first = _rung(ReportStage.NOTIFICATION, -2)
    assert first == "overdue"
    assert _rung(ReportStage.NOTIFICATION, -2, sent=[first]) is None
    assert _rung(ReportStage.NOTIFICATION, -240, sent=[first]) is None


def test_each_stage_uses_its_own_ladder():
    # Six hours out: urgent on a 24-hour clock, not yet worth a mail on a
    # 14-day one.
    assert _rung(ReportStage.EARLY_WARNING, 6) == "T-6h"
    assert _rung(ReportStage.FINAL, 6) == "T-1d"
    assert _rung(ReportStage.FINAL, 30) == "T-3d"
    assert _rung(ReportStage.FINAL, 200) is None


def test_stage_accepts_a_plain_string_off_the_database():
    assert _rung("early_warning", 3) == _rung(ReportStage.EARLY_WARNING, 3)
