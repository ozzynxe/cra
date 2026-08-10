"""The statutory clocks.

These are the highest-value tests in the repo: every other feature is a
convenience, but a wrong `due_at` is a missed legal deadline. They pin the
rules, not the implementation — the schedule table can be restructured freely
as long as the dates it produces stay the same.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from cra.deadlines import (
    Anchor,
    OBLIGATION_SCHEDULE,
    add_months,
    due_at_for,
    hours_remaining,
    obligation_state,
    pending_stages,
    schedule_for,
)
from cra.schemas.enums import IncidentKind, ObligationState, ReportStage

UTC = timezone.utc
HELSINKI = ZoneInfo("Europe/Helsinki")


def _stages(pairs):
    return {s: d for s, d in pairs}


# ---- the rule itself ---------------------------------------------------------


def test_exploited_vuln_early_warning_is_24h_from_awareness():
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    got = _stages(
        schedule_for(IncidentKind.ACTIVELY_EXPLOITED_VULN, became_aware_at=aware)
    )
    assert got[ReportStage.EARLY_WARNING] == datetime(2026, 9, 15, 9, 0, tzinfo=UTC)


def test_notification_is_72h_from_awareness_not_from_the_early_warning():
    """The 72h runs from awareness, not cumulatively from the 24h stage.

    Reading it as 24h + 72h would hand the user an extra day they do not have.
    """
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    got = _stages(
        schedule_for(IncidentKind.ACTIVELY_EXPLOITED_VULN, became_aware_at=aware)
    )
    assert got[ReportStage.NOTIFICATION] == aware + timedelta(hours=72)
    assert got[ReportStage.NOTIFICATION] - got[ReportStage.EARLY_WARNING] == timedelta(
        hours=48
    )


def test_exploited_vuln_final_report_is_not_scheduled_without_a_corrective_measure():
    """The 14 days run from when a fix becomes available, not from awareness.

    This is the single easiest thing to get wrong, and getting it wrong invents
    a deadline that does not exist.
    """
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    got = _stages(
        schedule_for(IncidentKind.ACTIVELY_EXPLOITED_VULN, became_aware_at=aware)
    )
    assert ReportStage.FINAL not in got
    assert [r.stage for r in pending_stages(IncidentKind.ACTIVELY_EXPLOITED_VULN)] == [
        ReportStage.FINAL
    ]


def test_exploited_vuln_final_report_lands_14_days_after_the_fix():
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    fix = datetime(2026, 10, 2, 16, 30, tzinfo=UTC)
    got = _stages(
        schedule_for(
            IncidentKind.ACTIVELY_EXPLOITED_VULN,
            became_aware_at=aware,
            corrective_measure_available_at=fix,
        )
    )
    assert got[ReportStage.FINAL] == datetime(2026, 10, 16, 16, 30, tzinfo=UTC)
    # The awareness-anchored stages are unaffected by the fix date.
    assert got[ReportStage.EARLY_WARNING] == aware + timedelta(hours=24)


def test_severe_incident_final_report_is_one_calendar_month_from_awareness():
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    got = _stages(schedule_for(IncidentKind.SEVERE_INCIDENT, became_aware_at=aware))
    assert got[ReportStage.FINAL] == datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
    # Unlike an exploited vuln, all three are known at awareness.
    assert len(got) == 3
    assert pending_stages(IncidentKind.SEVERE_INCIDENT) == []


def test_severe_incident_ignores_a_corrective_measure_date():
    """A fix date must not move a clock that is anchored on awareness."""
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    got = _stages(
        schedule_for(
            IncidentKind.SEVERE_INCIDENT,
            became_aware_at=aware,
            corrective_measure_available_at=datetime(2027, 1, 1, tzinfo=UTC),
        )
    )
    assert got[ReportStage.FINAL] == datetime(2026, 10, 14, 9, 0, tzinfo=UTC)


def test_schedule_accepts_the_kind_as_a_plain_string():
    """Handlers pass the value straight off a DB column."""
    aware = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
    assert schedule_for("severe_incident", became_aware_at=aware) == schedule_for(
        IncidentKind.SEVERE_INCIDENT, became_aware_at=aware
    )


def test_both_kinds_share_the_first_two_stages():
    for kind, rules in OBLIGATION_SCHEDULE.items():
        first_two = [(r.stage, r.anchor, r.offset) for r in rules[:2]]
        assert first_two == [
            (ReportStage.EARLY_WARNING, Anchor.AWARENESS, timedelta(hours=24)),
            (ReportStage.NOTIFICATION, Anchor.AWARENESS, timedelta(hours=72)),
        ], kind


# ---- calendar months ---------------------------------------------------------


@pytest.mark.parametrize(
    "start,expected",
    [
        # A short month clamps rather than spilling into the next one.
        ((2027, 1, 31), (2027, 2, 28)),
        ((2028, 1, 31), (2028, 2, 29)),  # leap year
        ((2026, 1, 30), (2026, 2, 28)),
        ((2026, 3, 31), (2026, 4, 30)),
        # A 31-day month keeps the day of month, so "one month" is 31 days here
        # and 30 there — which is what a calendar month means.
        ((2026, 3, 15), (2026, 4, 15)),
        ((2026, 12, 15), (2027, 1, 15)),  # year rollover
    ],
)
def test_add_months_clamps_to_the_end_of_a_short_month(start, expected):
    got = add_months(datetime(*start, 9, 0, tzinfo=UTC), 1)
    assert (got.year, got.month, got.day) == expected
    assert (got.hour, got.minute) == (9, 0)


def test_one_month_is_not_thirty_days():
    """Guards the specific bug: timedelta(days=30) from 31 January gives 2 March."""
    aware = datetime(2027, 1, 31, 9, 0, tzinfo=UTC)
    got = _stages(schedule_for(IncidentKind.SEVERE_INCIDENT, became_aware_at=aware))
    assert got[ReportStage.FINAL] != aware + timedelta(days=30)
    assert got[ReportStage.FINAL].month == 2


# ---- timezones and DST -------------------------------------------------------


def test_deadlines_are_absolute_instants_across_a_dst_boundary():
    """EU clocks go back on the last Sunday of October.

    24 hours must mean 24 elapsed hours, not "the same wall-clock time
    tomorrow" — the two differ by an hour twice a year, and an hour is 4% of an
    early-warning window.
    """
    # 2026-10-25 03:00 UTC is when Helsinki drops from +03:00 to +02:00.
    aware = datetime(2026, 10, 24, 12, 0, tzinfo=HELSINKI)
    got = _stages(schedule_for(IncidentKind.SEVERE_INCIDENT, became_aware_at=aware))
    early = got[ReportStage.EARLY_WARNING]

    assert (early - aware) == timedelta(hours=24)
    # Same instant, and the local wall clock has shifted by the DST hour.
    assert early.astimezone(UTC) == datetime(2026, 10, 25, 9, 0, tzinfo=UTC)
    assert early.astimezone(HELSINKI).hour == 11


def test_the_anchors_timezone_does_not_change_the_deadline():
    """Two spellings of one instant must produce one schedule, in UTC."""
    a = datetime(2026, 9, 14, 12, 0, tzinfo=HELSINKI)
    b = a.astimezone(UTC)
    got = schedule_for(IncidentKind.SEVERE_INCIDENT, became_aware_at=a)
    assert got == schedule_for(IncidentKind.SEVERE_INCIDENT, became_aware_at=b)
    assert all(due.tzinfo is UTC for _, due in got)


def test_a_naive_anchor_is_rejected_rather_than_assumed_to_be_local():
    with pytest.raises(ValueError, match="timezone-aware"):
        schedule_for(
            IncidentKind.SEVERE_INCIDENT, became_aware_at=datetime(2026, 9, 14, 12, 0)
        )


# ---- derived status ----------------------------------------------------------


def _due(hours_from_now: float, now: datetime) -> datetime:
    return now + timedelta(hours=hours_from_now)


NOW = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def test_state_is_pending_while_the_deadline_is_far_off():
    assert (
        obligation_state(
            due_at=_due(20, NOW), stage=ReportStage.EARLY_WARNING, now=NOW
        )
        is ObligationState.PENDING
    )


def test_state_is_due_soon_inside_the_stage_window():
    """The window is proportional: 6h on a 24h clock, 3 days on a 14-day one."""
    assert (
        obligation_state(due_at=_due(5, NOW), stage=ReportStage.EARLY_WARNING, now=NOW)
        is ObligationState.DUE_SOON
    )
    # Same five hours is merely pending on the final-report clock.
    assert (
        obligation_state(due_at=_due(5, NOW), stage=ReportStage.FINAL, now=NOW)
        is ObligationState.DUE_SOON
    )
    assert (
        obligation_state(due_at=_due(100, NOW), stage=ReportStage.FINAL, now=NOW)
        is ObligationState.PENDING
    )


def test_state_is_overdue_past_the_deadline():
    assert (
        obligation_state(due_at=_due(-0.1, NOW), stage=ReportStage.NOTIFICATION, now=NOW)
        is ObligationState.OVERDUE
    )


def test_submission_records_on_time_or_late_from_stored_facts_alone():
    due = _due(10, NOW)
    assert (
        obligation_state(due_at=due, submitted_at=due - timedelta(minutes=1), now=NOW)
        is ObligationState.SUBMITTED
    )
    assert (
        obligation_state(due_at=due, submitted_at=due + timedelta(minutes=1), now=NOW)
        is ObligationState.SUBMITTED_LATE
    )


def test_a_late_submission_stays_late_no_matter_when_you_ask():
    """Derived status must not drift with the wall clock once the facts are in.

    This is the property that makes an outage an availability problem rather
    than a compliance one.
    """
    due = datetime(2026, 9, 15, 9, 0, tzinfo=UTC)
    submitted = due + timedelta(hours=2)
    for offset in (timedelta(minutes=1), timedelta(days=400)):
        assert (
            obligation_state(due_at=due, submitted_at=submitted, now=submitted + offset)
            is ObligationState.SUBMITTED_LATE
        )


def test_a_waiver_outranks_everything_including_being_overdue():
    assert (
        obligation_state(
            due_at=_due(-500, NOW),
            waived_reason="out of scope: open-source steward",
            now=NOW,
        )
        is ObligationState.WAIVED
    )


def test_obligation_state_touches_no_clock_of_its_own_when_now_is_given():
    """Purity in the sense that matters: same inputs, same answer, forever."""
    due = _due(3, NOW)
    first = obligation_state(due_at=due, stage=ReportStage.EARLY_WARNING, now=NOW)
    second = obligation_state(due_at=due, stage=ReportStage.EARLY_WARNING, now=NOW)
    assert first is second is ObligationState.DUE_SOON


def test_hours_remaining_goes_negative_once_overdue():
    assert hours_remaining(_due(2.5, NOW), NOW) == 2.5
    assert hours_remaining(_due(-2.5, NOW), NOW) == -2.5


def test_due_at_for_returns_none_when_the_anchor_has_not_happened():
    rule = OBLIGATION_SCHEDULE[IncidentKind.ACTIVELY_EXPLOITED_VULN][2]
    assert rule.anchor is Anchor.CORRECTIVE_MEASURE
    assert due_at_for(rule, became_aware_at=NOW) is None
    assert (
        due_at_for(rule, became_aware_at=NOW, corrective_measure_available_at=NOW)
        == NOW + timedelta(days=14)
    )
