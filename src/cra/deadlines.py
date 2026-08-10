"""The statutory reporting clocks, in one auditable place.

Article 14 of Regulation (EU) 2024/2847. Everything about *when* a report is
due lives here, so a rule change is one edit against one table rather than a
hunt through handlers.

Two things this module is careful about:

**The final report does not run from awareness.** For an actively exploited
vulnerability the 14 days run from when a *corrective measure becomes
available* — a moment that has usually not happened when the incident is first
recorded. So that obligation is not materialised until its anchor exists. You
cannot be late for a clock that has not started, and showing a fabricated due
date would be worse than showing none.

**Status is derived, never stored.** `obligation_state()` is a pure function of
stored facts. A persisted `overdue` boolean flipped by a sweeper would mean a
sweeper outage silently marks someone compliant — the failure mode you least
want in a compliance tool.
"""

from __future__ import annotations

import calendar
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from cra.schemas.enums import IncidentKind, ObligationState, ReportStage


class Anchor(str, Enum):
    """What a stage's clock counts from."""

    AWARENESS = "awareness"
    CORRECTIVE_MEASURE = "corrective_measure"


@dataclass(frozen=True)
class StageRule:
    stage: ReportStage
    anchor: Anchor
    offset: Optional[timedelta] = None
    offset_months: int = 0

    def describe(self) -> str:
        window = f"{self.offset_months} month" if self.offset_months else _human(self.offset)
        return f"{window} from {self.anchor.value.replace('_', ' ')}"


def _human(td: Optional[timedelta]) -> str:
    if td is None:
        return "unknown"
    hours = int(td.total_seconds() // 3600)
    return f"{hours}h" if hours < 48 else f"{hours // 24} days"


# The legal rule. Both incident kinds share the first two stages and differ
# only in the final one — but they differ in *anchor* as well as length, which
# is the part that is easy to get wrong.
OBLIGATION_SCHEDULE: dict[IncidentKind, tuple[StageRule, ...]] = {
    IncidentKind.ACTIVELY_EXPLOITED_VULN: (
        StageRule(ReportStage.EARLY_WARNING, Anchor.AWARENESS, timedelta(hours=24)),
        StageRule(ReportStage.NOTIFICATION, Anchor.AWARENESS, timedelta(hours=72)),
        StageRule(ReportStage.FINAL, Anchor.CORRECTIVE_MEASURE, timedelta(days=14)),
    ),
    IncidentKind.SEVERE_INCIDENT: (
        StageRule(ReportStage.EARLY_WARNING, Anchor.AWARENESS, timedelta(hours=24)),
        StageRule(ReportStage.NOTIFICATION, Anchor.AWARENESS, timedelta(hours=72)),
        # "Within one month." Anchored on awareness rather than on the 72h
        # notification: that is the earlier of the two readings, and where the
        # guidance is ambiguous the safe deadline is the early one.
        StageRule(ReportStage.FINAL, Anchor.AWARENESS, offset_months=1),
    ),
}

# How far ahead a deadline reads as "due soon" rather than merely pending.
# Proportional to the window — six hours of warning is generous on a 24-hour
# clock and useless on a 14-day one.
DUE_SOON_WINDOW: dict[ReportStage, timedelta] = {
    ReportStage.EARLY_WARNING: timedelta(hours=6),
    ReportStage.NOTIFICATION: timedelta(hours=24),
    ReportStage.FINAL: timedelta(days=3),
}


def add_months(dt: datetime, months: int) -> datetime:
    """Calendar-month arithmetic, clamped to the end of a short month.

    "One month" is a calendar month, not 30 days: from 31 January it lands on
    28 February (29 in a leap year), not 2 March. Using timedelta(days=30) here
    would quietly produce the wrong legal date for roughly half the year.
    """
    month = dt.month - 1 + months
    year = dt.year + month // 12
    month = month % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def _as_utc(dt: datetime, *, field: str) -> datetime:
    """Normalise to UTC before any arithmetic. This is not cosmetic.

    Python's `datetime + timedelta` on a zoneinfo-aware value is *wall-clock*
    arithmetic: it adds to the naive fields and keeps the tzinfo, then the
    offset is re-derived. Add 24 hours to 12:00 on the day EU clocks go back
    and you get 12:00 the next day — 25 elapsed hours. The subtraction
    `later - earlier` even reports 24h, because Python skips the offset
    adjustment when both sides share a tzinfo object, so the error hides.

    "Within 24 hours of becoming aware" means 24 elapsed hours. Doing the
    arithmetic in UTC is what makes it so.
    """
    if dt.tzinfo is None:
        raise ValueError(
            f"{field} must be timezone-aware — a naive timestamp cannot anchor "
            "a statutory deadline"
        )
    return dt.astimezone(timezone.utc)


def due_at_for(
    rule: StageRule,
    *,
    became_aware_at: datetime,
    corrective_measure_available_at: Optional[datetime] = None,
) -> Optional[datetime]:
    """When this stage falls due, in UTC, or None if its anchor hasn't happened.

    Always returns UTC regardless of the anchor's own timezone: a deadline is
    an instant, and every consumer either stores it (`timestamptz`) or renders
    it against a chosen zone.
    """
    if rule.anchor is Anchor.AWARENESS:
        base = _as_utc(became_aware_at, field="became_aware_at")
    else:
        if corrective_measure_available_at is None:
            return None
        base = _as_utc(
            corrective_measure_available_at, field="corrective_measure_available_at"
        )

    if rule.offset_months:
        return add_months(base, rule.offset_months)
    assert rule.offset is not None
    return base + rule.offset


def schedule_for(
    kind: IncidentKind | str,
    *,
    became_aware_at: datetime,
    corrective_measure_available_at: Optional[datetime] = None,
) -> list[tuple[ReportStage, datetime]]:
    """Every stage whose clock has actually started, with its due date.

    Stages whose anchor is still unknown are omitted rather than guessed —
    they materialise later, when the anchoring event is recorded.
    """
    rules = OBLIGATION_SCHEDULE[IncidentKind(kind)]
    out: list[tuple[ReportStage, datetime]] = []
    for rule in rules:
        due = due_at_for(
            rule,
            became_aware_at=became_aware_at,
            corrective_measure_available_at=corrective_measure_available_at,
        )
        if due is not None:
            out.append((rule.stage, due))
    return out


def pending_stages(kind: IncidentKind | str) -> list[StageRule]:
    """Stages that need an anchor event before they can be scheduled."""
    return [
        r
        for r in OBLIGATION_SCHEDULE[IncidentKind(kind)]
        if r.anchor is not Anchor.AWARENESS
    ]


def obligation_state(
    *,
    due_at: datetime,
    submitted_at: Optional[datetime] = None,
    waived_reason: Optional[str] = None,
    stage: ReportStage | str = ReportStage.EARLY_WARNING,
    now: Optional[datetime] = None,
) -> ObligationState:
    """Derive an obligation's status from stored facts only.

    Pure by design: no I/O, no clock of its own unless you omit `now`. That is
    what lets a sweeper outage be an availability problem rather than a
    compliance one.
    """
    if waived_reason:
        return ObligationState.WAIVED
    if submitted_at is not None:
        return (
            ObligationState.SUBMITTED_LATE
            if submitted_at > due_at
            else ObligationState.SUBMITTED
        )

    now = now or datetime.now(due_at.tzinfo)
    if now > due_at:
        return ObligationState.OVERDUE

    window = DUE_SOON_WINDOW.get(ReportStage(stage), timedelta(hours=6))
    return ObligationState.DUE_SOON if due_at - now <= window else ObligationState.PENDING


def hours_remaining(due_at: datetime, now: Optional[datetime] = None) -> float:
    """Negative once overdue. Rounded to one decimal — a compliance clock
    reported to the microsecond invites false precision."""
    now = now or datetime.now(due_at.tzinfo)
    return round((due_at - now).total_seconds() / 3600, 1)


def sweep_lookahead() -> timedelta:
    """How far ahead the sweeper looks for approaching deadlines.

    Wide enough to cover the longest first rung on any ladder below, so no
    obligation becomes visible to the sweeper only after its first alert was
    already due.
    """
    hours = int(os.environ.get("CRA_SWEEP_LOOKAHEAD_HOURS", str(8 * 24)))
    return timedelta(hours=hours)


# ---- escalation ------------------------------------------------------------

# When to nag, per stage, as hours remaining. Proportional to the window: on a
# 24-hour clock the first warning at 12 hours still leaves half the time, while
# 12 hours' notice on a 14-day report would be an alarm nobody can act on.
#
# `None` is the overdue rung. It fires once after the deadline passes and then
# stops: a compliance tool that mails hourly about a missed deadline gets
# filtered to spam, taking the *next* deadline's alerts with it.
ESCALATION_LADDER: dict[ReportStage, tuple[Optional[float], ...]] = {
    ReportStage.EARLY_WARNING: (12, 6, 2, None),
    ReportStage.NOTIFICATION: (48, 24, 6, None),
    ReportStage.FINAL: (7 * 24, 3 * 24, 24, None),
}


def rung_label(rung: Optional[float]) -> str:
    """Stable identifier for one step of a ladder, used to deduplicate sends.

    Deliberately derived from the rung rather than a timestamp: "did we already
    send the six-hour warning" is the question, and answering it from a clock
    value breaks the moment a sweep is late.
    """
    if rung is None:
        return "overdue"
    if rung >= 24 and rung % 24 == 0:
        return f"T-{int(rung // 24)}d"
    return f"T-{int(rung)}h"


def due_rung(
    *,
    stage: ReportStage | str,
    due_at: datetime,
    now: datetime,
    already_sent: set[str],
) -> Optional[str]:
    """Label of the most urgent unsent rung this obligation has reached.

    Returns None when nothing is owed. Returns a *label* rather than a value
    because the overdue rung's value is itself `None`, and a function whose
    "nothing to do" and "the deadline has passed" answers are the same object
    is one somebody will eventually get backwards.

    Only the most urgent crossed rung is considered, and only if it has not
    already been sent. Two consequences, both intended:

    - A sweeper that has been down for a day sends one alert saying "two hours
      left" rather than a burst restating the history of a clock the user is
      already late for.
    - Sending a rung retires every gentler rung below it. Having warned at six
      hours, mailing "12 hours left" an hour later would be a regression in
      urgency and read as a system that has lost track of the deadline.
    """
    ladder = ESCALATION_LADDER.get(ReportStage(stage), ())
    remaining = (due_at - now).total_seconds() / 3600

    for rung in reversed(ladder):  # most urgent first
        crossed = remaining < 0 if rung is None else 0 <= remaining <= rung
        if not crossed:
            continue
        label = rung_label(rung)
        return None if label in already_sent else label
    return None
