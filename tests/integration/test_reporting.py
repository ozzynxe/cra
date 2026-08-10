"""Vulnerability → incident → obligation flow against a real database.

Skipped without DATABASE_URL, following the repo's `_NEEDS_DB` pattern.

The tests that earn their keep are the cascade ones. Article 14 turns on
*active exploitation*, and a developer who has just discovered they are being
exploited will not also remember to file a separate incident record. If the
cascade is wrong, the clock never starts and the tool has failed at the one
job it exists for.

These go through `dispatch()` rather than calling handlers directly, because
the envelope is the contract: a tool failure must reach the agent as data.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import (  # noqa: E402
    AuditEvent,
    Incident,
    ReportingObligation,
    User,
    session_scope,
)
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc


def _now():
    return datetime.now(UTC)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def product(owner):
    pid = str(uuid.uuid4())
    now = _now()
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Acme Gateway",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    return pid


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


def _obligations(product_id):
    with session_scope() as s:
        return list(
            s.query(ReportingObligation)
            .filter(ReportingObligation.product_id == product_id)
            .order_by(ReportingObligation.due_at)
        )


def _audit_ops(product_id):
    with session_scope() as s:
        return [
            e.op
            for e in s.query(AuditEvent)
            .filter(AuditEvent.product_id == product_id)
            # ts then id: rows from one transaction share a ts exactly, so
            # ordering on it alone made this assertion intermittently fail.
            .order_by(AuditEvent.ts, AuditEvent.id)
        ]


# ---- the cascade -------------------------------------------------------------


def test_a_plain_vulnerability_starts_no_clock(product, owner):
    r = _call("record_vulnerability", product, owner, summary="XSS in admin UI")
    assert r["ok"] is True
    assert r["actively_exploited"] is False
    assert "incident_id" not in r
    assert _obligations(product) == []
    # And it says what would change that, since the user is one fact away from
    # a 24-hour clock.
    assert "actively_exploited" in r["note"]


def test_recording_an_exploited_vulnerability_opens_an_incident_and_two_clocks(
    product, owner
):
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE, exploited in the wild",
        identifier="CVE-2026-1234",
        actively_exploited=True,
    )
    assert r["ok"] is True
    assert r["incident_id"]
    stages = {d["stage"] for d in r["deadlines"]}
    assert stages == {"early_warning", "notification"}
    # The final report is deliberately absent: its clock has not started.
    assert r["not_yet_scheduled"]["stages"] == ["final"]
    assert "corrective measure" in r["not_yet_scheduled"]["why"]
    assert "24 hours" in r["urgent"]


def test_flipping_actively_exploited_later_starts_the_clock_from_that_moment(
    product, owner
):
    before = _now()
    vid = _call("record_vulnerability", product, owner, summary="parser overflow")[
        "vulnerability_id"
    ]
    assert _obligations(product) == []

    r = _call("update_vulnerability", product, owner, vulnerability_id=vid,
              actively_exploited=True)
    assert r["ok"] is True
    early = next(d for d in r["deadlines"] if d["stage"] == "early_warning")
    due = datetime.fromisoformat(early["due_at"])
    # Awareness is *now*, not the original discovery — the duty starts when you
    # learn of the exploitation.
    assert timedelta(hours=23, minutes=59) < due - before < timedelta(hours=24, minutes=1)
    assert 23 < early["hours_remaining"] <= 24


def test_the_cascade_does_not_fire_twice(product, owner):
    vid = _call(
        "record_vulnerability", product, owner, summary="dupe", actively_exploited=True
    )["vulnerability_id"]
    first = _obligations(product)
    assert len(first) == 2

    # Re-asserting a fact that is already true must not duplicate the incident
    # or reset the deadlines the user is working against.
    r = _call("update_vulnerability", product, owner, vulnerability_id=vid,
              actively_exploited=True)
    assert r["ok"] is True
    second = _obligations(product)
    assert [o.id for o in second] == [o.id for o in first]
    assert [o.due_at for o in second] == [o.due_at for o in first]

    with session_scope() as s:
        assert s.query(Incident).filter(Incident.product_id == product).count() == 1


def test_a_corrective_measure_date_schedules_the_final_report_without_disturbing_the_rest(
    product, owner
):
    vid = _call(
        "record_vulnerability", product, owner, summary="rce", actively_exploited=True
    )["vulnerability_id"]
    before = {o.stage: (o.id, o.due_at) for o in _obligations(product)}

    fix = datetime(2026, 10, 2, 16, 30, tzinfo=UTC)
    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=vid,
        corrective_measure_available_at=fix.isoformat(),
    )
    assert r["ok"] is True
    assert [o["stage"] for o in r["final_report_scheduled"]] == ["final"]

    after = {o.stage: (o.id, o.due_at) for o in _obligations(product)}
    assert set(after) == {"early_warning", "notification", "final"}
    # The two running clocks are untouched — same rows, same deadlines.
    assert after["early_warning"] == before["early_warning"]
    assert after["notification"] == before["notification"]
    assert after["final"][1] == fix + timedelta(days=14)


def test_a_corrective_measure_without_an_incident_is_refused(product, owner):
    vid = _call("record_vulnerability", product, owner, summary="not exploited")[
        "vulnerability_id"
    ]
    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=vid,
        corrective_measure_available_at=_now().isoformat(),
    )
    assert r["ok"] is False
    assert "actively exploited" in r["error"]


# ---- incidents ---------------------------------------------------------------


def test_a_severe_incident_gets_all_three_stages_up_front(product, owner):
    aware = _now() - timedelta(hours=2)
    r = _call(
        "report_incident",
        product,
        owner,
        kind="severe_incident",
        became_aware_at=aware.isoformat(),
        description="attacker pivoted through our update channel",
    )
    assert r["ok"] is True
    stages = [d["stage"] for d in r["deadlines"]]
    assert stages == ["early_warning", "notification", "final"]
    assert "not_yet_scheduled" not in r
    # Deadlines run from the stated awareness, not from row creation — the two
    # hours already elapsed are two hours off the clock.
    early = next(d for d in r["deadlines"] if d["stage"] == "early_warning")
    assert 21.5 < early["hours_remaining"] < 22.5


def test_backdated_awareness_can_already_be_overdue(product, owner):
    """Recording an incident late must show the truth, not a fresh 24 hours."""
    aware = _now() - timedelta(hours=30)
    r = _call("report_incident", product, owner, became_aware_at=aware.isoformat())
    early = next(d for d in r["deadlines"] if d["stage"] == "early_warning")
    assert early["state"] == "overdue"
    assert early["hours_remaining"] < 0


def test_future_awareness_is_refused(product, owner):
    r = _call(
        "report_incident",
        product,
        owner,
        became_aware_at=(_now() + timedelta(hours=1)).isoformat(),
    )
    assert r["ok"] is False
    assert "future" in r["error"]


def test_a_naive_timestamp_is_refused_with_an_actionable_message(product, owner):
    r = _call("report_incident", product, owner, became_aware_at="2026-09-14T09:00:00")
    assert r["ok"] is False
    assert "timezone offset" in r["error"]


def test_an_unknown_incident_kind_lists_the_valid_ones(product, owner):
    r = _call("report_incident", product, owner, kind="minor_oopsie")
    assert r["ok"] is False
    assert "severe_incident" in r["error"]


# ---- reading the clocks ------------------------------------------------------


def test_deadlines_across_every_product_the_user_owns(owner, product):
    """The session-agnostic call — "is anything due?" — spans products."""
    second = str(uuid.uuid4())
    now = _now()
    store_pg.save_state(
        ComplianceState(
            product_id=second,
            name="Acme Sensor",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    _call("report_incident", product, owner, became_aware_at=(now - timedelta(hours=30)).isoformat())
    _call("report_incident", second, owner, became_aware_at=now.isoformat())

    r = _call("get_reporting_deadlines", "", owner)
    assert r["ok"] is True
    assert r["counts"]["open"] == 6
    # Only the 24h stage of the backdated incident has blown; its 72h
    # notification still has 42 hours on it.
    assert r["counts"]["overdue"] == 1
    assert r["deadlines"][0]["stage"] == "early_warning"
    assert r["deadlines"][0]["state"] == "overdue"
    assert "1 overdue" in r["attention"]
    # Soonest first, so the thing on fire is at the top.
    dues = [d["due_at"] for d in r["deadlines"]]
    assert dues == sorted(dues)
    assert {d["product_name"] for d in r["deadlines"]} == {"Acme Gateway", "Acme Sensor"}


def test_deadlines_of_another_users_product_are_invisible(product, owner):
    _call("report_incident", product, owner, description="ours")
    stranger = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=stranger, email=f"{stranger}@example.test"))

    assert _call("get_reporting_deadlines", "", stranger)["counts"]["open"] == 0
    scoped = _call("get_reporting_deadlines", product, stranger)
    assert scoped["ok"] is False
    assert scoped["code"] == "not_found"


# ---- recording a submission --------------------------------------------------


def test_recording_a_submission_closes_the_obligation(product, owner):
    _call("report_incident", product, owner)
    ob = _obligations(product)[0]

    r = _call(
        "record_report_submission",
        product,
        owner,
        obligation_id=ob.id,
        submission_ref="SRP-2026-000123",
    )
    assert r["ok"] is True
    assert r["state"] == "submitted"
    assert r["late_by_hours"] is None

    # Gone from the open list; still there if you ask for everything.
    assert _call("get_reporting_deadlines", product, owner)["counts"]["open"] == 2
    assert (
        _call("get_reporting_deadlines", product, owner, include_submitted=True)[
            "counts"
        ]["open"]
        == 3
    )


def test_a_late_submission_is_recorded_as_late_not_quietly_accepted(product, owner):
    _call(
        "report_incident",
        product,
        owner,
        became_aware_at=(_now() - timedelta(hours=40)).isoformat(),
    )
    ob = next(o for o in _obligations(product) if o.stage == "early_warning")

    r = _call("record_report_submission", product, owner, obligation_id=ob.id)
    assert r["state"] == "submitted_late"
    assert r["late_by_hours"] > 15


def test_double_submission_is_refused(product, owner):
    _call("report_incident", product, owner)
    ob = _obligations(product)[0]
    assert _call("record_report_submission", product, owner, obligation_id=ob.id)["ok"]

    again = _call("record_report_submission", product, owner, obligation_id=ob.id)
    assert again["ok"] is False
    assert "already recorded" in again["error"]


# ---- the audit trail ---------------------------------------------------------


def test_every_mutation_leaves_an_attributed_audit_row(product, owner):
    vid = _call(
        "record_vulnerability", product, owner, summary="rce", actively_exploited=True
    )["vulnerability_id"]
    _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=vid,
        corrective_measure_available_at=_now().isoformat(),
    )
    ob = next(o for o in _obligations(product) if o.stage == "final")
    _call("record_report_submission", product, owner, obligation_id=ob.id)

    ops = _audit_ops(product)
    assert ops == [
        "record_vulnerability",
        "open_incident",
        "update_vulnerability",
        "set_corrective_measure",
        "record_report_submission",
    ]

    with session_scope() as s:
        rows = s.query(AuditEvent).filter(AuditEvent.product_id == product).all()
    # Both halves of attribution: who is answerable, and what performed it.
    assert all(e.accountable_user_id == owner for e in rows)
    assert all(e.actor_kind == "agent" for e in rows)


def test_a_non_member_cannot_write_and_leaves_no_trace(product):
    stranger = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=stranger, email=f"{stranger}@example.test"))

    r = _call("record_vulnerability", product, stranger, summary="not mine")
    assert r["ok"] is False
    assert r["code"] == "not_found"
    assert _audit_ops(product) == []


def test_open_but_not_urgent_never_reads_as_nothing_due(product, owner):
    """The most dangerous sentence this tool could emit.

    Two clocks running, neither inside its warning window. "Nothing due" would
    be true of the urgency check and false of the situation.
    """
    _call("report_incident", product, owner)
    r = _call("get_reporting_deadlines", product, owner)

    assert r["counts"] == {"open": 3, "overdue": 0, "due_soon": 0}
    assert "Nothing due" not in r["attention"]
    assert "3 open" in r["attention"]
    assert "early warning" in r["attention"]


def test_nothing_open_says_so_plainly(product, owner):
    r = _call("get_reporting_deadlines", product, owner)
    assert r["counts"]["open"] == 0
    assert r["attention"] == "Nothing open."
