"""The deadline sweeper against a real database, with SES stubbed.

What is worth testing here is not that email works — it is the four places
this deliberately behaves unlike the Coauthor sweeper it was forked from:
it queries obligations rather than walking users, it never coalesces, it is
on by default, and a misconfiguration is recorded rather than swallowed.
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
from sqlalchemy import text  # noqa: E402

from cra.db import NotificationLog, ProductMember, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import deadline_sweeper, store_pg  # noqa: E402

UTC = timezone.utc


@pytest.fixture(autouse=True)
def alerting_configured(monkeypatch):
    monkeypatch.setenv("CRA_DEADLINE_ALERTS_ENABLED", "1")
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")


@pytest.fixture(autouse=True)
def isolated_clocks():
    """Clear every open obligation and support period before each test.

    The sweeper is deliberately global — it asks "what is due anywhere", not
    "what is due for this product" — so obligations left behind by another
    test are indistinguishable from real work and make counts nondeterministic.
    Scoping the assertions instead would test a narrower sweeper than the one
    that ships.

    Support periods are cleared for the same reason and were added when the
    Article 13(19) pass landed: this module is about the Article 14 ladder, and
    a product left with an end date by another test puts end-of-support mail in
    an outbox these tests read as theirs. The two passes are counted separately
    in the result, but they share `_send`.
    """
    with session_scope() as s:
        for table in (
            "notification_log",
            "reporting_obligations",
            "incidents",
            "vulnerabilities",
        ):
            s.execute(text(f"DELETE FROM {table}"))
        s.execute(text("UPDATE products SET support_period_end = NULL"))
    yield


@pytest.fixture
def outbox(monkeypatch):
    sent: list[dict] = []

    def _fake_send(*, to_email, subject, plain, html):
        sent.append({"to": to_email, "subject": subject, "plain": plain})
        return f"ses-{len(sent)}"

    monkeypatch.setattr(deadline_sweeper, "_send", _fake_send)
    return sent


def _user(email: str | None = None) -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=email or f"{uid}@example.test"))
    return uid


@pytest.fixture
def owner():
    return _user()


@pytest.fixture
def product(owner):
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
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


def _incident(product, owner, *, aware_hours_ago: float):
    aware = datetime.now(UTC) - timedelta(hours=aware_hours_ago)
    return dispatcher.dispatch(
        "report_incident",
        product,
        owner,
        {"became_aware_at": aware.isoformat(), "description": "Update channel breach"},
    )["incident_id"]


def _logs(product_id):
    with session_scope() as s:
        return list(
            s.query(NotificationLog)
            .filter(NotificationLog.product_id == product_id)
            .order_by(NotificationLog.created_at)
        )


# ---- the four inversions -----------------------------------------------------


def test_alerting_is_on_by_default(monkeypatch):
    """Coauthor's switch shipped dark. A deploy that silently stops chasing
    deadlines is the failure this exists to prevent."""
    monkeypatch.delenv("CRA_DEADLINE_ALERTS_ENABLED", raising=False)
    assert deadline_sweeper.is_enabled() is True
    monkeypatch.setenv("CRA_DEADLINE_ALERTS_ENABLED", "0")
    assert deadline_sweeper.is_enabled() is False


def test_the_kill_switch_stops_the_sweep_entirely(product, owner, outbox, monkeypatch):
    _incident(product, owner, aware_hours_ago=13)
    monkeypatch.setenv("CRA_DEADLINE_ALERTS_ENABLED", "off")
    result = deadline_sweeper.sweep_once()
    assert result == {"enabled": False, "sent": 0, "suppressed": 0, "considered": 0}
    assert outbox == []


def test_it_finds_work_from_the_obligation_table_not_a_user_cursor(
    product, owner, outbox
):
    """No cursor to initialise: an obligation created a moment ago is swept on
    the very next pass, which is the only acceptable behaviour on a 24h clock."""
    _incident(product, owner, aware_hours_ago=13)  # 11h left on the early warning
    result = deadline_sweeper.sweep_once()
    assert result["sent"] == 1
    assert "11h left" in outbox[0]["subject"]
    assert "early warning" in outbox[0]["subject"]


def test_nothing_is_coalesced(product, owner, outbox):
    """Two products, two obligations, two separate mails — no digest window.
    Batching a one-hour-to-deadline alert is what this fork removed."""
    second = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=second,
            name="Acme Sensor",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    _incident(product, owner, aware_hours_ago=13)
    _incident(second, owner, aware_hours_ago=13)

    deadline_sweeper.sweep_once()
    subjects = {m["subject"] for m in outbox}
    assert len(subjects) == 2
    assert any("Acme Gateway" in s for s in subjects)
    assert any("Acme Sensor" in s for s in subjects)


def test_a_missing_sender_is_recorded_not_swallowed(
    product, owner, monkeypatch
):
    """An operator asking "why did nobody get told" should get the answer from
    the database, not from log archaeology."""
    monkeypatch.delenv("CRA_ALERTS_FROM", raising=False)
    _incident(product, owner, aware_hours_ago=13)

    result = deadline_sweeper.sweep_once()
    assert result["suppressed"] == 1 and result["sent"] == 0

    row = _logs(product)[0]
    assert row.status == "suppressed"
    assert "CRA_ALERTS_FROM is not set" in row.error_text
    assert "CRA_DEADLINE_ALERTS_ENABLED=0" in row.error_text


def test_a_suppression_is_recorded_once_not_every_sweep(product, owner, monkeypatch):
    """A misconfigured deploy must not write a row per obligation per sweep.

    At a five-minute interval that is 288 rows a day per open obligation, and
    it grows fastest exactly when nobody is watching. Suppression needs an
    operator, so it settles the rung rather than retrying.
    """
    monkeypatch.delenv("CRA_ALERTS_FROM", raising=False)
    _incident(product, owner, aware_hours_ago=13)

    assert deadline_sweeper.sweep_once()["suppressed"] == 1
    for _ in range(3):
        assert deadline_sweeper.sweep_once()["suppressed"] == 0
    assert len(_logs(product)) == 1


def test_fixing_the_config_does_not_resend_a_settled_rung(product, owner, monkeypatch):
    """The flip side, and the accepted cost: a rung suppressed while
    misconfigured is not retried once the sender is set. The next rung down
    still fires, so the deadline is not lost — but an operator should treat
    suppression rows as an incident, not a queue that drains itself.

    Deliberately does not use the `outbox` fixture: it stubs `_send`, which is
    the very function that detects the missing sender.
    """
    monkeypatch.delenv("CRA_ALERTS_FROM", raising=False)
    _incident(product, owner, aware_hours_ago=13)
    assert deadline_sweeper.sweep_once()["suppressed"] == 1

    sent: list[str] = []
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")
    monkeypatch.setattr(
        deadline_sweeper,
        "_send",
        lambda *, to_email, subject, plain, html: sent.append(subject) or "ses-1",
    )

    assert deadline_sweeper.sweep_once()["sent"] == 0
    assert sent == []

    # ...but the T-6h rung, reached later, is delivered normally.
    later = datetime.now(UTC) + timedelta(hours=6)
    assert deadline_sweeper.sweep_once(now=later)["sent"] == 1
    assert sent == ["5h left: CRA early warning for Acme Gateway"]


# ---- escalation over time ----------------------------------------------------


def test_a_rung_is_not_repeated_across_sweeps(product, owner, outbox):
    _incident(product, owner, aware_hours_ago=13)
    assert deadline_sweeper.sweep_once()["sent"] == 1
    assert deadline_sweeper.sweep_once()["sent"] == 0
    assert deadline_sweeper.sweep_once()["sent"] == 0
    assert len(outbox) == 1


def test_the_next_rung_fires_as_the_deadline_approaches(product, owner, outbox):
    _incident(product, owner, aware_hours_ago=13)
    deadline_sweeper.sweep_once()                     # T-12h
    later = datetime.now(UTC) + timedelta(hours=6)
    deadline_sweeper.sweep_once(now=later)            # T-6h → now ~5h left
    much_later = datetime.now(UTC) + timedelta(hours=10)
    deadline_sweeper.sweep_once(now=much_later)       # T-2h

    kinds = [row.kind for row in _logs(product) if row.kind]
    assert kinds == ["T-12h", "T-6h", "T-2h"]
    assert len(outbox) == 3


def test_an_overdue_obligation_is_chased_exactly_once(product, owner, outbox):
    """Hourly mail about a missed deadline gets the sender filtered, taking
    the *next* deadline's alerts down with it."""
    _incident(product, owner, aware_hours_ago=26)  # early warning already blown

    def _early_overdue():
        return [
            m
            for m in outbox
            if m["subject"] == "OVERDUE: CRA early warning for Acme Gateway"
        ]

    deadline_sweeper.sweep_once()
    assert len(_early_overdue()) == 1
    assert "was due at" in _early_overdue()[0]["plain"]

    deadline_sweeper.sweep_once()
    deadline_sweeper.sweep_once(now=datetime.now(UTC) + timedelta(days=5))
    assert len(_early_overdue()) == 1


def test_each_stage_is_chased_on_its_own_clock(product, owner, outbox):
    """The 72-hour notification going overdue is a separate obligation and
    earns its own alert — silence there would be the worse bug."""
    _incident(product, owner, aware_hours_ago=26)
    deadline_sweeper.sweep_once()
    deadline_sweeper.sweep_once(now=datetime.now(UTC) + timedelta(days=5))

    overdue = {m["subject"] for m in outbox if m["subject"].startswith("OVERDUE")}
    assert overdue == {
        "OVERDUE: CRA early warning for Acme Gateway",
        "OVERDUE: CRA full notification for Acme Gateway",
    }


def test_a_submitted_obligation_stops_being_chased(product, owner, outbox):
    incident = _incident(product, owner, aware_hours_ago=13)
    with session_scope() as s:
        from cra.db import ReportingObligation

        ob = (
            s.query(ReportingObligation)
            .filter(
                ReportingObligation.incident_id == incident,
                ReportingObligation.stage == "early_warning",
            )
            .one()
        )
        ob_id = ob.id
    dispatcher.dispatch(
        "record_report_submission", product, owner, {"obligation_id": ob_id}
    )
    assert deadline_sweeper.sweep_once()["sent"] == 0
    assert outbox == []


def test_a_waived_obligation_is_not_chased(product, owner, outbox):
    incident = _incident(product, owner, aware_hours_ago=13)
    with session_scope() as s:
        from cra.db import ReportingObligation

        for ob in s.query(ReportingObligation).filter(
            ReportingObligation.incident_id == incident
        ):
            ob.waived_reason = "out of scope: open-source steward"
    assert deadline_sweeper.sweep_once()["sent"] == 0


def test_a_stage_whose_ladder_has_not_been_reached_stays_quiet(product, owner, outbox):
    """Both stages are inside the lookahead, but only the early warning has
    crossed a rung. Alerting on the 72-hour notification while the 24-hour
    clock is the live problem would bury the thing that matters."""
    _incident(product, owner, aware_hours_ago=13)
    deadline_sweeper.sweep_once()
    assert {m["subject"].split(":")[0] for m in outbox} == {"11h left"}
    stages = {row.obligation_id for row in _logs(product)}
    assert len(stages) == 1


# ---- fan-out and delivery ----------------------------------------------------


def test_every_member_is_told_not_just_the_owner(product, owner, outbox):
    """A deadline is the team's problem, and the person holding the billing
    relationship is frequently not the one who can file the report."""
    teammate = _user()
    state = store_pg.load_state(product)
    state.members[teammate] = MemberInfo(
        role=Role.MAINTAINER, user_id=teammate, joined_at=datetime.now(UTC)
    )
    store_pg.save_state(state)
    with session_scope() as s:
        assert (
            s.query(ProductMember).filter(ProductMember.product_id == product).count()
            == 2
        )

    _incident(product, owner, aware_hours_ago=13)
    deadline_sweeper.sweep_once()
    assert {m["to"] for m in outbox} == {_email(teammate), _email(owner)}


def _email(uid: str) -> str:
    with session_scope() as s:
        return s.get(User, uid).email


def test_a_user_who_opted_out_is_skipped(product, owner, outbox):
    with session_scope() as s:
        s.get(User, owner).notifications_enabled = False
    _incident(product, owner, aware_hours_ago=13)
    assert deadline_sweeper.sweep_once()["sent"] == 0
    assert outbox == []


def test_one_failing_send_does_not_stop_the_rest(product, owner, monkeypatch):
    teammate = _user()
    state = store_pg.load_state(product)
    state.members[teammate] = MemberInfo(
        role=Role.MAINTAINER, user_id=teammate, joined_at=datetime.now(UTC)
    )
    store_pg.save_state(state)
    _incident(product, owner, aware_hours_ago=13)

    doomed = _email(teammate)

    def _flaky(*, to_email, subject, plain, html):
        if to_email == doomed:
            raise RuntimeError("SES said no")
        return "ses-ok"

    monkeypatch.setattr(deadline_sweeper, "_send", _flaky)
    result = deadline_sweeper.sweep_once()

    assert result["sent"] == 1
    statuses = {row.status for row in _logs(product)}
    assert statuses == {"sent", "failed"}
    failed = next(r for r in _logs(product) if r.status == "failed")
    assert "SES said no" in failed.error_text


def test_a_failed_send_is_retried_on_the_next_sweep(product, owner, monkeypatch):
    """At-least-once on purpose: a duplicate alert is a far better outcome
    than a missed statutory deadline."""
    _incident(product, owner, aware_hours_ago=13)
    monkeypatch.setattr(
        deadline_sweeper,
        "_send",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("transient")),
    )
    assert deadline_sweeper.sweep_once()["sent"] == 0

    monkeypatch.setattr(deadline_sweeper, "_send", lambda **kw: "ses-ok")
    assert deadline_sweeper.sweep_once()["sent"] == 1
    assert {r.status for r in _logs(product)} == {"failed", "sent"}


# ---- dry run -----------------------------------------------------------------


def test_dry_run_reports_what_would_go_out_and_sends_nothing(product, owner, outbox):
    _incident(product, owner, aware_hours_ago=13)
    result = deadline_sweeper.sweep_once(dry_run=True)

    assert outbox == []
    assert _logs(product) == []
    assert result["considered"] == 1
    plan = result["planned"][0]
    assert plan["rung"] == "T-12h"
    assert plan["product"] == "Acme Gateway"
    assert 10 < plan["hours_remaining"] < 12
    # And a dry run must not mark anything as notified, or the real sweep
    # afterwards would stay silent.
    assert deadline_sweeper.sweep_once()["sent"] == 1
