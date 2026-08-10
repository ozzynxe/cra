"""Where the Article 14 clocks are anchored.

Awareness is the trigger in Article 14 — "within 24 hours of becoming aware" —
so the anchor is the most consequential timestamp in the system. It used to be
unreachable on the exploited-vulnerability path: `record_vulnerability` had no
`became_aware_at`, the cascade anchored on the moment of the call, and
`discovered_at` was stored but never fed a clock.

The consequence was the wrong way round. A team that learned of exploitation on
Friday and recorded it on Monday got a 24-hour clock starting Monday, and the
tool reported them comfortably on time while they were roughly two days late.
`deadlines.py` is careful never to invent a deadline that has not started; this
was the same error inverted — inventing one later than the law allows.
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
from cra.db import AuditEvent, Incident, ReportingObligation, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc


def _user() -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


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


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _stage(result, stage):
    return next(d for d in result["deadlines"] if d["stage"] == stage)


# ---- recording with a past awareness date ------------------------------------


def test_a_past_awareness_date_anchors_the_clocks(product, owner):
    """The fix. Friday's awareness, Monday's recording."""
    aware = datetime.now(UTC) - timedelta(hours=30)
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE in the request router",
        actively_exploited=True,
        became_aware_at=_iso(aware),
    )
    assert r["ok"] is True
    early = _stage(r, "early_warning")
    # 24h from awareness, which was 30h ago — the deadline is behind us.
    assert early["hours_remaining"] < 0
    assert early["state"] == "overdue"
    assert datetime.fromisoformat(early["due_at"]) == aware + timedelta(hours=24)


def test_being_already_late_is_said_out_loud(product, owner):
    """A negative `hours_remaining` buried in a list is not telling someone
    they have missed a statutory deadline."""
    aware = datetime.now(UTC) - timedelta(hours=30)
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE in the request router",
        actively_exploited=True,
        became_aware_at=_iso(aware),
    )
    assert r["already_overdue"] == ["early_warning"]
    assert "ALREADY OVERDUE" in r["backdated"]
    assert "File immediately" in r["backdated"]


def test_a_backdated_anchor_that_is_not_yet_late_still_says_so(product, owner):
    aware = datetime.now(UTC) - timedelta(hours=3)
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="Auth bypass",
        actively_exploited=True,
        became_aware_at=_iso(aware),
    )
    assert "already_overdue" not in r
    assert "Nothing is overdue yet" in r["backdated"]
    assert _stage(r, "early_warning")["hours_remaining"] == pytest.approx(21, abs=0.2)


def test_the_incident_row_carries_the_real_awareness_time(product, owner):
    aware = datetime.now(UTC) - timedelta(hours=30)
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE",
        actively_exploited=True,
        became_aware_at=_iso(aware),
    )
    with session_scope() as s:
        incident = s.get(Incident, r["incident_id"])
    assert incident.became_aware_at == aware


def test_a_future_awareness_date_is_refused(product, owner):
    """It would push a statutory deadline out."""
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE",
        actively_exploited=True,
        became_aware_at=_iso(datetime.now(UTC) + timedelta(hours=2)),
    )
    assert r["ok"] is False and "in the future" in r["error"]


def test_a_naive_awareness_date_is_refused(product, owner):
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE",
        actively_exploited=True,
        became_aware_at="2026-09-01T14:00:00",
    )
    assert r["ok"] is False and "timezone" in r["error"]


def test_omitting_it_still_works_but_says_what_it_assumed(product, owner):
    """The default is unchanged; what changed is that it stops being silent."""
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE",
        actively_exploited=True,
    )
    assert r["ok"] is True
    assert _stage(r, "early_warning")["hours_remaining"] == pytest.approx(24, abs=0.1)
    assert "anchored at the moment you recorded this" in r["anchor_assumed"]
    assert "update_vulnerability" in r["anchor_assumed"]


def test_discovery_is_not_awareness(product, owner):
    """Knowing a flaw exists and knowing it is being exploited are different
    moments. Only the second starts a clock."""
    discovered = datetime.now(UTC) - timedelta(days=20)
    r = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE",
        discovered_at=_iso(discovered),
        actively_exploited=True,
    )
    # Anchored at now, not 20 days ago.
    assert _stage(r, "early_warning")["hours_remaining"] == pytest.approx(24, abs=0.1)


def test_a_late_flip_can_be_anchored_in_the_past_too(product, owner):
    """The other route in: recorded as ordinary, later found to be exploited."""
    v = _call("record_vulnerability", product, owner, summary="Auth bypass")
    aware = datetime.now(UTC) - timedelta(hours=26)
    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        actively_exploited=True,
        became_aware_at=_iso(aware),
    )
    assert r["ok"] is True
    assert _stage(r, "early_warning")["state"] == "overdue"


# ---- correcting an anchor after the fact --------------------------------------


def _exploited_now(product, owner):
    return _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE in the request router",
        actively_exploited=True,
    )


def test_an_anchor_set_by_default_can_be_corrected(product, owner):
    """Without this the default is not a default, it is a trap."""
    v = _exploited_now(product, owner)
    aware = datetime.now(UTC) - timedelta(hours=30)

    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(aware),
        awareness_rationale="The WAF log shows the first successful exploit at "
        "02:14 on the 4th; we saw it the same morning.",
    )
    assert r["ok"] is True
    moved = {m["stage"] for m in r["awareness_reanchored"]["deadlines_moved"]}
    assert moved == {"early_warning", "notification"}
    assert r["already_overdue"] == ["early_warning"]

    with session_scope() as s:
        rows = (
            s.query(ReportingObligation)
            .filter(ReportingObligation.incident_id == v["incident_id"])
            .all()
        )
        due = {o.stage: o.due_at for o in rows}
    assert due["early_warning"] == aware + timedelta(hours=24)


def test_moving_an_anchor_demands_a_reason(product, owner):
    v = _exploited_now(product, owner)
    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(datetime.now(UTC) - timedelta(hours=30)),
    )
    assert r["ok"] is False
    assert "awareness_rationale is required" in r["error"]


def test_the_correction_is_auditable_with_both_dates(product, owner):
    v = _exploited_now(product, owner)
    aware = datetime.now(UTC) - timedelta(hours=30)
    _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(aware),
        awareness_rationale="WAF log evidence.",
    )
    with session_scope() as s:
        row = (
            s.query(AuditEvent)
            .filter(
                AuditEvent.product_id == product,
                AuditEvent.op == "reanchor_awareness",
            )
            .one()
        )
    assert row.actor_kind == "human"
    assert row.accountable_user_id == owner
    assert row.payload["now"] == aware.isoformat()
    assert row.payload["was"] != row.payload["now"]
    assert row.rationale.startswith("WAF log evidence")


def test_an_unchanged_anchor_is_a_no_op_needing_no_reason(product, owner):
    v = _exploited_now(product, owner)
    with session_scope() as s:
        aware = s.get(Incident, v["incident_id"]).became_aware_at

    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(aware),
    )
    assert r["ok"] is True
    assert r["awareness_unchanged"] == aware.isoformat()


def test_a_submitted_obligation_keeps_its_original_deadline(product, owner):
    """Whether a filed report was late is a matter of record. Recomputing its
    due date would retroactively change the answer."""
    v = _exploited_now(product, owner)
    early = _stage(v, "early_warning")
    _call(
        "record_report_submission",
        product,
        owner,
        obligation_id=early["obligation_id"],
        submission_ref="SRP-123",
    )

    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(datetime.now(UTC) - timedelta(hours=30)),
        awareness_rationale="Log review moved the date back.",
    )
    assert r["ok"] is True
    frozen = r["awareness_reanchored"]["left_alone_because_submitted"]
    assert [f["stage"] for f in frozen] == ["early_warning"]
    assert "matter of record" in r["submitted_note"]

    with session_scope() as s:
        row = (
            s.query(ReportingObligation)
            .filter(
                ReportingObligation.incident_id == v["incident_id"],
                ReportingObligation.stage == "early_warning",
            )
            .one()
        )
    assert row.due_at == datetime.fromisoformat(early["due_at"])


def test_re_anchoring_a_vulnerability_with_no_incident_is_refused(product, owner):
    v = _call("record_vulnerability", product, owner, summary="Ordinary bug")
    r = _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(datetime.now(UTC) - timedelta(hours=5)),
        awareness_rationale="n/a",
    )
    assert r["ok"] is False and "no clock to re-anchor" in r["error"]


def test_the_final_report_still_waits_for_its_own_anchor(product, owner):
    """Re-anchoring awareness must not conjure a final-report deadline: its 14
    days run from a corrective measure, which may not exist yet."""
    v = _exploited_now(product, owner)
    _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=_iso(datetime.now(UTC) - timedelta(hours=30)),
        awareness_rationale="Log review.",
    )
    with session_scope() as s:
        stages = {
            o.stage
            for o in s.query(ReportingObligation)
            .filter(ReportingObligation.incident_id == v["incident_id"])
            .all()
        }
    assert stages == {"early_warning", "notification"}


def test_an_assumed_anchor_does_not_also_claim_to_be_awareness(product, owner):
    """Two fields in one response cannot both be right, and the wrong one was
    the comforting one.

    Omitting `became_aware_at` anchors the clocks at the moment of recording.
    `anchor_assumed` says so. But `backdated` was emitted unconditionally, and
    because the anchor defaults to now while `now` is recomputed microseconds
    later downstream, it fired with "Clocks anchored 0.0h ago, at the time you
    became aware — not at the time you recorded it. Nothing is overdue yet."

    It appeared first. In this product the reassuring direction is the one that
    costs: the whole risk being managed is a team believing a statutory deadline
    is further away than it legally is.
    """
    out = _call(
        "record_vulnerability", product, owner,
        summary="Request-smuggling flaw a customer reports being exploited.",
        actively_exploited=True,
    )
    assert out["ok"] is True
    assert "anchor_assumed" in out
    assert "backdated" not in out


def test_a_real_backdate_still_says_so(product, owner):
    """The note earns its place only if it still fires when an anchor genuinely
    is in the past — which is the case it was written for."""
    aware = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    out = _call(
        "record_vulnerability", product, owner,
        summary="Request-smuggling flaw reported by a customer three days ago.",
        actively_exploited=True,
        became_aware_at=aware,
    )
    assert "backdated" in out
    assert "anchor_assumed" not in out
    assert "ALREADY OVERDUE" in out["backdated"]
