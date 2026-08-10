"""`set_support_period` end to end, and the alerts that follow it.

Issues #2 and #3. Together they are the difference between a user being able to
finish an Annex VII technical file and not: `tf.4` previously had no
first-class way to be filled at all, so the only route was attaching a document
by hand — the "we tracked it in a spreadsheet" failure the product exists to
replace.

Two things are asserted throughout. The **reasoning** is half of 13(8), so a
date alone must not complete the slot. And the **five-year floor** has exactly
one exception, which has to be claimed rather than arrived at.
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
from cra.db import AuditEvent, NotificationLog, Product, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import deadline_sweeper as sweeper  # noqa: E402
from cra.server import mailer, store_pg  # noqa: E402

UTC = timezone.utc
NOW = datetime.now(UTC)


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test", notifications_enabled=True))
    return uid


@pytest.fixture
def product(owner, make_releasable):
    pid = str(uuid.uuid4())
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Acme Gateway",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=NOW)},
            created_at=NOW,
            updated_at=NOW,
        )
    )
    _call(
        "classify_product",
        pid,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Ordinary product with digital elements.",
    )
    make_releasable(_call, pid, owner)
    return pid


def _set(product, owner, *, start="2026-01-01T00:00:00Z", end, **kw):
    args = {
        "start": start,
        "end": end,
        "rationale": "Comparable gateways are supported five years; our platform to 2031.",
    }
    args.update(kw)
    return _call("set_support_period", product, owner, **args)


def _tf4(product, owner):
    tf = _call("assemble_technical_file", product, owner)
    return next(s for s in tf["slots"] if s["slot"] == "tf.4")


# ---- the floor and its one exception ---------------------------------------------


def test_a_five_year_period_is_accepted(product, owner):
    out = _set(product, owner, end="2031-01-01T00:00:00Z")
    assert out["ok"] is True
    assert out["years"] >= 5.0


def test_four_years_is_refused_with_the_regulation_s_own_exception(product, owner):
    """Not a bare validation message. The user is one sentence away from a
    lawful shorter period, and the error is where that sentence belongs."""
    out = _set(product, owner, end="2030-01-01T00:00:00Z")
    assert out["ok"] is False
    assert "at least five" in out["error"]
    assert "expected_use_years" in out["error"]
    assert "expected to be in use for less than five years" in out["error"]


def test_a_short_period_is_allowed_when_the_expected_use_is_short(product, owner):
    out = _set(
        product, owner, end="2029-01-01T00:00:00Z", expected_use_years=3,
    )
    assert out["ok"] is True
    assert "expected to be in use for 3" in out["short_period_basis"]


def test_the_exception_cannot_be_claimed_with_a_number_over_five(product, owner):
    out = _set(product, owner, end="2030-01-01T00:00:00Z", expected_use_years=7)
    assert out["ok"] is False
    assert "does not apply" in out["error"]


def test_a_long_period_is_not_described_as_claiming_the_exception(product, owner):
    """Issue #41. `expected_use_years` on a period that clears the floor is
    legitimate context, and the note used to be gated on the argument being
    present rather than on the floor test — so a seven-year period came back
    saying "Under five years, on the stated basis that the product is expected
    to be in use for 7". Internally impossible, and it asserts that a statutory
    exception was invoked when it was not.

    The dates were right and the legal characterisation was wrong, which is the
    harder half to notice: an agent relaying the response repeats the sentence,
    and the sentence is the thing an auditor tests.
    """
    out = _set(product, owner, end="2033-01-01T00:00:00Z", expected_use_years=7)
    assert out["ok"] is True
    assert out["years"] >= 5.0
    assert "short_period_basis" not in out
    # And it does not simply go quiet, which would leave a caller who passed the
    # argument unable to tell whether the exception had been taken.
    assert "not being relied on" in out["expected_use_recorded"]
    assert "7" in out["expected_use_recorded"]


def test_the_exception_note_still_appears_when_it_is_actually_used(product, owner):
    """The other side of #41 — the fix must not silence the real case."""
    out = _set(product, owner, end="2029-01-01T00:00:00Z", expected_use_years=3)
    assert out["ok"] is True
    assert "Under five years" in out["short_period_basis"]
    assert "expected_use_recorded" not in out


def test_supporting_for_less_than_the_expected_use_is_refused(product, owner):
    """The direction the exception does not cover: 13(8) says the period
    *corresponds to* the expected use time, so a two-year period on a product
    expected to run for four is the gap the exception exists to close, not a
    use of it."""
    out = _set(product, owner, end="2028-01-01T00:00:00Z", expected_use_years=4)
    assert out["ok"] is False
    assert "corresponds to" in out["error"]


def test_the_reasoning_is_required(product, owner):
    out = _call(
        "set_support_period",
        product,
        owner,
        start="2026-01-01T00:00:00Z",
        end="2031-01-01T00:00:00Z",
        rationale="   ",
    )
    assert out["ok"] is False
    assert "Annex VII(4)" in out["error"]


def test_an_end_before_the_start_is_refused(product, owner):
    out = _set(product, owner, start="2026-01-01T00:00:00Z", end="2025-01-01T00:00:00Z")
    assert out["ok"] is False
    assert "before or when it starts" in out["error"]


# ---- Annex VII(4) fills from the record --------------------------------------------


def test_tf4_completes_without_a_manual_attachment(product, owner):
    """#2's 'Done when'. Before this, the only way to fill this slot was to
    attach a document."""
    assert _tf4(product, owner)["complete"] is False

    _set(product, owner, end="2031-01-01T00:00:00Z")

    slot = _tf4(product, owner)
    assert slot["complete"] is True
    assert slot["evidence_ids"] == [], "completed from the record, not an attachment"
    assert slot["support_period"]["years"] >= 5.0


def test_the_slot_names_what_is_missing_before_it_is_set(product, owner):
    slot = _tf4(product, owner)
    assert "no support period recorded" in slot["missing"]
    assert "set_support_period" in slot["missing"]


def test_the_reasoning_reaches_the_frozen_file(product, owner):
    """13(8) puts the *information taken into account* in the documentation, so
    it has to survive into the artefact rather than living only in an audit
    row."""
    _set(product, owner, end="2031-01-01T00:00:00Z")
    slot = _tf4(product, owner)
    assert slot["support_period"]["end"].startswith("2031-01-01")
    assert slot["support_period"]["determined_at"]


def test_the_determination_is_audited_with_its_reasoning(product, owner):
    _set(product, owner, end="2031-01-01T00:00:00Z")
    with session_scope() as s:
        ev = (
            s.query(AuditEvent)
            .filter(
                AuditEvent.product_id == product,
                AuditEvent.op == "set_support_period",
            )
            .one()
        )
        assert ev.payload["years"] >= 5.0
        assert "Comparable gateways" in ev.rationale


# ---- the start comes from the release, when there is one ------------------------------


def test_the_start_defaults_to_the_first_release(product, owner, monkeypatch):
    """13(8) runs the period from placing on the market, which the tool now
    knows rather than having to ask."""
    from cra.advisories.feeds import KevCatalogue, OsvResult
    from cra.server import advisories

    monkeypatch.setattr(
        advisories,
        "osv_query",
        lambda comps: OsvResult(ok=True, queried=len(list(comps))),
    )
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: KevCatalogue(ok=True))
    monkeypatch.setattr(advisories, "osv_advisory", lambda i: {})
    monkeypatch.setattr(
        advisories,
        "epss_catalogue",
        lambda **kw: type("C", (), {"ok": False, "model_version": None, "score_date": None})(),
    )
    monkeypatch.setattr(advisories, "epss_scores", lambda ids: {})
    _call(
        "record_sbom",
        product,
        owner,
        sbom=(
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":'
            '[{"name":"lodash","purl":"pkg:npm/lodash@4.17.20"}]}'
        ),
        source_ref="git:a1",
    )
    assert _call("scan_advisories", product, owner)["scanned"] is True
    assert _call(
        "record_release",
        product,
        owner,
        version="1.0.0",
        released_at="2026-03-01T00:00:00Z",
    )["ok"] is True

    out = _call(
        "set_support_period",
        product,
        owner,
        end="2032-01-01T00:00:00Z",
        rationale="Six years from first shipment.",
    )
    assert out["ok"] is True
    assert out["start"].startswith("2026-03-01")
    assert out["start_inferred_from_release"] == "1.0.0"


def test_without_a_release_or_a_start_it_says_which_to_supply(product, owner):
    out = _call(
        "set_support_period",
        product,
        owner,
        end="2031-01-01T00:00:00Z",
        rationale="Five years.",
    )
    assert out["ok"] is False
    assert "record_release() first, or pass start=" in out["error"]


# ---- status surfaces it unasked ------------------------------------------------------


def test_status_says_when_nothing_is_recorded(product, owner):
    view = _call("get_compliance_status", product, owner)["support_period"]
    assert view["state"] == "not_recorded"
    assert "at least five years" in view["why_it_matters"]


def test_status_distinguishes_inside_from_ended(product, owner):
    """#3's 'Done when': a product past its support period is visibly
    distinguishable from one still inside it."""
    _set(product, owner, end="2031-01-01T00:00:00Z")
    assert _call("get_compliance_status", product, owner)["support_period"]["state"] == "active"

    past = (NOW - timedelta(days=30)).isoformat()
    _set(product, owner, start="2020-01-01T00:00:00Z", end=past)
    view = _call("get_compliance_status", product, owner)["support_period"]
    assert view["state"] == "ended"
    assert "Article 13(9)" in view["note"], "the duty that continues afterwards"


def test_status_flags_a_date_with_no_reasoning(product, owner):
    """Reachable by a direct state write rather than the tool, which is exactly
    when a status needs to notice."""
    state = store_pg.load_state(product)
    state.support_period.end = NOW + timedelta(days=800)
    state.support_period.start = NOW
    state.support_period.rationale = ""
    store_pg.save_state(state)

    view = _call("get_compliance_status", product, owner)["support_period"]
    assert view["has_reasoning"] is False
    assert "Annex VII(4)" in view["incomplete"]


# ---- the sweeper ----------------------------------------------------------------------


@pytest.fixture
def captured(monkeypatch):
    sent = []
    monkeypatch.setattr(
        mailer, "send", lambda **kw: sent.append(kw) or "ses-message-id"
    )
    monkeypatch.setattr(sweeper, "is_enabled", lambda: True)
    return sent


def _end_in(product, days: float):
    """Set the mirrored column directly — the ladder is what is under test."""
    with session_scope() as s:
        s.get(Product, product).support_period_end = NOW + timedelta(days=days)


def _rows_for(product) -> list:
    """Notification rows for this product only.

    The sweeper is global by design — it walks every product in the table —
    so a bare `result["sent"]` also counts other tests' fixtures. Asserting on
    this product's rows is both isolated and closer to the real question.
    """
    with session_scope() as s:
        return [
            (r.kind, r.status, r.obligation_id)
            for r in s.query(NotificationLog)
            .filter(NotificationLog.product_id == product)
            .all()
        ]


def _mine(captured, owner) -> list:
    """Mails to this test's owner.

    Keyed on the recipient, not the product name — every fixture product here
    is called "Acme Gateway", and the sweeper is global, so matching on the
    subject picks up other tests' mail.
    """
    return [c for c in captured if c["to_email"].startswith(owner)]


def test_a_product_ending_in_90_days_produces_a_notification(product, owner, captured):
    """#3's 'Done when', first clause."""
    _end_in(product, 90)
    sweeper.sweep_once(now=NOW)

    assert _rows_for(product) == [("eos:T-90d", "sent", None)]
    assert "90 days left of support" in _mine(captured, owner)[0]["subject"]


def test_it_does_not_send_the_same_rung_twice(product, owner, captured):
    _end_in(product, 90)
    sweeper.sweep_once(now=NOW)
    sweeper.sweep_once(now=NOW + timedelta(hours=1))
    assert len(_rows_for(product)) == 1


def test_a_passed_period_sends_the_ended_message(product, owner, captured):
    _end_in(product, -5)
    sweeper.sweep_once(now=NOW)
    assert [k for k, _, _ in _rows_for(product)] == ["eos:ended"]
    mine = _mine(captured, owner)[0]
    assert "Support period ended" in mine["subject"]
    assert "Article 13(9)" in mine["plain"], "the duty that continues"


def test_a_distant_end_date_sends_nothing(product, owner, captured):
    _end_in(product, 400)
    sweeper.sweep_once(now=NOW)
    assert _rows_for(product) == []
    assert _mine(captured, owner) == []


def test_a_product_with_no_support_period_is_not_considered(product, owner, captured):
    sweeper.sweep_once(now=NOW)
    assert _rows_for(product) == []


def test_the_rows_are_namespaced_and_carry_no_obligation(product, owner, captured):
    """`notification_log` is shared with the Article 14 ladder. These rows have
    no obligation to point at, which is why dedupe keys on the product and the
    kind is prefixed."""
    _end_in(product, 30)
    sweeper.sweep_once(now=NOW)
    assert _rows_for(product) == [("eos:T-30d", "sent", None)]


def test_a_missing_sender_is_recorded_as_suppressed_not_lost(product, owner, monkeypatch):
    """The module's own rule: misconfiguration is recorded, not swallowed. An
    operator asking "why did nobody get told" gets an answer from the data."""
    monkeypatch.setattr(sweeper, "is_enabled", lambda: True)

    def unconfigured(**kw):
        raise mailer.NotConfigured("CRA_ALERTS_FROM is not set")

    monkeypatch.setattr(mailer, "send", unconfigured)
    _end_in(product, 7)
    sweeper.sweep_once(now=NOW)

    assert [(k, st) for k, st, _ in _rows_for(product)] == [("eos:T-7d", "suppressed")]
    with session_scope() as s:
        row = (
            s.query(NotificationLog)
            .filter(NotificationLog.product_id == product)
            .one()
        )
        assert "CRA_ALERTS_FROM" in row.error_text


def test_a_dry_run_resolves_recipients_without_sending(product, owner, captured):
    _end_in(product, 90)
    result = sweeper.sweep_once(now=NOW, dry_run=True)
    mine = [p for p in result["support_period"]["planned"] if p["product"] == "Acme Gateway"]
    assert len(mine) == 1
    assert mine[0]["kind"] == "eos:T-90d"
    assert mine[0]["recipients"]
    assert _rows_for(product) == [], "a dry run records nothing"
    assert captured == []


def test_support_period_alerts_are_counted_apart_from_deadlines(product, owner, captured):
    """"You owe a report in six hours" and "this leaves support in 90 days" are
    different questions, and adding them into one number leaves an operator
    unpicking it."""
    _end_in(product, 90)
    result = sweeper.sweep_once(now=NOW)
    assert result["sent"] == 0, "no Article 14 obligation exists on this product"
    assert result["support_period"]["sent"] >= 1
    assert "support_period" in result and "considered" in result["support_period"]
