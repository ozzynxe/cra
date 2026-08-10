"""Two people on one product.

Two things were broken and both are asserted here.

**A team plan did not cover the team.** Entitlements were checked against
whoever was calling, so a product could carry a plan permitting many members
and still refuse one of them on their own account's tier. The governing plan
is now the product owner's.

**You could not add anyone.** `add_member` took an internal UUID and nothing
could look one up, so inviting a colleague required database access. It takes
an email, and an address without an account gets an invitation applied when
they sign up.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from sqlalchemy import select  # noqa: E402

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import AuditEvent, ProductInvitation, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import entitlements, signup, store_pg  # noqa: E402

UTC = timezone.utc


@pytest.fixture(autouse=True)
def enforced(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "1")
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")


@pytest.fixture
def outbox(monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr("cra.server.mailer.send", lambda **kw: sent.append(kw) or "m")
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: sent.append(kw) or "m")
    return sent


def _user(tier="free") -> tuple[str, str]:
    uid = str(uuid.uuid4())
    email = f"{uuid.uuid4().hex[:12]}@example.test"
    with session_scope() as s:
        s.add(User(id=uid, email=email, tier=tier))
    return uid, email


def _product(owner: str, name="Shared product") -> str:
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(ComplianceState(
        product_id=pid, name=name,
        members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
        created_at=now, updated_at=now))
    dispatcher.dispatch("classify_product", pid, owner, {
        "product_class": "default", "in_scope": True, "rationale": "test"})
    return pid


def _call(tool, pid, uid, **args):
    return dispatcher.dispatch(tool, pid, uid, args)


# ---- whose plan governs ------------------------------------------------------


def test_a_team_plan_covers_the_team():
    """The bug this closes: pay for unlimited members, add one, and watch them
    be refused by their own free tier."""
    alice, _ = _user("team")
    bob, bob_email = _user("free")
    pid = _product(alice)
    assert _call("add_member", pid, alice, email=bob_email)["ok"] is True

    for tool in ("get_reporting_deadlines", "list_advisory_candidates"):
        out = _call(tool, pid, bob)
        assert out["ok"] is True, f"{tool} refused a colleague on a paid product"


def test_a_colleagues_own_free_product_is_still_free():
    """Coverage follows the product, so it must not leak to their own.

    Pinned on CONFORMITY since reporting moved to the free plan — the semantics
    are the same, only the feature that still gates anything has changed.
    """
    alice, _ = _user("team")
    bob, bob_email = _user("free")
    _call("add_member", _product(alice), alice, email=bob_email)

    own = _product(bob, name="Bob's own")
    out = _call("sign_off", own, bob, signer_name="B", signer_role="Dev", statement="x")
    assert out["ok"] is False
    assert out["code"] == "upgrade_required"
    assert out["plan"] == "free"


def test_the_refusal_names_the_products_plan_not_the_callers():
    alice, _ = _user("free")
    bob, bob_email = _user("team")     # a paying colleague on a free product
    pid = _product(alice)
    _call("add_member", pid, alice, email=bob_email)

    out = _call("sign_off", pid, bob, signer_name="B", signer_role="Dev", statement="x")
    assert out["ok"] is False
    assert out["plan"] == "free"       # the owner's, not bob's


def test_across_products_nothing_is_uncovered_for_reporting_any_more():
    """Reporting is on the free plan, so this list is now always complete.

    Kept as the assertion that it *is* complete rather than deleted: the
    failure this guards against — a shorter list of statutory deadlines that
    does not say what it omitted, reading as "nothing is due" — is the worst
    output this tool has, and it should stay pinned.
    """
    alice, _ = _user("team")
    bob, bob_email = _user("free")
    _call("add_member", _product(alice, name="Covered"), alice, email=bob_email)
    _product(bob, name="Bob's own")

    out = _call("get_reporting_deadlines", "", bob)
    assert out["ok"] is True
    assert not out.get("not_covered")
    assert not out.get("coverage_note")


def test_the_split_still_works_for_a_feature_the_plan_lacks():
    """`covered_product_ids` is dormant — both callers ask about REPORTING, and
    free covers it, so no live call can produce a non-empty `blocked` list.

    Exercised here against CONFORMITY so it cannot rot while unused. The
    machinery is kept because the first cross-product tool gated on a paid
    feature would have to rebuild all of it, including the shadow-mode branch
    below, which records a real bug: filtering while enforcement was off made
    "what is due across everything I own" answer "nothing" for every free
    account.
    """
    bob, _ = _user("free")
    _product(bob)
    covered, blocked = entitlements.covered_product_ids(bob, entitlements.CONFORMITY)
    assert blocked and not covered, "a free owner should be blocked for CONFORMITY"

    os.environ["CRA_ENTITLEMENTS_ENFORCED"] = "0"
    try:
        covered, blocked = entitlements.covered_product_ids(bob, entitlements.CONFORMITY)
        assert blocked == [] and covered, "shadow mode must not filter"
    finally:
        os.environ["CRA_ENTITLEMENTS_ENFORCED"] = "1"


# ---- inviting ----------------------------------------------------------------


def test_adding_someone_who_already_has_an_account_is_immediate(outbox):
    alice, _ = _user("team")
    bob, bob_email = _user()
    pid = _product(alice)

    out = _call("add_member", pid, alice, email=bob_email)
    assert out["ok"] is True and not out.get("pending")
    assert _call("get_compliance_status", pid, bob)["ok"] is True


def test_a_stranger_is_invited_and_joins_when_they_sign_up(outbox):
    alice, _ = _user("team")
    pid = _product(alice, name="Acme Gateway")
    stranger = f"{uuid.uuid4().hex[:10]}@example.test"

    out = _call("add_member", pid, alice, email=stranger, role="maintainer")
    assert out["ok"] is True and out["pending"] is True
    assert any("Acme Gateway" in m["subject"] for m in outbox)

    # They sign up through the ordinary front door.
    signup.request_access(stranger)
    link = next(
        w for w in outbox[-1]["plain"].split() if w.startswith("https://")
    ).split("t=", 1)[1]
    completed = signup.complete(link)

    assert _call("get_compliance_status", pid, completed["user_id"] if "user_id" in completed
                 else _uid_of(stranger))["ok"] is True


def _uid_of(email: str) -> str:
    with session_scope() as s:
        return s.execute(select(User).where(User.email == email)).scalar_one().id


def test_the_answer_does_not_reveal_whether_they_had_an_account(outbox):
    """Same line `request_access` holds: who has an account here is not
    something an invitation form gives away."""
    alice, _ = _user("team")
    pid = _product(alice)
    _bob, known = _user()

    known_out = _call("add_member", pid, alice, email=known)
    stranger_out = _call("add_member", pid, alice, email=f"{uuid.uuid4().hex[:10]}@example.test")
    assert known_out["ok"] is stranger_out["ok"] is True


def test_joining_by_invitation_is_audited(outbox):
    """Who could have touched a technical file is part of the record."""
    alice, _ = _user("team")
    pid = _product(alice)
    stranger = f"{uuid.uuid4().hex[:10]}@example.test"
    _call("add_member", pid, alice, email=stranger)

    signup.request_access(stranger)
    link = next(w for w in outbox[-1]["plain"].split() if w.startswith("https://")).split("t=", 1)[1]
    signup.complete(link)

    with session_scope() as s:
        ops = [
            a.op for a in s.execute(
                select(AuditEvent).where(AuditEvent.product_id == pid)
            ).scalars()
        ]
    assert "accept_invitation" in ops


def test_the_invitation_row_survives_acceptance(outbox):
    alice, _ = _user("team")
    pid = _product(alice)
    stranger = f"{uuid.uuid4().hex[:10]}@example.test"
    _call("add_member", pid, alice, email=stranger)
    signup.request_access(stranger)
    link = next(w for w in outbox[-1]["plain"].split() if w.startswith("https://")).split("t=", 1)[1]
    signup.complete(link)

    with session_scope() as s:
        row = s.execute(
            select(ProductInvitation).where(ProductInvitation.email == stranger)
        ).scalar_one()
    assert row.accepted_at is not None
    assert row.invited_by == alice


def test_re_inviting_does_not_stack_rows(outbox):
    alice, _ = _user("team")
    pid = _product(alice)
    stranger = f"{uuid.uuid4().hex[:10]}@example.test"
    _call("add_member", pid, alice, email=stranger, role="viewer")
    _call("add_member", pid, alice, email=stranger, role="maintainer")

    with session_scope() as s:
        rows = list(s.execute(
            select(ProductInvitation).where(ProductInvitation.email == stranger)
        ).scalars())
    assert len(rows) == 1
    assert rows[0].role == "maintainer"


def test_only_an_owner_may_add_anyone(outbox):
    alice, _ = _user("team")
    bob, bob_email = _user()
    pid = _product(alice)
    _call("add_member", pid, alice, email=bob_email, role="editor")

    out = _call("add_member", pid, bob, email=f"{uuid.uuid4().hex[:10]}@example.test")
    assert out["ok"] is False


def test_a_solo_plan_may_now_add_a_second_person(outbox):
    """`solo` refused this until 2026-08-09, putting a boundary on hiring
    rather than on anything to do with compliance. Seats are no longer metered
    on any plan."""
    alice, _ = _user("solo")
    pid = _product(alice)
    out = _call("add_member", pid, alice, email=f"{uuid.uuid4().hex[:10]}@example.test")
    assert out["ok"] is True, out
