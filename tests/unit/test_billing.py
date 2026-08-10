"""Pure-logic tests for the Stripe billing module.

`session_scope` and the Stripe SDK are mocked, so this runs without a database
or a Stripe account. `tests/integration/test_billing.py` covers the same paths
against real Postgres, plus the HTTP surface.

Inherited from Coauthor, where there was one `pro` tier. The plan now comes
from Stripe metadata and is validated against the ladder, so the assertions
here moved with it — a purchase grants the plan that was bought, or nothing.

User ids are UUIDs throughout, not because these tests care but because
`users.id` is a UUID column: a lookup with anything else raises a DataError
that escapes as a 500, which Stripe reads as "retry for three days".
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from cra.server import billing

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
PLAN_MD = {"cra_plan": "team"}


# ---- helpers ---------------------------------------------------------------


@dataclass
class FakeUser:
    """Stand-in for `cra.db.User` — billing only touches a small set of
    fields, so a lightweight dataclass keeps tests fast."""

    id: str
    email: str = "test@example.com"
    display_name: Optional[str] = None
    tier: str = "free"
    stripe_customer_id: Optional[str] = None
    subscription_status: Optional[str] = None
    tier_until: Optional[datetime] = None


class FakeSession:
    """Minimal stand-in for SQLAlchemy session inside a session_scope ctx."""

    def __init__(self, users: dict[str, FakeUser]):
        self._users = users
        self.added: list[Any] = []
        self._duplicate_event_ids: set[str] = set()

    def get(self, model, key):  # noqa: ANN001 — duck-typed
        # We only ever .get(User, id); pretend that's the only behavior.
        return self._users.get(key)

    def add(self, obj):  # noqa: ANN001
        # Mimic ProcessedStripeEvent IntegrityError on dup
        from cra.db import ProcessedStripeEvent
        from sqlalchemy.exc import IntegrityError

        if isinstance(obj, ProcessedStripeEvent):
            if obj.event_id in self._duplicate_event_ids:
                raise IntegrityError("dup", {}, Exception("duplicate"))
            self._duplicate_event_ids.add(obj.event_id)
        self.added.append(obj)

    def scalar(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
        # Used by `_user_id_from_session_or_subscription` fallback lookup;
        # tests that rely on this path stub the whole helper instead.
        return None


@pytest.fixture
def fake_db(monkeypatch):
    """Patch `billing.session_scope` to yield a session populated with the
    users we supply, and return the session so tests can inspect mutations."""
    users: dict[str, FakeUser] = {}
    sess = FakeSession(users)

    @contextlib.contextmanager
    def fake_scope():
        yield sess

    monkeypatch.setattr(billing, "session_scope", fake_scope)
    return users, sess


# ---- env / config ----------------------------------------------------------


def test_is_billing_configured_wants_stripe_an_origin_and_something_to_sell(monkeypatch):
    for var in (
        "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "CRA_APP_ORIGIN",
        "STRIPE_PRICE_TEAM_MONTHLY",
    ):
        monkeypatch.delenv(var, raising=False)
    assert billing.is_billing_configured() is False

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    # Keys and an origin but nothing priced: there is nothing anyone could buy.
    assert billing.is_billing_configured() is False

    monkeypatch.setenv("STRIPE_PRICE_TEAM_MONTHLY", "price_m")
    assert billing.is_billing_configured() is True
    assert billing.sellable_plans() == {"team": ["monthly"]}


def test_a_user_id_that_is_not_a_uuid_is_not_used(monkeypatch):
    """`users.id` is a UUID column. Passing Stripe's string straight into a
    lookup turns a malformed payload into a 500, and a 500 into three days of
    retries over something that can never succeed."""
    monkeypatch.setattr(billing, "session_scope", lambda: (_ for _ in ()).throw(
        AssertionError("should not have reached the database")
    ))
    assert billing._as_user_id("nobody") is None
    assert billing._as_user_id("") is None
    assert billing._as_user_id(None) is None
    assert billing._as_user_id(U1) == U1


def test_a_plan_name_is_validated_before_it_grants_anything():
    assert billing._plan_from({"metadata": {"cra_plan": "team"}}) == "team"
    assert billing._plan_from({"metadata": {"cra_plan": "TEAM"}}) == "team"
    # Not on the ladder, so it is not a plan.
    assert billing._plan_from({"metadata": {"cra_plan": "unlimited"}}) is None
    assert billing._plan_from({"metadata": {}}) is None


def test_to_aware_utc_handles_none():
    assert billing._to_aware_utc(None) is None


def test_to_aware_utc_returns_aware_datetime():
    # Round-trip through `int(.timestamp())` rather than hand-calculating epoch
    # — keeps the assertion focused on the conversion (UTC + aware), not on
    # arithmetic.
    expected = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    dt = billing._to_aware_utc(int(expected.timestamp()))
    assert dt == expected
    assert dt.tzinfo is timezone.utc


def test_period_end_from_subscription_dict_top_level():
    """Older payload shape — current_period_end at the subscription root."""
    expected = datetime(2026, 7, 9, tzinfo=timezone.utc)
    sub = {"id": "sub_x", "current_period_end": int(expected.timestamp())}
    assert billing._period_end_from_subscription_dict(sub) == expected


def test_period_end_from_subscription_dict_per_item():
    """Newer payload shape — current_period_end on items.data[0]."""
    expected = datetime(2026, 7, 9, tzinfo=timezone.utc)
    sub = {
        "id": "sub_x",
        "items": {"data": [{"current_period_end": int(expected.timestamp())}]},
    }
    assert billing._period_end_from_subscription_dict(sub) == expected


def test_period_end_from_subscription_dict_no_data():
    sub = {"id": "sub_x", "items": {"data": []}}
    assert billing._period_end_from_subscription_dict(sub) is None


# ---- user-id resolution from events ----------------------------------------


def test_user_id_from_session_uses_client_reference_id_first():
    obj = {
        "client_reference_id": U1,
        "metadata": {"coauthor_user_id": U2},
        "customer": "cus_zzz",
    }
    assert billing._user_id_from_session_or_subscription(obj) == U1


def test_user_id_from_session_falls_back_to_metadata():
    obj = {
        "metadata": {"coauthor_user_id": U2},
        "customer": "cus_zzz",
    }
    assert billing._user_id_from_session_or_subscription(obj) == U2


def test_user_id_from_session_returns_none_when_nothing_matches(fake_db):
    obj = {"customer": "cus_zzz"}  # no metadata, customer not in fake DB
    assert billing._user_id_from_session_or_subscription(obj) is None


# ---- handle_event dispatch -------------------------------------------------


def test_handle_event_unknown_type_is_noop(fake_db):
    res = billing.handle_event(
        {"id": "evt_unknown_1", "type": "ping.pong", "data": {"object": {}}}
    )
    assert res["ok"] is True
    assert res.get("ignored") == "ping.pong"


def test_handle_event_duplicate_event_id_short_circuits(fake_db):
    users, sess = fake_db
    users[U1] = FakeUser(id=U1)

    event = {
        "id": "evt_dup_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": U1,
                "customer": "cus_aaa",
                "metadata": PLAN_MD,
            }
        },
    }
    first = billing.handle_event(event)
    assert first["ok"] is True
    assert users[U1].tier == "team"

    # Reset the user state to make sure the second call doesn't touch it.
    users[U1].tier = "free"
    users[U1].subscription_status = None

    second = billing.handle_event(event)
    assert second["ok"] is True
    assert second.get("duplicate") is True
    # Critical: side effects did NOT re-run.
    assert users[U1].tier == "free"


def test_handle_checkout_completed_flips_tier_and_persists_customer(fake_db, monkeypatch):
    users, _ = fake_db
    users[U1] = FakeUser(id=U1)

    # Avoid Stripe.Subscription.retrieve fallback by giving the session an
    # explicit period_end shape it can read directly.
    monkeypatch.setattr(billing, "_resolve_period_end", lambda obj: datetime(
        2026, 6, 9, tzinfo=timezone.utc
    ))

    res = billing.handle_event({
        "id": "evt_checkout_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_x",
                "client_reference_id": U1,
                "customer": "cus_aaa",
                "metadata": PLAN_MD,
            }
        },
    })
    assert res["ok"] is True
    assert users[U1].tier == "team"
    assert users[U1].subscription_status == "active"
    assert users[U1].stripe_customer_id == "cus_aaa"
    assert users[U1].tier_until == datetime(2026, 6, 9, tzinfo=timezone.utc)


def test_handle_subscription_deleted_keeps_the_plan_until_the_grace_ends(fake_db):
    """Critical UX: cancel-at-period-end keeps the user on Pro until tier_until."""
    users, _ = fake_db
    end = datetime(2026, 6, 9, tzinfo=timezone.utc)
    users[U1] = FakeUser(
        id=U1,
        tier="team",
        subscription_status="active",
        stripe_customer_id="cus_aaa",
        tier_until=None,
    )

    res = billing.handle_event({
        "id": "evt_deleted_1",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_xxx",
                "client_reference_id": U1,
                "customer": "cus_aaa",
                "current_period_end": int(end.timestamp()),
                "status": "canceled",
            }
        },
    })
    assert res["ok"] is True
    # Tier stays pro — user paid through `tier_until`. Status flips to canceled.
    assert users[U1].tier == "team"
    assert users[U1].subscription_status == "canceled"
    assert users[U1].tier_until == end


def test_handle_subscription_updated_mirrors_status_and_period_end(fake_db):
    """Stripe's recent API moved current_period_end to items.data[*] —
    `_period_end_from_subscription_dict` handles both shapes, so we exercise
    the per-item shape in this test (it's what production payloads now
    look like)."""
    users, _ = fake_db
    end = datetime(2026, 7, 9, tzinfo=timezone.utc)
    users[U1] = FakeUser(
        id=U1,
        tier="team",
        subscription_status="active",
        stripe_customer_id="cus_aaa",
    )

    res = billing.handle_event({
        "id": "evt_updated_1",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_xxx",
                "client_reference_id": U1,
                "customer": "cus_aaa",
                "status": "past_due",
                "items": {
                    "data": [
                        {"current_period_end": int(end.timestamp())},
                    ]
                },
            }
        },
    })
    assert res["ok"] is True
    assert users[U1].subscription_status == "past_due"
    assert users[U1].tier_until == end
    # Tier stays pro — past_due is a billing dunning state, not a downgrade.
    assert users[U1].tier == "team"


def test_handle_subscription_updated_cancel_at_period_end(fake_db):
    """Stripe surfaces `cancel_at_period_end=true` while subscription is still
    `status=active` — UI should show 'canceled' so the end date is visible."""
    users, _ = fake_db
    end = datetime(2026, 6, 9, tzinfo=timezone.utc)
    users[U1] = FakeUser(
        id=U1,
        tier="team",
        subscription_status="active",
        stripe_customer_id="cus_aaa",
    )
    res = billing.handle_event({
        "id": "evt_cancelpe_1",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_xxx",
                "client_reference_id": U1,
                "customer": "cus_aaa",
                "status": "active",
                "cancel_at_period_end": True,
                "current_period_end": int(end.timestamp()),
            }
        },
    })
    assert res["ok"] is True
    assert users[U1].subscription_status == "canceled"
    assert users[U1].tier == "team"


def test_handle_event_no_user_match_is_safe(fake_db):
    """Webhook for a user we don't have in the DB shouldn't crash; it returns
    ok=False with a clear error so the SDK retries and we have something to
    grep for in logs."""
    res = billing.handle_event({
        "id": "evt_nomatch_1",
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_test_x", "customer": "cus_unknown"}},
    })
    assert res["ok"] is False
    assert "user" in res["error"]


# ---- expire_stale_tier ------------------------------------------------------


def test_expire_stale_tier_flips_a_lapsed_plan_to_free(fake_db):
    users, _ = fake_db
    past = datetime.now(timezone.utc) - timedelta(days=1)
    users[U1] = FakeUser(id=U1, tier="team", tier_until=past)

    flipped = billing.expire_stale_tier(U1)
    assert flipped == "free"
    assert users[U1].tier == "free"


def test_expire_stale_tier_leaves_a_current_plan_alone(fake_db):
    users, _ = fake_db
    future = datetime.now(timezone.utc) + timedelta(days=30)
    users[U1] = FakeUser(id=U1, tier="team", tier_until=future)

    flipped = billing.expire_stale_tier(U1)
    assert flipped is None
    assert users[U1].tier == "team"


def test_expire_stale_tier_leaves_free_alone(fake_db):
    users, _ = fake_db
    users[U1] = FakeUser(id=U1, tier="free")

    flipped = billing.expire_stale_tier(U1)
    assert flipped is None
    assert users[U1].tier == "free"


def test_expire_stale_tier_handles_unknown_user(fake_db):
    flipped = billing.expire_stale_tier("does-not-exist")
    assert flipped is None


# ---- webhook signature verification ----------------------------------------


def test_verify_webhook_requires_secret(monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    with pytest.raises(billing.WebhookSignatureError, match="not configured"):
        billing.verify_webhook(b"{}", "t=1,v1=fake")


def test_verify_webhook_rejects_invalid_signature(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    # Stripe SDK raises `SignatureVerificationError` which we wrap.
    with pytest.raises(billing.WebhookSignatureError):
        billing.verify_webhook(b'{"id":"evt_1"}', "t=1,v1=definitely-not-valid")
