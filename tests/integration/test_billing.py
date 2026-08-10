"""Paying, and what the code refuses to conclude from a payment.

Stripe is stubbed throughout — none of this needs the network. What is being
tested is the boundary: money arrives from an external system carrying a claim
about what was bought, and that claim turns into an access-control decision.

The properties worth pinning are all about not over-trusting that:

  * a plan name from Stripe is validated against the ladder before it grants
    anything, because "whatever the metadata said" is not an authorisation
    model;
  * a payment we cannot attribute to a plan grants nothing and says so, rather
    than guessing the cheapest or most generous option;
  * the redirect back from Stripe grants nothing at all — only the webhook
    does, because `?checkout=success` is a string a browser can be pointed at;
  * a duplicate event does not double-apply, since Stripe retries for days.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from starlette.testclient import TestClient  # noqa: E402

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import User, session_scope  # noqa: E402
from cra.server import billing, entitlements  # noqa: E402
from cra.server.http_app import app  # noqa: E402

UTC = timezone.utc


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "1")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    monkeypatch.setenv("STRIPE_PRICE_SOLO_MONTHLY", "price_solo_m")
    monkeypatch.setenv("STRIPE_PRICE_TEAM_MONTHLY", "price_team_m")
    monkeypatch.setenv("STRIPE_PRICE_TEAM_ANNUAL", "price_team_a")


@pytest.fixture
def client():
    return TestClient(app)


def _user(tier="free") -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test", tier=tier))
    return uid


def _tier(uid: str) -> tuple[str, object]:
    with session_scope() as s:
        u = s.get(User, uid)
        return u.tier, u.tier_until


def _call(tool, actor_id, **args):
    return dispatcher.dispatch(tool, "", actor_id, args)


def _session(uid, plan, *, cadence="monthly", period_end=None, customer="cus_1"):
    return {
        "id": "cs_1",
        "client_reference_id": uid,
        "customer": customer,
        "metadata": {"coauthor_user_id": uid, "cra_plan": plan, "cadence": cadence},
        "current_period_end": period_end,
    }


def _event(obj, *, type_="checkout.session.completed", eid=None):
    return {
        "id": eid or f"evt_{uuid.uuid4().hex[:12]}",
        "type": type_,
        "data": {"object": obj},
    }


# ---- what is for sale --------------------------------------------------------


def test_only_plans_with_a_configured_price_are_sellable():
    """Derived from the environment, so a plan without a price simply is not
    offered — no list in code to forget to update."""
    available = billing.sellable_plans()
    assert available == {"solo": ["monthly"], "team": ["monthly", "annual"]}
    for granted in ("free", "founding", "internal"):
        assert granted not in available


def test_the_menu_names_what_a_plan_lifts_but_never_a_price(monkeypatch):
    """Prices live in Stripe. A number duplicated here is wrong the first time
    one changes, and this is the copy a user is shown."""
    out = _call("get_upgrade_link", _user())
    assert out["current_plan"] == "free"
    blob = repr(out)
    assert "€" not in blob and "$" not in blob
    assert "price_" not in blob   # nor the Stripe price ids themselves
    team = next(p for p in out["plans"] if p["plan"] == "team")
    assert team["products"] == 3
    # `adds` is what a plan lifts *over free*, and free now covers everything
    # except the legal act — so every paid plan adds exactly one thing.
    assert set(team["adds"]) == {entitlements.CONFORMITY}


def test_upgrading_is_reachable_from_the_free_plan():
    """A paywall you cannot reach from behind the paywall is a dead end."""
    from cra.agents import dispatch

    for tool in ("get_upgrade_link", "manage_subscription"):
        assert tool in dispatch._FREE
        assert tool in dispatch._SESSION_AGNOSTIC


def test_an_unconfigured_deployment_says_so_instead_of_failing(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    out = _call("get_upgrade_link", _user())
    assert out["ok"] is True
    assert out["checkout_available"] is False
    assert "cra@skarp.app" in out["how"]


def test_an_unsellable_plan_is_refused_with_the_alternatives():
    out = _call("get_upgrade_link", _user(), plan="portfolio")
    assert out["ok"] is False
    assert "solo" in out["error"] and "team" in out["error"]


def test_a_cadence_that_is_not_sold_is_refused():
    out = _call("get_upgrade_link", _user(), plan="solo", cadence="annual")
    assert out["ok"] is False
    assert "annual" in out["error"]


# ---- checkout ----------------------------------------------------------------


def test_a_checkout_link_does_not_claim_the_upgrade_happened(monkeypatch):
    uid = _user()
    monkeypatch.setattr(
        billing, "create_checkout_session",
        lambda user, **kw: billing.CheckoutResult(url="https://checkout.stripe.com/x", session_id="cs_1"),
    )
    out = _call("get_upgrade_link", uid, plan="team")
    assert out["checkout_url"].startswith("https://checkout.stripe.com/")
    assert "Nothing has changed yet" in out["note"]
    # And it did not: the tier only moves on the webhook.
    assert _tier(uid)[0] == "free"


def test_the_plan_bought_is_stamped_where_the_webhook_will_find_it(monkeypatch):
    """Renewals and cancellations arrive as subscription events long after the
    checkout session is gone, so the plan has to be on the subscription too."""
    captured = {}

    class _FakeStripe:
        class checkout:
            class Session:
                @staticmethod
                def create(**kw):
                    captured.update(kw)
                    return {"url": "https://checkout.stripe.com/x", "id": "cs_1"}

    monkeypatch.setattr(billing, "_stripe", lambda: _FakeStripe)
    monkeypatch.setattr(billing, "get_or_create_customer", lambda u: "cus_1")

    uid = _user()
    with session_scope() as s:
        user = s.get(User, uid)
        s.expunge(user)
    billing.create_checkout_session(user, plan="team", cadence="annual")

    assert captured["metadata"]["cra_plan"] == "team"
    assert captured["subscription_data"]["metadata"]["cra_plan"] == "team"
    assert captured["client_reference_id"] == uid
    assert captured["line_items"][0]["price"] == "price_team_a"


# ---- the webhook, which is the only thing that grants -----------------------


def test_a_completed_checkout_grants_the_plan_that_was_bought():
    uid = _user()
    ends = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    out = billing.handle_event(_event(_session(uid, "team", period_end=ends)))
    assert out["ok"] is True

    tier, until = _tier(uid)
    assert tier == "team"
    assert until is not None
    assert entitlements.plan_for(uid).max_products == 3


def test_a_plan_name_stripe_does_not_recognise_grants_nothing():
    """Metadata comes back from an external system and is about to become an
    access decision. Validate it, or 'whatever the payload said' is the
    authorisation model."""
    uid = _user()
    out = billing.handle_event(_event(_session(uid, "unlimited-everything")))
    assert out["ok"] is False
    assert _tier(uid)[0] == "free"


def test_a_payment_with_no_plan_grants_nothing_rather_than_guessing():
    """Silently granting the cheapest thing is a support ticket from someone
    who paid for more; granting the most generous is one from an accountant."""
    uid = _user()
    session = _session(uid, "team")
    session["metadata"] = {"coauthor_user_id": uid}
    out = billing.handle_event(_event(session))
    assert out["ok"] is False
    assert _tier(uid)[0] == "free"


def test_a_retried_event_does_not_apply_twice():
    """Stripe retries on 5xx for about three days."""
    uid = _user()
    event = _event(_session(uid, "team"))
    assert billing.handle_event(event)["ok"] is True

    with session_scope() as s:
        s.get(User, uid).tier = "free"          # simulate a later downgrade
    again = billing.handle_event(event)
    assert again.get("duplicate") is True
    assert _tier(uid)[0] == "free"              # not re-granted


def test_a_portal_downgrade_moves_the_plan():
    uid = _user(tier="team")
    sub = {
        "id": "sub_1",
        "customer": "cus_1",
        "status": "active",
        "metadata": {"coauthor_user_id": uid, "cra_plan": "solo"},
        "current_period_end": int((datetime.now(UTC) + timedelta(days=10)).timestamp()),
    }
    billing.handle_event(_event(sub, type_="customer.subscription.updated"))
    assert _tier(uid)[0] == "solo"


def test_a_cancellation_keeps_the_plan_through_the_paid_period():
    """Cutting someone off mid-period would take away reporting clocks they
    have already paid for — and those are statutory."""
    uid = _user(tier="team")
    ends = datetime.now(UTC) + timedelta(days=20)
    sub = {
        "id": "sub_1",
        "customer": "cus_1",
        "metadata": {"coauthor_user_id": uid, "cra_plan": "team"},
        "current_period_end": int(ends.timestamp()),
    }
    billing.handle_event(_event(sub, type_="customer.subscription.deleted"))

    assert _tier(uid)[0] == "team"
    assert entitlements.plan_for(uid).name == "team"


def test_and_then_lapses_on_its_own_with_nothing_running():
    uid = _user(tier="team")
    with session_scope() as s:
        s.get(User, uid).tier_until = datetime.now(UTC) - timedelta(seconds=1)
    assert entitlements.plan_for(uid).name == "free"
    # The persistent flip is a convenience, not the mechanism.
    assert billing.expire_stale_tier(uid) == "free"
    assert _tier(uid)[0] == "free"


def test_a_grant_plan_never_lapses():
    """`founding` and `internal` are not subscriptions and have no paid-through
    date to fall off."""
    uid = _user(tier="founding")
    with session_scope() as s:
        s.get(User, uid).tier_until = datetime.now(UTC) - timedelta(days=400)
    assert billing.expire_stale_tier(uid) is None
    assert entitlements.plan_for(uid).name == "founding"


def test_an_unknown_event_type_is_accepted_and_ignored():
    out = billing.handle_event(_event({}, type_="invoice.paid"))
    assert out["ok"] is True
    assert out["ignored"] == "invoice.paid"


# ---- the HTTP surface --------------------------------------------------------


def test_an_unsigned_webhook_is_rejected_and_not_retried(client):
    r = client.post("/api/stripe/webhook", content=b'{"id":"evt_1"}')
    assert r.status_code == 400  # 4xx: Stripe gives up rather than retrying


def test_a_forged_webhook_cannot_grant_a_plan(client, monkeypatch):
    """The signature is the only thing standing between this endpoint and
    anybody on the internet writing to `users.tier`."""
    uid = _user()
    r = client.post(
        "/api/stripe/webhook",
        json=_event(_session(uid, "portfolio")),
        headers={"stripe-signature": "t=1,v1=nonsense"},
    )
    assert r.status_code == 400
    assert _tier(uid)[0] == "free"


def test_a_verified_webhook_is_accepted(client, monkeypatch):
    uid = _user()
    monkeypatch.setattr(
        billing, "verify_webhook", lambda payload, sig: _event(_session(uid, "solo"))
    )
    r = client.post(
        "/api/stripe/webhook", json={}, headers={"stripe-signature": "t=1,v1=ok"}
    )
    assert r.status_code == 200
    assert _tier(uid)[0] == "solo"


def test_a_handler_failure_is_not_retried_for_three_days(client, monkeypatch):
    """It would fail identically each time. The useful outcome is a log line a
    person reads, not seventy-two hours of noise."""
    monkeypatch.setattr(
        billing, "verify_webhook",
        lambda payload, sig: _event(_session(str(uuid.uuid4()), "team")),
    )
    r = client.post(
        "/api/stripe/webhook", json={}, headers={"stripe-signature": "t=1,v1=ok"}
    )
    assert r.status_code == 200


def test_the_success_page_grants_nothing(client):
    """It is reachable by typing a URL, so it must not be able to say anything
    about entitlement."""
    uid = _user()
    r = client.get("/billing", params={"checkout": "success"})
    assert r.status_code == 200
    assert "cra_overview" in r.text
    assert _tier(uid)[0] == "free"


def test_the_cancel_page_says_nothing_was_charged(client):
    r = client.get("/billing", params={"checkout": "cancel"})
    assert "Nothing was charged" in r.text
