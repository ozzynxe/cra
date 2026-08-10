"""Buying from a browser.

The agent path already worked. This exists for the two people it did not serve
— someone deciding whether to buy at all, and the person who actually pays, who
on a team plan often has no MCP client — and to stop "click the payment link
your AI gave you" becoming the normal way to pay.

What is pinned here:

  * the pricing page never states a price it cannot currently stand behind: it
    is read from Stripe, cached, and when neither is available the page says so
    rather than rendering a blank or a guess;
  * the flow proves the address before it will open a checkout, using a code
    issued for billing that an OAuth code cannot substitute for;
  * nothing is remembered between requests — the intent travels in the form —
    so there is no session to steal;
  * and the redirect back from Stripe still grants nothing.

screen: allow-file money: the fixtures below use invented amounts, and the only
real figure asserted is the free tier's zero, which is not a price.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from starlette.testclient import TestClient  # noqa: E402

from cra.db import User, session_scope  # noqa: E402
from cra.server import billing, pricing, signup  # noqa: E402
from cra.server.http_app import app  # noqa: E402


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "1")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")
    monkeypatch.setenv("CRA_SIGNUP_ENABLED", "1")
    monkeypatch.setenv("CRA_RL_BILLING_PER_HOUR", "10000")
    monkeypatch.setenv("STRIPE_PRICE_SOLO_MONTHLY", "price_solo_m")
    monkeypatch.setenv("STRIPE_PRICE_TEAM_MONTHLY", "price_team_m")
    # Both cadences, as production has. Configuring only monthly hid the
    # cadence toggle entirely — which is correct behaviour, and is also why
    # nothing here noticed that an annual price could be advertised and never
    # bought.
    monkeypatch.setenv("STRIPE_PRICE_SOLO_ANNUAL", "price_solo_a")
    monkeypatch.setenv("STRIPE_PRICE_TEAM_ANNUAL", "price_team_a")
    pricing._reset_cache()
    yield
    pricing._reset_cache()


@pytest.fixture
def outbox(monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: sent.append(kw) or "msg")
    return sent


class _StripeObject:
    """Behaves like the real thing, which is the point.

    `stripe.StripeObject` supports `obj["field"]` but not `obj.get("field")` —
    `.get` falls through to its `__getattr__` and raises. Stubbing with a plain
    dict made the pricing page pass its tests and then fail on the first real
    request, so the stub now refuses `.get` the same way.
    """

    def __init__(self, data):
        self._data = {
            k: _StripeObject(v) if isinstance(v, dict) else v for k, v in data.items()
        }

    def __getitem__(self, key):
        return self._data[key]

    def __getattr__(self, name):
        raise AttributeError(name)


# Deliberately not the real ladder. Amounts live in Stripe and no figure this
# service actually charges belongs in this repository — a fixture that encoded
# the live prices would publish them and go stale at the next repricing. These
# are arbitrary and only have to be distinct, non-round, and formattable.
SOLO_M, TEAM_M = 700, 2300
SOLO_A, TEAM_A = 7000, 23000


@pytest.fixture
def prices(monkeypatch):
    """Stripe's price objects, stubbed with stand-in amounts."""
    catalogue = {
        "price_solo_m": {"unit_amount": SOLO_M, "currency": "eur", "recurring": {"interval": "month"}},
        "price_team_m": {"unit_amount": TEAM_M, "currency": "eur", "recurring": {"interval": "month"}},
        "price_solo_a": {"unit_amount": SOLO_A, "currency": "eur", "recurring": {"interval": "year"}},
        "price_team_a": {"unit_amount": TEAM_A, "currency": "eur", "recurring": {"interval": "year"}},
    }

    class _FakeStripe:
        class Price:
            @staticmethod
            def retrieve(ref):
                return _StripeObject(catalogue[ref])

    monkeypatch.setattr(billing, "_stripe", lambda: _FakeStripe)
    return catalogue


@pytest.fixture
def client():
    return TestClient(app)


def _user(tier="free", customer=None) -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test", tier=tier, stripe_customer_id=customer))
    return uid


def _fresh_email() -> str:
    """Never a fixed address. Live challenges are capped per address and the
    dev database persists between runs, so a hardcoded one quietly hits the cap
    on the third run and the test fails somewhere unrelated."""
    return f"{uuid.uuid4().hex[:12]}@example.test"


def _email_of(uid: str) -> str:
    with session_scope() as s:
        return s.get(User, uid).email


def _hidden(html: str) -> dict:
    out = {}
    for tag in re.findall(r'<input[^>]*type="hidden"[^>]*>', html):
        n = re.search(r'name="([^"]*)"', tag)
        v = re.search(r'value="([^"]*)"', tag)
        if n:
            out[n.group(1)] = v.group(1) if v else ""
    return out


def _code(outbox) -> str:
    body = outbox[-1]["plain"].replace("\n", " ")
    return next(w for w in body.split() if w.isdigit() and len(w) == 6)


# ---- /pricing ----------------------------------------------------------------


def test_the_pricing_page_shows_prices_read_from_stripe(client, prices):
    r = client.get("/pricing")
    assert r.status_code == 200
    assert f"\u20ac{TEAM_M // 100}" in r.text and f"\u20ac{SOLO_M // 100}" in r.text
    # And the free tier is described, not just the paid ones.
    assert "Free" in r.text and "gap report" in r.text


def test_the_pricing_page_is_the_one_app_page_worth_indexing(client, prices):
    r = client.get("/pricing")
    assert 'name="robots" content="noindex"' not in r.text
    assert client.get("/billing").text.count('content="noindex"') == 1


def test_a_price_stripe_cannot_answer_for_is_not_invented(client, monkeypatch):
    """Rendering a blank or a guess is a claim to a prospect. Saying the price
    is unavailable is merely an outage."""
    class _Broken:
        class Price:
            @staticmethod
            def retrieve(ref):
                raise RuntimeError("stripe is down")

    monkeypatch.setattr(billing, "_stripe", lambda: _Broken)
    r = client.get("/pricing")
    assert r.status_code == 200
    assert "temporarily unavailable" in r.text
    # Exactly one euro figure may survive an outage: the free tier's €0, which
    # is not a Stripe product and so was never fetched. Every other number on
    # this page comes from the payment provider, and rendering one it could not
    # answer for — as a guess or as a blank — is a claim to a prospect.
    assert r.text.count("€") == 1 and "€0" in r.text
    assert "/ month" not in r.text


def test_a_stale_price_beats_no_price(client, prices, monkeypatch):
    """Prices move twice a year. A cached one is almost certainly still right,
    and this is the copy, not the charge."""
    assert f"\u20ac{TEAM_M // 100}" in client.get("/pricing").text

    class _Broken:
        class Price:
            @staticmethod
            def retrieve(ref):
                raise RuntimeError("stripe is down")

    monkeypatch.setattr(billing, "_stripe", lambda: _Broken)
    pricing._FETCHED_AT.clear()          # force a refetch attempt
    assert f"\u20ac{TEAM_M // 100}" in client.get("/pricing").text


def test_with_nothing_priced_the_page_does_not_pretend_to_sell(client, monkeypatch):
    for var in (
        "STRIPE_PRICE_SOLO_MONTHLY",
        "STRIPE_PRICE_TEAM_MONTHLY",
        "STRIPE_PRICE_SOLO_ANNUAL",
        "STRIPE_PRICE_TEAM_ANNUAL",
    ):
        monkeypatch.delenv(var)
    r = client.get("/pricing")
    assert "not on sale here yet" in r.text


# ---- the browser purchase flow ----------------------------------------------


def test_a_purchase_proves_the_address_before_reaching_stripe(client, prices, outbox, monkeypatch):
    uid = _user()
    monkeypatch.setattr(
        billing, "create_checkout_session",
        lambda user, **kw: billing.CheckoutResult(url="https://checkout.stripe.com/x", session_id="cs_1"),
    )

    page = client.get("/pricing")
    assert 'value="subscribe"' in page.text

    asked = client.post("/billing", data={"step": "email", "action": "subscribe", "plan": "team"})
    assert "Confirm it's you" in asked.text

    sent = client.post(
        "/billing",
        data={**_hidden(asked.text), "email": _email_of(uid)},
    )
    assert "Enter your code" in sent.text
    assert len(outbox) == 1
    # The mail says what it is for. A code with no stated reason is
    # indistinguishable from a phishing attempt.
    assert "team" in outbox[0]["plain"]

    done = client.post(
        "/billing",
        data={**_hidden(sent.text), "code": _code(outbox)},
        follow_redirects=False,
    )
    assert done.status_code == 303
    assert done.headers["location"].startswith("https://checkout.stripe.com/")


def test_the_intent_survives_the_code_exchange(client, prices, outbox):
    """Which plan you chose is carried in the form, not in a session — so it
    has to still be there two requests later."""
    _user()
    asked = client.post("/billing", data={"step": "email", "action": "subscribe", "plan": "solo"})
    sent = client.post("/billing", data={**_hidden(asked.text), "email": _fresh_email()})
    carried = _hidden(sent.text)
    assert carried["plan"] == "solo"
    assert carried["action"] == "subscribe"


def test_an_oauth_code_cannot_open_the_billing_flow(client, prices, outbox):
    """Both codes prove the same address. They are not worth the same thing."""
    uid = _user()
    email = _email_of(uid)
    challenge = signup.start_code_challenge(email, client_name="Claude")  # OAuth purpose

    r = client.post(
        "/billing",
        data={
            "step": "code", "action": "subscribe", "plan": "team",
            "email": email, "challenge_id": challenge, "code": _code(outbox),
        },
        follow_redirects=False,
    )
    assert r.status_code == 401


def test_a_wrong_code_does_not_lose_the_purchase(client, prices, outbox):
    _user()
    asked = client.post("/billing", data={"step": "email", "action": "subscribe", "plan": "team"})
    sent = client.post("/billing", data={**_hidden(asked.text), "email": _fresh_email()})

    retry = client.post("/billing", data={**_hidden(sent.text), "code": "000000"})
    assert retry.status_code == 401
    assert _hidden(retry.text)["plan"] == "team"
    assert len(outbox) == 1  # and no second email


def test_buying_creates_the_account_if_there_is_not_one(client, prices, outbox, monkeypatch):
    """The buyer is often not an existing user — that is the whole reason this
    page exists."""
    monkeypatch.setattr(
        billing, "create_checkout_session",
        lambda user, **kw: billing.CheckoutResult(url="https://checkout.stripe.com/x", session_id="cs_1"),
    )
    fresh = f"{uuid.uuid4().hex[:10]}@example.test"
    asked = client.post("/billing", data={"step": "email", "action": "subscribe", "plan": "team"})
    sent = client.post("/billing", data={**_hidden(asked.text), "email": fresh})
    done = client.post(
        "/billing", data={**_hidden(sent.text), "code": _code(outbox)}, follow_redirects=False
    )
    assert done.status_code == 303

    from sqlalchemy import select

    with session_scope() as s:
        user = s.execute(select(User).where(User.email == fresh)).scalar_one()
    assert user.email_verified_at is not None
    assert user.terms_accepted_at is not None   # the page said so before sending


# ---- managing ----------------------------------------------------------------


def test_managing_without_a_subscription_says_so_rather_than_erroring(client, prices, outbox):
    """And says the code has been spent.

    This is the dead end that produced the original report: the button says
    "Continue to Stripe", this page is not Stripe, and pressing it again meets
    "that code has been used" with no explanation of why the first press
    appeared to do nothing.

    The code genuinely cannot be preserved here — checking for a Stripe
    customer before mailing one would answer "does this address have a
    subscription" to anybody who asked, which is an account-enumeration oracle.
    So the honest fix is to say what happened rather than to hide it.
    """
    uid = _user()
    asked = client.post("/billing", data={"step": "email", "action": "manage"})
    sent = client.post("/billing", data={**_hidden(asked.text), "email": _email_of(uid)})
    out = client.post("/billing", data={**_hidden(sent.text), "code": _code(outbox)})
    assert "Nothing to manage yet" in out.text
    assert "no Stripe subscription to open" in out.text
    assert "Your code has been used" in out.text


def test_managing_with_one_reaches_the_portal(client, prices, outbox, monkeypatch):
    uid = _user(tier="team", customer="cus_1")
    monkeypatch.setattr(billing, "create_portal_session", lambda u: "https://billing.stripe.com/p/x")

    asked = client.post("/billing", data={"step": "email", "action": "manage"})
    sent = client.post("/billing", data={**_hidden(asked.text), "email": _email_of(uid)})
    out = client.post(
        "/billing", data={**_hidden(sent.text), "code": _code(outbox)}, follow_redirects=False
    )
    assert out.status_code == 303
    assert out.headers["location"].startswith("https://billing.stripe.com/")


# ---- failure and the return trip --------------------------------------------


def test_stripe_being_down_says_nothing_was_charged(client, prices, outbox, monkeypatch):
    _user()
    def boom(user, **kw):
        raise RuntimeError("stripe is down")

    monkeypatch.setattr(billing, "create_checkout_session", boom)
    asked = client.post("/billing", data={"step": "email", "action": "subscribe", "plan": "team"})
    sent = client.post("/billing", data={**_hidden(asked.text), "email": _fresh_email()})
    out = client.post("/billing", data={**_hidden(sent.text), "code": _code(outbox)})
    assert out.status_code == 502
    assert "Nothing was charged" in out.text


def test_an_unconfigured_deployment_offers_a_person_not_a_stack_trace(client, monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY")
    assert client.get("/billing").status_code == 503
    assert "cra@skarp.app" in client.get("/billing").text


def test_the_success_page_still_grants_nothing(client):
    uid = _user()
    r = client.get("/billing", params={"checkout": "success"})
    assert "cra_overview" in r.text
    with session_scope() as s:
        assert s.get(User, uid).tier == "free"


# ---- finding it again --------------------------------------------------------


def test_every_page_links_to_billing(client, prices):
    """Someone who has paid needs to find where to manage it. The only link
    used to be one muted line at the foot of the pricing page."""
    for path in ("/pricing", "/billing", "/billing?checkout=success"):
        assert 'href="/billing"' in client.get(path).text or "href='/billing'" in client.get(path).text, path


def test_the_success_page_says_where_the_subscription_lives(client):
    body = client.get("/billing", params={"checkout": "success"}).text
    assert "cra.skarp.app/billing" in body
    assert "cancellation" in body.lower()


def test_paying_sends_a_confirmation_naming_the_billing_page(outbox, monkeypatch):
    """Paying used to produce nothing from us — Stripe's receipt and silence.
    An inbox is where people look months later when a card expires."""
    from cra.server import billing as b

    monkeypatch.setattr(b, "session_scope", session_scope)
    uid = _user()
    email = _email_of(uid)
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: outbox.append(kw) or "m")
    monkeypatch.setattr("cra.server.mailer.send", lambda **kw: outbox.append(kw) or "m")

    b.handle_event({
        "id": f"evt_{uuid.uuid4().hex[:12]}",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_1", "client_reference_id": uid, "customer": "cus_1",
            "metadata": {"cra_plan": "team"},
        }},
    })
    assert len(outbox) == 1
    sent = outbox[0]
    assert sent["to_email"] == email
    assert "team" in sent["subject"]
    assert "/billing" in sent["plain"]
    assert "cancel" in sent["plain"].lower()


def test_a_failed_confirmation_does_not_undo_the_grant(outbox, monkeypatch):
    """Stripe would retry, the event is already marked processed, and the plan
    is already granted. The grant is what matters; the email is a courtesy."""
    from cra.server import billing as b

    monkeypatch.setattr("cra.server.mailer.send",
                        lambda **kw: (_ for _ in ()).throw(RuntimeError("SES down")))
    uid = _user()
    out = b.handle_event({
        "id": f"evt_{uuid.uuid4().hex[:12]}",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_1", "client_reference_id": uid, "customer": "cus_1",
            "metadata": {"cra_plan": "solo"},
        }},
    })
    assert out["ok"] is True
    with session_scope() as s:
        assert s.get(User, uid).tier == "solo"


# ---- the annual cadence, and the buy path off /pricing -------------------------
#
# All four of these come from one report: "I get emailed a code, but when I put
# it in and click continue to Stripe nothing happens." None of them was
# reachable by the existing suite, because nothing exercised the *page* — the
# handler was always called with arguments a test had assembled by hand.


def test_the_pricing_page_offers_both_cadences(client, prices):
    """Every annual figure on this page used to be unbuyable: `cadence` was
    read from the form at checkout and never emitted by anything, so it
    defaulted to monthly whatever the visitor had been shown."""
    page = client.get("/pricing").text
    assert 'class="cadence-toggle"' in page
    assert '/pricing?cadence=annual' in page


def test_the_selected_cadence_reaches_the_plan_buttons(client, prices):
    monthly = client.get("/pricing").text
    annual = client.get("/pricing?cadence=annual").text
    assert 'name="cadence" value="monthly"' in monthly
    assert 'name="cadence" value="annual"' in annual


def test_an_unknown_cadence_falls_back_rather_than_reaching_stripe(client, prices):
    """`?cadence=` is a query parameter anybody can type, and it travels to the
    Stripe lookup. An unvalidated value would raise ValueError at the *code*
    step — after the visitor's one-time code had been spent."""
    page = client.get("/pricing?cadence=fortnightly").text
    assert 'name="cadence" value="monthly"' in page
    assert "fortnightly" not in page


def test_choosing_a_plan_does_not_complain_about_an_empty_email(client, prices):
    """The pricing buttons carry intent but no address. Posting `step=email`
    made the handler validate an empty string and answer "That does not look
    like an email address" on a form the visitor had not filled in yet."""
    out = client.post(
        "/billing",
        data={"step": "start", "action": "subscribe", "plan": "team", "cadence": "annual"},
    )
    assert out.status_code == 200
    assert "does not look like an email address" not in out.text
    assert "Confirm it's you" in out.text
    assert _hidden(out.text)["cadence"] == "annual"


def test_the_cadence_survives_the_email_and_code_steps(client, prices, outbox, monkeypatch):
    """The whole point. It has to arrive at `create_checkout_session`."""
    seen = {}

    class _Result:
        url = "https://checkout.stripe.com/c/annual"

    def _capture(user, *, plan, cadence="monthly"):
        seen.update(plan=plan, cadence=cadence)
        return _Result()

    monkeypatch.setattr(billing, "create_checkout_session", _capture)
    uid = _user()

    start = client.post(
        "/billing",
        data={"step": "start", "action": "subscribe", "plan": "team", "cadence": "annual"},
    )
    sent = client.post("/billing", data={**_hidden(start.text), "email": _email_of(uid)})
    out = client.post(
        "/billing",
        data={**_hidden(sent.text), "code": _code(outbox)},
        follow_redirects=False,
    )

    assert out.status_code == 303
    assert seen == {"plan": "team", "cadence": "annual"}


def test_a_checkout_refusal_returns_to_the_code_step_not_the_start(
    client, prices, outbox, monkeypatch
):
    """Bouncing to the email form after the code was spent read as the page
    resetting itself, and left no way to retry."""
    def _boom(user, *, plan, cadence="monthly"):
        raise ValueError(f"{plan!r} is not sold {cadence}")

    monkeypatch.setattr(billing, "create_checkout_session", _boom)
    uid = _user()

    start = client.post(
        "/billing", data={"step": "start", "action": "subscribe", "plan": "team"}
    )
    sent = client.post("/billing", data={**_hidden(start.text), "email": _email_of(uid)})
    out = client.post("/billing", data={**_hidden(sent.text), "code": _code(outbox)})

    assert out.status_code == 400
    assert "Enter your code" in out.text, "should stay on the code step"
    assert "is not sold" in out.text


# ---- the CSP that silently ate the redirect -------------------------------------


def test_billing_pages_allow_a_form_redirect_to_stripe(client, prices):
    """The bug behind "I enter the code and nothing happens".

    `form-action` is checked against the **redirect destination**, not only the
    POST target. Under the default `'self'` the browser blocked the 303 to
    Stripe after `verify_code` had already spent the one-time code — silently,
    with a console warning and nothing in the server log, so the server
    recorded a successful redirect and the visitor saw a page that had not
    moved. Pressing the button again then met "that code has been used".

    Proven in a browser before this was written: Chromium reports "Sending form
    data to ... violates the following Content Security Policy directive:
    form-action 'self'. The request has been blocked."
    """
    for url in ("/pricing", "/billing"):
        csp = client.get(url).headers["content-security-policy"]
        assert "https://checkout.stripe.com" in csp, url
        assert "https://billing.stripe.com" in csp, url


def test_everything_else_keeps_the_tight_policy(client):
    """Only the pages that actually end at Stripe widen it. The console lists
    unreported vulnerabilities and must not be able to post them anywhere."""
    csp = client.get("/app").headers["content-security-policy"]
    assert "form-action 'self';" in csp
    assert "stripe.com" not in csp


def test_the_stripe_hosts_are_named_not_wildcarded(client, prices):
    csp = client.get("/billing").headers["content-security-policy"]
    assert "*.stripe.com" not in csp and "https://stripe.com" not in csp
