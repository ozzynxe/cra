"""The read-only console.

Two properties carry this file. The first is that no page shows anything its
viewer could not already fetch through MCP — asserted by sweeping every
product-scoped route with a non-member, so a new page cannot be added without
inheriting the check. That is the same shape as the membership sweep over the
tool surface, and for the same reason: the one gap that ever existed got in
through a handler written without the check its neighbours had.

The second is that a session is genuinely revocable. It is the only stateful
credential in this service, it reads unreported exploited-vulnerability
records, and "I lost my laptop" has to have an answer.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from starlette.testclient import TestClient  # noqa: E402

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import User, WebSession, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import sessions, signup, store_pg, webui  # noqa: E402
from cra.server.http_app import app  # noqa: E402

UTC = timezone.utc

# Every product-scoped page. The sweep below is parametrised over this, so a
# new page that forgets the membership check fails the suite.
PRODUCT_ROUTES = ("", "/requirements", "/report")


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "1")
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")
    monkeypatch.setenv("CRA_SIGNUP_ENABLED", "1")
    monkeypatch.setenv("CRA_RL_CONSOLE_LOGIN_PER_HOUR", "10000")


@pytest.fixture
def outbox(monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: sent.append(kw) or "m")
    return sent


@pytest.fixture
def client():
    return TestClient(app)


def _user(tier="team") -> tuple[str, str]:
    uid = str(uuid.uuid4())
    email = f"{uuid.uuid4().hex[:12]}@example.test"
    with session_scope() as s:
        s.add(User(id=uid, email=email, tier=tier))
    return uid, email


def _product(owner: str, name="Console probe") -> str:
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(ComplianceState(
        product_id=pid, name=name,
        members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
        created_at=now, updated_at=now))
    dispatcher.dispatch("classify_product", pid, owner, {
        "product_class": "default", "in_scope": True,
        "rationale": "Ordinary product with digital elements."})
    return pid


def _signed_in(client, uid) -> TestClient:
    client.cookies.set(sessions.COOKIE, sessions.issue(uid))
    return client


def _code(outbox) -> str:
    body = outbox[-1]["plain"].replace("\n", " ")
    return next(w for w in body.split() if w.isdigit() and len(w) == 6)


def _hidden(html: str) -> dict:
    out = {}
    for tag in re.findall(r'<input[^>]*type="hidden"[^>]*>', html):
        n = re.search(r'name="([^"]*)"', tag)
        v = re.search(r'value="([^"]*)"', tag)
        if n:
            out[n.group(1)] = v.group(1) if v else ""
    return out


# ---- the sweep ---------------------------------------------------------------


@pytest.mark.parametrize("suffix", PRODUCT_ROUTES)
def test_a_non_member_gets_nothing(client, suffix):
    """A product id is not a capability, on the web either."""
    owner, _ = _user()
    pid = _product(owner)
    stranger, _ = _user()

    r = _signed_in(client, stranger).get(f"/app/p/{pid}{suffix}", follow_redirects=False)
    assert r.status_code == 404
    assert "Console probe" not in r.text


@pytest.mark.parametrize("suffix", PRODUCT_ROUTES)
def test_an_unknown_product_reads_the_same_as_someone_elses(client, suffix):
    """Distinguishing them would confirm an id exists to someone not on it."""
    owner, _ = _user()
    pid = _product(owner)
    stranger, _ = _user()
    c = _signed_in(client, stranger)

    theirs = c.get(f"/app/p/{pid}{suffix}")
    nowhere = c.get(f"/app/p/{uuid.uuid4()}{suffix}")
    assert theirs.status_code == nowhere.status_code == 404
    assert theirs.text == nowhere.text


@pytest.mark.parametrize("suffix", PRODUCT_ROUTES)
def test_signed_out_is_sent_to_login_not_shown_the_page(client, suffix):
    owner, _ = _user()
    pid = _product(owner)
    client.cookies.clear()
    r = client.get(f"/app/p/{pid}{suffix}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/app/login")


@pytest.mark.parametrize("suffix", PRODUCT_ROUTES)
def test_a_member_sees_their_own(client, suffix):
    owner, _ = _user()
    pid = _product(owner)
    r = _signed_in(client, owner).get(f"/app/p/{pid}{suffix}")
    assert r.status_code == 200
    assert "Console probe" in r.text


# ---- sessions ----------------------------------------------------------------


def test_login_mints_a_session_and_logout_revokes_it(client, outbox):
    uid, email = _user()
    client.cookies.clear()

    page = client.get("/app/login")
    sent = client.post("/app/login", data={**_hidden(page.text), "email": email})
    assert "Enter your code" in sent.text

    done = client.post(
        "/app/login", data={**_hidden(sent.text), "code": _code(outbox)},
        follow_redirects=False,
    )
    assert done.status_code == 303
    cookie = done.cookies.get(sessions.COOKIE)
    assert cookie and sessions.resolve(cookie) == uid

    client.cookies.set(sessions.COOKIE, cookie)
    assert client.post("/app/logout", follow_redirects=False).status_code == 303
    assert sessions.resolve(cookie) is None


def test_a_revoked_session_is_refused_exactly_like_a_forged_one(client):
    uid, _ = _user()
    cookie = sessions.issue(uid)
    sessions.revoke(cookie)

    for bad in (cookie, f"{uuid.uuid4()}.nope", "not-a-session", ""):
        client.cookies.set(sessions.COOKIE, bad)
        r = client.get("/app", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/app/login")


def test_an_expired_session_stops_working(client):
    uid, _ = _user()
    cookie = sessions.issue(uid)
    sid = cookie.split(".", 1)[0]
    with session_scope() as s:
        s.get(WebSession, sid).expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert sessions.resolve(cookie) is None


def test_a_session_cannot_renew_itself_past_the_hard_cap():
    """Otherwise an expiry is decoration: use it daily and it lasts forever."""
    uid, _ = _user()
    cookie = sessions.issue(uid)
    sid = cookie.split(".", 1)[0]
    soon = datetime.now(UTC) + timedelta(hours=1)
    with session_scope() as s:
        row = s.get(WebSession, sid)
        row.hard_expires_at = soon
        row.last_seen_at = datetime.now(UTC) - timedelta(days=1)

    assert sessions.resolve(cookie) == uid
    with session_scope() as s:
        assert s.get(WebSession, sid).expires_at <= soon


def test_revoke_all_ends_every_session(client):
    """The answer to 'I lost my laptop', and the reason these are rows."""
    uid, _ = _user()
    cookies = [sessions.issue(uid) for _ in range(3)]
    assert sessions.revoke_all(uid) == 3
    assert all(sessions.resolve(c) is None for c in cookies)


def test_logging_in_twice_never_reuses_a_session_id():
    """Reuse would let a cookie captured before a login keep working after."""
    uid, _ = _user()
    first, second = sessions.issue(uid), sessions.issue(uid)
    assert first.split(".")[0] != second.split(".")[0]


def test_only_a_hash_of_the_session_secret_is_stored():
    uid, _ = _user()
    secret = sessions.issue(uid).split(".", 1)[1]
    with session_scope() as s:
        rows = list(s.query(WebSession).filter(WebSession.user_id == uid))
    assert all(secret not in r.secret_sha256 for r in rows)


def test_a_login_code_cannot_be_spent_on_billing(outbox):
    """Third purpose, same rule: proving the address is not the same as what
    the proof is worth."""
    _uid, email = _user()
    challenge = signup.start_code_challenge(
        email, purpose=signup.PURPOSE_LOGIN, what="sign in"
    )
    code = _code(outbox)
    with pytest.raises(signup.SignupError):
        signup.verify_code(challenge, code, purpose=signup.PURPOSE_BILLING)
    assert signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)["ok"]


# ---- the pages ---------------------------------------------------------------


def test_an_empty_console_says_where_the_work_happens(client):
    """A console that shows nothing and offers nothing reads as broken."""
    uid, _ = _user()
    r = _signed_in(client, uid).get("/app")
    assert r.status_code == 200
    assert "claude mcp add" in r.text
    assert "No products yet" in r.text


def test_the_product_list_shows_only_yours(client):
    mine, _ = _user()
    theirs, _ = _user()
    _product(mine, name="Mine")
    _product(theirs, name="Theirs")

    body = _signed_in(client, mine).get("/app").text
    assert "Mine" in body and "Theirs" not in body


def test_a_free_plan_sees_a_plan_limit_not_an_error(client):
    """`upgrade_required` is a plan limit; rendering it as a failure would read
    as the product being broken."""
    uid, _ = _user(tier="free")
    pid = _product(uid)
    r = _signed_in(client, uid).get(f"/app/p/{pid}/requirements")
    assert r.status_code == 200
    # list_requirements is free, so this page renders; the report is the one
    # that carries the coverage note.
    assert "22" in r.text


def test_the_free_report_says_it_is_a_working_view(client):
    uid, _ = _user(tier="free")
    pid = _product(uid)
    r = _signed_in(client, uid).get(f"/app/p/{pid}/report")
    assert r.status_code == 200
    # The note changed when evidence moved onto the free plan: a free user can
    # record evidence now, so gaps are real gaps. What is still true is that
    # nobody has attested to this version.
    assert "freezing or signing" in r.text
    assert "not that the work is undone" not in r.text
    assert "Content hash" in r.text or "content hash" in r.text.lower()


def test_the_report_carries_the_hash_and_the_disclaimer(client):
    uid, _ = _user()
    pid = _product(uid)
    r = _signed_in(client, uid).get(f"/app/p/{pid}/report")
    # The retention row cites the provision that actually imposes it. It said
    # "Annex VII requires ... retained" until 2026-08-09; Annex VII lists what
    # the file contains and imposes nothing.
    assert "Article 13(13)" in r.text
    assert "Annex VII requires" not in r.text
    assert "cannot certify" in r.text or "not a compliance determination" in r.text


# ---- headers -----------------------------------------------------------------


def test_console_pages_carry_a_policy_and_are_not_cached(client):
    """Pages served from disk get a CSP from Caddy; proxied ones get nothing
    unless the app sets it. These list open vulnerabilities."""
    uid, _ = _user()
    r = _signed_in(client, uid).get("/app")
    assert r.headers["content-security-policy"] == webui.CSP
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_the_session_cookie_is_locked_down(client, outbox):
    uid, email = _user()
    client.cookies.clear()
    page = client.get("/app/login")
    sent = client.post("/app/login", data={**_hidden(page.text), "email": email})
    done = client.post(
        "/app/login", data={**_hidden(sent.text), "code": _code(outbox)},
        follow_redirects=False,
    )
    raw = done.headers["set-cookie"].lower()
    assert "httponly" in raw
    assert "samesite=lax" in raw
    assert sessions.COOKIE == "cra_session"   # not the inherited coauthor name


def test_login_will_not_redirect_off_site(client, outbox):
    """An open redirect on a login page is how a credential ends up elsewhere."""
    uid, email = _user()
    client.cookies.clear()
    page = client.get("/app/login", params={"next": "https://evil.test/steal"})
    sent = client.post(
        "/app/login",
        data={**_hidden(page.text), "next": "https://evil.test/steal", "email": email},
    )
    done = client.post(
        "/app/login", data={**_hidden(sent.text), "code": _code(outbox)},
        follow_redirects=False,
    )
    assert done.headers["location"] == "/app"
