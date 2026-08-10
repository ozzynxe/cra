"""Connecting a client without ever handling a token.

The consent page used to demand a pasted `cra_…` token, which meant self-serve
access issued a credential the user then carried by hand to the client they
actually wanted to connect. Now it emails a six-digit code instead, and this is
the walk-through: connector UI → email → code → authorized.

What these pin, beyond "it works":

  * every step carries the whole OAuth request, because dropping one parameter
    sends the user back to the client to start over and reads as a broken
    connector rather than a typo;
  * a wrong code re-renders the code step, not the email step;
  * the emailed code is worth a grant for one named client and nothing more —
    in particular it is not a bearer token, and does not become one until the
    client redeems the authorization code with its PKCE verifier;
  * the token form is still reachable, because mail delivery going down must
    not take the whole connector flow with it.

Driven through the real Starlette app over ASGI. The forms are the product
here, so exercising the handlers directly would test the wrong thing.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import uuid
from urllib.parse import parse_qs, urlparse

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from starlette.testclient import TestClient  # noqa: E402

from cra.server import connector_tokens, oauth, signup  # noqa: E402
from cra.server.http_app import app  # noqa: E402

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture(autouse=True)
def outbox(monkeypatch):
    sent: list[dict] = []
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")
    monkeypatch.setenv("CRA_SIGNUP_ENABLED", "1")
    monkeypatch.delenv("CRA_SIGNUP_INVITE_CODE", raising=False)
    # Rate limiting is asserted in its own suite; here it would just make the
    # multi-step flows flaky against a shared bucket.
    monkeypatch.setenv("CRA_RL_OAUTH_AUTHORIZE_PER_HOUR", "10000")
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: sent.append(kw) or "msg-1")
    return sent


@pytest.fixture
def client():
    # No lifespan: starting it would start the MCP session manager, which
    # refuses to run twice against one app instance, and none of these routes
    # touch the MCP wire.
    return TestClient(app)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _authorize_params(challenge: str) -> dict:
    return {
        "response_type": "code",
        "client_id": "test-client",
        "redirect_uri": REDIRECT,
        "state": "opaque-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": "https://cra.example.test/mcp/me/mcp",
        "scope": "mcp",
    }


def _hidden(html: str) -> dict[str, str]:
    """Every hidden field the rendered form will post back."""
    out = {}
    for tag in re.findall(r"<input[^>]*type=\"hidden\"[^>]*>", html):
        name = re.search(r'name="([^"]*)"', tag)
        value = re.search(r'value="([^"]*)"', tag)
        if name:
            out[name.group(1)] = value.group(1) if value else ""
    return out


def _code_from(outbox) -> str:
    body = outbox[-1]["plain"].replace("\n", " ")
    return next(w for w in body.split() if w.isdigit() and len(w) == 6)


def _email() -> str:
    return f"{uuid.uuid4().hex[:12]}@example.test"


# ---- the whole walk ----------------------------------------------------------


def test_a_stranger_connects_a_client_without_ever_seeing_a_token(client, outbox):
    verifier, challenge = _pkce()
    email = _email()

    page = client.get("/oauth/authorize", params=_authorize_params(challenge))
    assert page.status_code == 200
    assert 'name="email"' in page.text
    # Consent is informed at the step where it is given, so the capability list
    # is on the page before anything is sent anywhere.
    assert "unreported" in page.text

    step_one = _hidden(page.text)
    sent = client.post(
        "/oauth/authorize", data={**step_one, "step": "email", "email": email}
    )
    assert sent.status_code == 200
    assert 'name="code"' in sent.text
    assert email in sent.text
    assert len(outbox) == 1

    step_two = _hidden(sent.text)
    # The OAuth request survived intact. This is the failure that would look
    # like "the connector is broken" rather than "you typed it wrong".
    for key, value in _authorize_params(challenge).items():
        assert step_two[key] == value

    done = client.post(
        "/oauth/authorize",
        data={**step_two, "step": "code", "code": _code_from(outbox)},
        follow_redirects=False,
    )
    assert done.status_code == 302
    target = urlparse(done.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == REDIRECT
    query = parse_qs(target.query)
    assert query["state"] == ["opaque-state"]

    # And the authorization code is worth a working token, but only to whoever
    # holds the PKCE verifier.
    granted = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
        },
    )
    assert granted.status_code == 200
    token = granted.json()["access_token"]
    assert token.startswith("cra_")

    verified = connector_tokens.verify_token(token)
    assert verified.product_id is None  # user-wide, as the consent page said
    # Nothing but the client ever held it: the user was never shown a token,
    # and the email did not carry one.
    assert "cra_" not in outbox[0]["plain"] + outbox[0]["html"]


def test_the_authorization_code_is_useless_without_the_verifier(client, outbox):
    _verifier, challenge = _pkce()
    page = client.get("/oauth/authorize", params=_authorize_params(challenge))
    sent = client.post(
        "/oauth/authorize",
        data={**_hidden(page.text), "step": "email", "email": _email()},
    )
    done = client.post(
        "/oauth/authorize",
        data={**_hidden(sent.text), "step": "code", "code": _code_from(outbox)},
        follow_redirects=False,
    )
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]

    stolen = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": secrets.token_urlsafe(48),
            "redirect_uri": REDIRECT,
        },
    )
    assert stolen.status_code == 400
    assert stolen.json()["error"] == "invalid_grant"


def test_a_wrong_code_keeps_the_user_on_the_code_step(client, outbox):
    _verifier, challenge = _pkce()
    page = client.get("/oauth/authorize", params=_authorize_params(challenge))
    sent = client.post(
        "/oauth/authorize",
        data={**_hidden(page.text), "step": "email", "email": _email()},
    )
    hidden = _hidden(sent.text)

    retry = client.post(
        "/oauth/authorize",
        data={**hidden, "step": "code", "code": "000000"},
        follow_redirects=False,
    )
    assert retry.status_code == 401
    assert 'name="code"' in retry.text
    # Same challenge, so the code already in their inbox still works — being
    # sent back to the email step would mean a second, pointless email.
    assert _hidden(retry.text)["challenge_id"] == hidden["challenge_id"]
    assert len(outbox) == 1

    good = client.post(
        "/oauth/authorize",
        data={**hidden, "step": "code", "code": _code_from(outbox)},
        follow_redirects=False,
    )
    assert good.status_code == 302


def test_a_rejected_address_does_not_lose_the_oauth_request(client, outbox):
    _verifier, challenge = _pkce()
    page = client.get("/oauth/authorize", params=_authorize_params(challenge))
    bad = client.post(
        "/oauth/authorize",
        data={**_hidden(page.text), "step": "email", "email": "not-an-address"},
    )
    assert bad.status_code == 400
    assert outbox == []
    for key, value in _authorize_params(challenge).items():
        assert _hidden(bad.text)[key] == value


def test_the_token_form_stays_reachable(client, outbox):
    """Mail delivery going down must not take the connector flow with it."""
    _verifier, challenge = _pkce()
    page = client.get(
        "/oauth/authorize", params={**_authorize_params(challenge), "signin": "token"}
    )
    assert page.status_code == 200
    assert 'name="connector_token"' in page.text

    # And the email page offers the way there.
    default = client.get("/oauth/authorize", params=_authorize_params(challenge))
    assert "signin=token" in default.text


def test_closing_self_serve_falls_back_to_the_token_form(client, monkeypatch):
    """An address cannot be proven on a deployment that will not mail anyone,
    so the page must not offer to try."""
    monkeypatch.setenv("CRA_SIGNUP_ENABLED", "0")
    _verifier, challenge = _pkce()
    page = client.get("/oauth/authorize", params=_authorize_params(challenge))
    assert 'name="connector_token"' in page.text
    assert 'name="email"' not in page.text


def test_a_forged_challenge_id_cannot_authorize(client, outbox):
    """The challenge id is not a secret — the browser that asked for the code
    has it, and so does an attacker who typed someone else's address."""
    _verifier, challenge = _pkce()
    page = client.get("/oauth/authorize", params=_authorize_params(challenge))
    sent = client.post(
        "/oauth/authorize",
        data={**_hidden(page.text), "step": "email", "email": _email()},
    )
    hidden = {**_hidden(sent.text), "challenge_id": str(uuid.uuid4())}

    forged = client.post(
        "/oauth/authorize",
        data={**hidden, "step": "code", "code": _code_from(outbox)},
        follow_redirects=False,
    )
    assert forged.status_code == 401


def test_the_client_name_cannot_inject_into_the_consent_page(client):
    """Client names come from dynamic client registration, which is open."""
    registered = client.post(
        "/oauth/register",
        json={
            "client_name": '<img src=x onerror="alert(1)">',
            "redirect_uris": [REDIRECT],
        },
    )
    assert registered.status_code in (200, 201)
    client_id = registered.json()["client_id"]

    _verifier, challenge = _pkce()
    page = client.get(
        "/oauth/authorize",
        params={**_authorize_params(challenge), "client_id": client_id},
    )
    # The name is rendered, but as text: no tag survives, and neither does the
    # quote that would break out of an attribute.
    assert '<img src=x onerror="alert(1)">' not in page.text
    assert "<img" not in page.text
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in page.text
