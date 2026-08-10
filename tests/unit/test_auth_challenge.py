"""Every 401 from an MCP mount must say where to authenticate.

This is the failure mode with no symptom. A client that gets a bare 401 has
nowhere to go: RFC 9728 and the MCP authorization spec both have it read
`resource_metadata` off `WWW-Authenticate` to find the authorization server.
Without the header it gives up quietly — no browser, no prompt, no email — and
the connector simply never works, with nothing in the application log to say
why. The deploy smoke test asserts the status code is 401, which stayed true
the whole time the header was missing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from cra.server.auth import PartyAuthMiddleware  # noqa: E402


def _client(party: str = "me") -> TestClient:
    app = Starlette(
        routes=[Route("/mcp", lambda r: PlainTextResponse("reached"), methods=["GET", "POST"])],
        middleware=[Middleware(PartyAuthMiddleware, party_id=party)],
    )
    return TestClient(app)


@pytest.mark.parametrize("party", ["me", "dynamic"])
def test_the_401_body_does_not_name_the_product_this_was_forked_from(party):
    """The error code is the first thing any new client is told.

    It read `coauth_required` until 2026-08-08 — the name of the product this
    was forked from, in the one response every unauthenticated caller sees,
    served publicly. Nothing tested it, so it survived the rename of everything
    else and was still live in production months later.

    Pinned as a string rather than by absence of one word: a code is wire
    contract, and changing it is a decision to make deliberately.
    """
    r = _client(party).post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 401
    assert r.json()["code"] == "connector_token_required"
    assert "coauth" not in r.text.lower()


@pytest.mark.parametrize("party", ["me", "dynamic"])
def test_an_unauthenticated_call_is_told_where_to_authenticate(party):
    r = _client(party).post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 401
    challenge = r.headers.get("WWW-Authenticate")
    assert challenge, "401 with no WWW-Authenticate — the client has nowhere to go"
    assert "Bearer" in challenge
    assert "resource_metadata=" in challenge


def test_the_advertised_metadata_url_is_the_one_rfc_9728_defines():
    r = _client().post("/mcp", json={})
    url = re.search(r'resource_metadata="([^"]+)"', r.headers["WWW-Authenticate"]).group(1)
    assert url.endswith("/.well-known/oauth-protected-resource")


def test_the_origin_follows_the_forwarded_headers_caddy_sets():
    """Behind a proxy the app sees http and an internal host. Advertising that
    would send the client to a URL it cannot reach."""
    r = _client().post(
        "/mcp",
        json={},
        headers={"x-forwarded-proto": "https", "x-forwarded-host": "cra.skarp.app"},
    )
    challenge = r.headers["WWW-Authenticate"]
    assert 'resource_metadata="https://cra.skarp.app/.well-known/oauth-protected-resource"' in challenge
    assert "http://" not in challenge


def test_a_bad_token_also_gets_the_challenge():
    """Not just the no-credential case: an expired or revoked token is the
    other way a working connector goes quiet, and re-authenticating is exactly
    the right response to it."""
    r = _client().post("/mcp", json={}, headers={"Authorization": "Bearer cra_not_a_real_token"})
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers.get("WWW-Authenticate", "")
