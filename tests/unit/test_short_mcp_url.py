"""`https://<host>/mcp` — the URL people actually guess.

It used to 404. That is the worst shape a connector failure can take: the
client reports nothing useful, the server logs nothing at all, and the user has
no way to tell a wrong URL from a broken service. A connector in this project's
own account was pointed at it and failed exactly that way.

The mount that fixes it sits last and matches a prefix, so the thing to guard
is precedence: if `Mount("/mcp")` ever moves above the others it silently
swallows `/mcp/me/mcp` and every product-scoped mount with it, and everything
would still appear to work — one shared user-wide session serving requests that
were meant to be scoped to a product.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from cra.server.http_app import build_app  # noqa: E402

BODY = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}


@pytest.fixture(scope="module")
def client():
    # No lifespan: these assertions are about routing and auth, both of which
    # run before the session manager is ever consulted.
    return TestClient(build_app())


@pytest.mark.parametrize("path", ["/mcp", "/mcp/me/mcp"])
def test_both_urls_reach_the_mcp_surface(client, path):
    """401, not 404. The distinction is the whole point: 401 means the mount is
    there and wants credentials; 404 means the URL is wrong."""
    r = client.post(path, json=BODY)
    assert r.status_code == 401, f"{path} returned {r.status_code}"


@pytest.mark.parametrize("path", ["/mcp", "/mcp/me/mcp"])
def test_both_urls_say_where_to_authenticate(client, path):
    r = client.post(path, json=BODY)
    assert "resource_metadata=" in r.headers.get("WWW-Authenticate", "")


def test_the_short_url_does_not_shadow_the_product_scoped_mounts(client):
    """The scoped mounts must still route. A prefix `Mount("/mcp")` would have
    swallowed them with nothing looking broken — one shared user-wide session
    quietly serving requests meant to be scoped to a product. The rewrite
    cannot do that: it only fires on an exact match."""
    assert client.post("/mcp/some-product-id/mcp", json=BODY).status_code == 401

    paths = [getattr(r, "path", "") for r in build_app().routes]
    assert "/mcp" not in paths, (
        "bare /mcp should be a rewrite, not a mount — a prefix mount here "
        f"shadows every scoped route: {[p for p in paths if p.startswith('/mcp')]}"
    )


def test_the_rewrite_only_fires_on_an_exact_match():
    """`/mcpanything` and `/mcp/me/mcp` must be left alone."""
    from cra.server.http_app import ShortMcpPath

    seen = []

    async def sink(scope, receive, send):
        seen.append(scope["path"])

    import asyncio

    for given in ("/mcp", "/mcp/", "/mcp/me/mcp", "/mcpx", "/mcp/prod/mcp", "/health"):
        asyncio.run(ShortMcpPath(sink)({"type": "http", "path": given}, None, None))

    assert seen == [
        "/mcp/me/mcp",   # rewritten
        "/mcp/me/mcp",   # rewritten
        "/mcp/me/mcp",   # already correct, untouched
        "/mcpx",
        "/mcp/prod/mcp",
        "/health",
    ]


def test_the_short_url_is_not_a_redirect(client):
    """A 307 would work for clients that follow redirects on POST and fail
    quietly for those that do not. This is a real endpoint."""
    r = client.post("/mcp", json=BODY, follow_redirects=False)
    assert r.status_code == 401
    assert "location" not in {k.lower() for k in r.headers}


def test_unrelated_paths_are_still_not_found(client):
    """The short mount matches a prefix; it must not have become a catch-all
    that answers 401 for everything."""
    r = client.get("/definitely-not-a-route")
    assert r.status_code == 404
