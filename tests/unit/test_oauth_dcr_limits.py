"""Unit tests for the OAuth DCR memory-exhaustion defences.

Locks the rate-limit rule and the in-memory cap/eviction logic for
`_clients` and `_codes` so a future regression can't accidentally re-open
the unbounded-write surface an anonymous attacker can otherwise exploit.

Pure unit tests — no Redis, no DB, no live HTTP.
"""

from __future__ import annotations

import os
import time

import pytest

from cra.server import oauth
from cra.server import rate_limit as rl


# ---- rate-limit rule lookup -----------------------------------------------


def test_dcr_rule_present_in_default_rules():
    """The `/oauth/register` rule must be in DEFAULT_RULES — without it the
    in-memory `_clients` dict is wide open to flood."""
    matches = [r for r in rl.DEFAULT_RULES if r.name == "oauth-dcr"]
    assert len(matches) == 1
    rule = matches[0]
    assert rule.method == "POST"
    assert rule.path_re.match("/oauth/register") is not None
    # Must NOT match other auth endpoints to avoid double-counting.
    assert rule.path_re.match("/api/auth/register") is None
    assert rule.window_seconds == 3600


# ---- _gc_clients: TTL + soft cap ------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_oauth_state():
    """Snapshot + restore the auth-code dict so tests don't leak into each
    other. `_clients` is no longer a dict — registrations live in Postgres
    since they had to survive a restart — so the client-side GC tests below
    need a database and clean up after themselves."""
    saved_codes = dict(oauth._codes)
    oauth._codes.clear()
    try:
        yield
    finally:
        oauth._codes.clear()
        oauth._codes.update(saved_codes)


_NEEDS_DB = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)


def _add_client(name: str, issued_offset: int = 0) -> None:
    from datetime import datetime, timedelta, timezone

    from cra.db import session_scope
    from cra.db.models import OAuthClient

    with session_scope() as db:
        db.merge(
            OAuthClient(
                client_id=name,
                client_name=name,
                redirect_uris=[],
                issued_at=datetime.now(timezone.utc) + timedelta(seconds=issued_offset),
            )
        )


def _client_ids() -> set:
    from cra.db import session_scope
    from cra.db.models import OAuthClient

    with session_scope() as db:
        return {r.client_id for r in db.query(OAuthClient).all()}


@pytest.fixture
def _no_clients():
    """The GC operates on the whole table, so these tests need it empty."""
    from cra.db import session_scope
    from cra.db.models import OAuthClient

    with session_scope() as db:
        db.query(OAuthClient).delete()
    yield
    with session_scope() as db:
        db.query(OAuthClient).delete()


@_NEEDS_DB
def test_gc_clients_drops_expired_entries(_no_clients):
    _add_client("fresh")
    _add_client("stale", issued_offset=-oauth._CLIENT_TTL - 60)
    oauth._gc_clients()
    ids = _client_ids()
    assert "fresh" in ids
    assert "stale" not in ids


@_NEEDS_DB
def test_gc_clients_evicts_oldest_when_over_cap(monkeypatch, _no_clients):
    monkeypatch.setattr(oauth, "_MAX_CLIENTS", 3)
    # All in-TTL; oldest by issued_at must go first.
    for i, name in enumerate(["oldest", "older", "old", "new"]):
        _add_client(name, issued_offset=-100 + i)
    oauth._gc_clients()
    ids = _client_ids()
    assert "oldest" not in ids
    assert len(ids) == oauth._MAX_CLIENTS - 1


# ---- _gc_codes: TTL + hard cap --------------------------------------------


def test_gc_codes_drops_expired_entries():
    now = time.time()
    oauth._codes["fresh"] = {"created_at": now, "client_id": "c", "redirect_uri": "u"}
    oauth._codes["stale"] = {
        "created_at": now - oauth._CODE_TTL - 1,
        "client_id": "c",
        "redirect_uri": "u",
    }
    oauth._gc_codes()
    assert "fresh" in oauth._codes
    assert "stale" not in oauth._codes


def test_gc_codes_evicts_oldest_when_over_cap(monkeypatch):
    monkeypatch.setattr(oauth, "_MAX_CODES", 3)
    now = time.time()
    for i, name in enumerate(["oldest", "older", "old", "new"]):
        oauth._codes[name] = {
            "created_at": now - 50 + i,
            "client_id": "c",
            "redirect_uri": "u",
        }
    oauth._gc_codes()
    assert "oldest" not in oauth._codes
    assert len(oauth._codes) == oauth._MAX_CODES - 1


# ---- register() is wired to _gc_clients -----------------------------------


@_NEEDS_DB
def test_register_calls_gc_clients_before_insert(monkeypatch):
    """Defence-in-depth: even if the rate-limit middleware is bypassed (e.g.
    Redis is down and we fail open), the register handler itself must sweep
    the table so it cannot grow without bound.

    The assertion is that the sweep runs *before* the insert — counting rows
    inside the tracker and comparing afterwards is what proves the ordering."""
    calls: list[int] = []
    real_gc = oauth._gc_clients

    def tracking_gc():
        calls.append(len(_client_ids()))
        real_gc()

    monkeypatch.setattr(oauth, "_gc_clients", tracking_gc)

    from starlette.requests import Request
    import asyncio
    import json

    async def _drive():
        # Forge a minimal ASGI scope. The handler only reads body + responds.
        body_bytes = json.dumps(
            {
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "client_name": "test",
            }
        ).encode("utf-8")
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/oauth/register",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
        }

        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        request = Request(scope, receive)
        await oauth.register(request)

    asyncio.run(_drive())
    assert calls, "register() must call _gc_clients before inserting"
