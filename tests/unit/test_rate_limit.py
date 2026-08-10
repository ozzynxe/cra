"""Unit tests for the per-IP rate-limit middleware (Phase 12.5).

Stubs Redis with an in-memory dict so the suite stays runnable without a live
Redis. Covers:
  - rule matching by method + path
  - limit enforcement (429 after the threshold)
  - window expiry (counter resets)
  - X-Forwarded-For client IP extraction
  - fail-open on Redis errors
  - shadow mode (`CRA_RATE_LIMIT_OFF=1` counts but doesn't enforce)
  - env-based limit override
"""

from __future__ import annotations

import re
from typing import Optional

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from cra.server import rate_limit as rl


# ---- in-memory redis stub ---------------------------------------------------


class FakeRedis:
    """Minimal stand-in for redis-py — enough for the middleware's INCR /
    EXPIRE / TTL surface. No actual TTL clock; tests advance state by
    calling `expire_key()` directly."""

    def __init__(self):
        self._counts: dict[str, int] = {}
        self._ttls: dict[str, int] = {}
        self.fail_next = False  # set True to simulate a Redis error

    def incr(self, key: str) -> int:
        if self.fail_next:
            self.fail_next = False
            raise ConnectionError("simulated redis down")
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    def ttl(self, key: str) -> Optional[int]:
        return self._ttls.get(key)

    def expire_key(self, key: str) -> None:
        """Test helper — pretend the window elapsed."""
        self._counts.pop(key, None)
        self._ttls.pop(key, None)


@pytest.fixture
def fake_redis(monkeypatch):
    """Patch the module-level redis getter to return a per-test FakeRedis."""
    fake = FakeRedis()
    monkeypatch.setattr(rl, "_get_redis", lambda: fake)
    monkeypatch.setattr(rl, "_REDIS_CLIENT", fake)
    return fake


# ---- test app builder -------------------------------------------------------


def _hello(_request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


def _build_test_app(rules=None) -> Starlette:
    """A tiny Starlette app with the rate-limit middleware mounted in front
    of a single endpoint at every path we care about."""
    return Starlette(
        routes=[
            Route("/api/discover", _hello, methods=["GET"]),
            Route("/api/documents/{document_id}", _hello, methods=["GET"]),
            Route("/api/documents", _hello, methods=["POST"]),
            Route("/api/auth/register", _hello, methods=["POST"]),
            Route("/api/documents/{document_id}/comments", _hello, methods=["POST"]),
            Route("/api/somethingelse", _hello, methods=["GET"]),
        ],
        middleware=[Middleware(rl.RateLimitMiddleware, rules=rules)],
    )


# ---- rule matching ----------------------------------------------------------


def test_rule_matches_method_and_path():
    rule = rl.RateLimitRule(
        name="t",
        method="POST",
        path_re=re.compile(r"^/foo$"),
        limit_default=1,
        limit_env="X",
        window_seconds=60,
    )
    mw = rl.RateLimitMiddleware(app=None, rules=[rule])

    class _R:
        def __init__(self, method, path):
            self.method = method
            self.url = type("U", (), {"path": path})()

    assert mw._match_rule(_R("POST", "/foo")) is rule
    assert mw._match_rule(_R("GET", "/foo")) is None  # method mismatch
    assert mw._match_rule(_R("POST", "/bar")) is None  # path mismatch


def test_unmatched_path_passes_through(fake_redis):
    """Endpoints not in the rule table aren't rate-limited."""
    client = TestClient(_build_test_app())
    for _ in range(500):
        r = client.get("/api/somethingelse")
        assert r.status_code == 200
    # No keys were touched
    assert fake_redis._counts == {}


# ---- enforcement ------------------------------------------------------------


def test_under_limit_passes(fake_redis):
    client = TestClient(_build_test_app())
    for _ in range(5):
        r = client.get("/api/discover")
        assert r.status_code == 200
        assert r.headers["X-RateLimit-Limit"] == "60"
    assert int(fake_redis._counts["coauthor:rl:anon-read-discover:testclient"]) == 5


def test_over_limit_returns_429(fake_redis):
    client = TestClient(_build_test_app())
    # Hit auth-register's 5/hour limit
    for i in range(5):
        r = client.post("/api/auth/register", json={})
        assert r.status_code == 200, f"req {i}: {r.text}"
    # 6th request should 429
    r = client.post("/api/auth/register", json={})
    assert r.status_code == 429
    body = r.json()
    assert body["code"] == "rate_limited"
    assert body["retry_after_seconds"] > 0
    assert r.headers["Retry-After"] == str(body["retry_after_seconds"])
    assert r.headers["X-RateLimit-Remaining"] == "0"


def test_window_reset_lets_traffic_through(fake_redis):
    """After the window expires, the counter resets and traffic flows."""
    client = TestClient(_build_test_app())
    for _ in range(5):
        client.post("/api/auth/register", json={})
    assert client.post("/api/auth/register", json={}).status_code == 429

    # Simulate window roll-over.
    fake_redis.expire_key("coauthor:rl:auth-register:testclient")
    assert client.post("/api/auth/register", json={}).status_code == 200


def test_remaining_header_decrements(fake_redis):
    client = TestClient(_build_test_app())
    r1 = client.get("/api/discover")
    r2 = client.get("/api/discover")
    assert int(r1.headers["X-RateLimit-Remaining"]) > int(r2.headers["X-RateLimit-Remaining"])


# ---- IP extraction ----------------------------------------------------------


def test_xforwarded_for_used_for_bucket(fake_redis):
    """Different X-Forwarded-For values get separate buckets — so two real
    clients behind the same Caddy proxy don't share a counter."""
    client = TestClient(_build_test_app())
    client.get("/api/discover", headers={"X-Forwarded-For": "1.2.3.4"})
    client.get("/api/discover", headers={"X-Forwarded-For": "5.6.7.8"})
    keys = list(fake_redis._counts.keys())
    assert "coauthor:rl:anon-read-discover:1.2.3.4" in keys
    assert "coauthor:rl:anon-read-discover:5.6.7.8" in keys


def test_xforwarded_for_chain_uses_first(fake_redis):
    """`X-Forwarded-For: client, proxy1, proxy2` → use 'client'."""
    client = TestClient(_build_test_app())
    client.get("/api/discover", headers={"X-Forwarded-For": "1.2.3.4, 10.0.0.1"})
    assert "coauthor:rl:anon-read-discover:1.2.3.4" in fake_redis._counts


# ---- failure modes ----------------------------------------------------------


def test_fail_open_on_redis_error(fake_redis):
    """If Redis errors, the middleware passes the request through. We'd
    rather serve traffic than 503 every request when the cache is down."""
    fake_redis.fail_next = True
    client = TestClient(_build_test_app())
    r = client.get("/api/discover")
    assert r.status_code == 200  # request succeeded despite Redis error


def test_shadow_mode_counts_but_doesnt_enforce(fake_redis, monkeypatch):
    """`CRA_RATE_LIMIT_OFF=1` should still INCR but not 429."""
    monkeypatch.setenv("CRA_RATE_LIMIT_OFF", "1")
    client = TestClient(_build_test_app())
    for _ in range(20):  # auth-register limit is 5
        r = client.post("/api/auth/register", json={})
        assert r.status_code == 200
    # Counts still incremented — useful for tuning thresholds
    assert fake_redis._counts["coauthor:rl:auth-register:testclient"] == 20


# ---- env-overridable limits -------------------------------------------------


def test_env_override_changes_limit(fake_redis, monkeypatch):
    monkeypatch.setenv("CRA_RL_DISCOVER_PER_MIN", "2")
    client = TestClient(_build_test_app())
    assert client.get("/api/discover").status_code == 200
    assert client.get("/api/discover").status_code == 200
    assert client.get("/api/discover").status_code == 429


def test_env_override_invalid_falls_back_to_default(fake_redis, monkeypatch):
    monkeypatch.setenv("CRA_RL_DISCOVER_PER_MIN", "not-a-number")
    rule = next(r for r in rl.DEFAULT_RULES if r.name == "anon-read-discover")
    assert rule.limit() == 60  # default
