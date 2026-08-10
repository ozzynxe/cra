"""Unit tests for the per-user concurrent MCP session cap."""

from __future__ import annotations

import time

import pytest

from cra.server import session_limiter


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    """Each test starts with a clean limiter and a known cap."""
    monkeypatch.setenv("CRA_MAX_CONCURRENT_SESSIONS", "4")
    session_limiter._reset_for_testing()
    yield
    session_limiter._reset_for_testing()


def test_under_cap_allows_new_sessions():
    for i in range(4):
        allowed, count, limit = session_limiter.check_and_track(
            "user-1", f"session-{i}"
        )
        assert allowed is True
        assert count == i + 1
        assert limit == 4


def test_over_cap_rejects_new_session():
    for i in range(4):
        session_limiter.check_and_track("user-1", f"session-{i}")
    allowed, count, limit = session_limiter.check_and_track("user-1", "session-5")
    assert allowed is False
    assert count == 4
    assert limit == 4


def test_existing_session_always_allowed_even_at_cap():
    for i in range(4):
        session_limiter.check_and_track("user-1", f"session-{i}")
    # Touching session-0 again must not count as a new session, must succeed.
    allowed, count, _ = session_limiter.check_and_track("user-1", "session-0")
    assert allowed is True
    assert count == 4


def test_per_user_isolation():
    for i in range(4):
        session_limiter.check_and_track("user-1", f"session-{i}")
    # user-2 starts at zero — fully independent.
    allowed, count, _ = session_limiter.check_and_track("user-2", "session-a")
    assert allowed is True
    assert count == 1


def test_idle_timeout_releases_slot(monkeypatch):
    # Fill the cap with sessions whose last_seen is back-dated past IDLE_SECONDS.
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    stale = now - timedelta(seconds=session_limiter.IDLE_SECONDS + 5)
    with session_limiter._limiter._lock:
        session_limiter._limiter._sessions["user-1"] = {
            f"old-{i}": stale for i in range(4)
        }
    # A new request should now sweep the stale entries and let us in.
    allowed, count, _ = session_limiter.check_and_track("user-1", "fresh-session")
    assert allowed is True
    assert count == 1


def test_no_session_id_only_checks_count():
    # initialize-style call: session_id is None until FastMCP assigns one.
    for i in range(4):
        session_limiter.check_and_track("user-1", f"session-{i}")
    # An initialize call (session_id=None) at the cap is rejected without
    # adding to the count.
    allowed, count, _ = session_limiter.check_and_track("user-1", None)
    assert allowed is False
    assert count == 4
    # And we didn't accidentally track None.
    s = session_limiter.stats()
    assert s["total_sessions"] == 4


def test_cap_zero_disables_limiter(monkeypatch):
    monkeypatch.setenv("CRA_MAX_CONCURRENT_SESSIONS", "0")
    for i in range(50):
        allowed, _, limit = session_limiter.check_and_track("user-1", f"s-{i}")
        assert allowed is True
        assert limit == 0


def test_invalid_env_falls_back_to_4(monkeypatch):
    monkeypatch.setenv("CRA_MAX_CONCURRENT_SESSIONS", "not-a-number")
    for i in range(4):
        allowed, _, limit = session_limiter.check_and_track("user-1", f"s-{i}")
        assert allowed is True
        assert limit == 4
    allowed, count, _ = session_limiter.check_and_track("user-1", "s-5")
    assert allowed is False
    assert count == 4
