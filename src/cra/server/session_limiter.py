"""Per-user concurrent MCP session cap.

Counts the number of active MCP sessions a user has at once. A "session" =
a unique `mcp-session-id` header value seen with that user's connector token.
Sessions idle out after `IDLE_SECONDS` of no activity (default 60s).

The cap (`CRA_MAX_CONCURRENT_SESSIONS`, default 4) protects against:
- A user accidentally leaving multiple agents connected (background drain)
- An agent stuck in a tool-call loop being multiplied N× by N parallel sessions
- Deliberate abuse — spinning up many agents to pound on a single doc

Hitting the cap returns 429 with a clear message; the user disconnects an
unused connector and retries.

State is **in-memory** — does NOT survive container restart, and does NOT
scale across multiple app containers. For a multi-instance deployment, swap
the dict for Redis (`SETEX` per session id with TTL=IDLE_SECONDS, `SCARD`
to count).

The legacy `tok_a_*` / `tok_b_*` static-bearer path doesn't go through this
limiter — those tokens have no associated user id and are only used for
demos. Only `coauth_*` user-attributable tokens are tracked.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger(__name__)


# A session with no traffic in this many seconds is considered dead and is
# evicted from the count. Tuned to be longer than typical MCP keepalive
# gaps (which are sub-second) but short enough that a forgotten browser tab
# frees up a slot within a minute or two.
IDLE_SECONDS = 60


def _max_concurrent() -> int:
    raw = os.environ.get("CRA_MAX_CONCURRENT_SESSIONS", "4")
    try:
        n = int(raw)
    except ValueError:
        log.warning(
            "CRA_MAX_CONCURRENT_SESSIONS=%r is not an int; defaulting to 4", raw
        )
        return 4
    return max(0, n)  # 0 disables the cap entirely


class SessionLimiter:
    """Tracks active sessions per user.

    Two operations:
      `check_and_track(user_id, session_id)` → (allowed, count, limit)
      `stats()` → small dict for debugging
    """

    def __init__(self) -> None:
        # user_id -> { session_id -> last_seen_datetime }
        self._sessions: dict[str, dict[str, datetime]] = {}
        self._lock = threading.Lock()

    def _sweep(self, user_id: str, now: datetime) -> None:
        """Remove stale sessions for one user. Caller must hold the lock."""
        sessions = self._sessions.get(user_id)
        if not sessions:
            return
        threshold = now - timedelta(seconds=IDLE_SECONDS)
        dead = [sid for sid, ts in sessions.items() if ts < threshold]
        for sid in dead:
            del sessions[sid]
        if not sessions:
            self._sessions.pop(user_id, None)

    def check_and_track(
        self, user_id: str, session_id: Optional[str]
    ) -> tuple[bool, int, int]:
        """Track activity and check the cap.

        Returns (allowed, current_count, limit). If `allowed` is False, the
        caller should reject the request with 429.

        - If `session_id` is None (e.g. the initial `initialize` call before
          FastMCP has assigned an id), we only check the count — we don't add
          anything yet. The session will be tracked on its first follow-up
          request that carries the id.
        - If `session_id` is already known, we touch it (update last_seen)
          and allow regardless of cap.
        - If `session_id` is new and we're at the cap, we reject without
          tracking it.
        """
        limit = _max_concurrent()
        if limit == 0:  # cap disabled
            return True, 0, 0
        now = datetime.now(timezone.utc)
        with self._lock:
            self._sweep(user_id, now)
            user_sessions = self._sessions.setdefault(user_id, {})

            # No session id yet — just count, don't track.
            if session_id is None:
                count = len(user_sessions)
                return count < limit, count, limit

            # Existing session — touch and allow.
            if session_id in user_sessions:
                user_sessions[session_id] = now
                return True, len(user_sessions), limit

            # New session — gate on the cap.
            if len(user_sessions) >= limit:
                return False, len(user_sessions), limit
            user_sessions[session_id] = now
            return True, len(user_sessions), limit

    def stats(self) -> dict:
        with self._lock:
            return {
                "users_tracked": len(self._sessions),
                "total_sessions": sum(len(s) for s in self._sessions.values()),
                "limit": _max_concurrent(),
                "idle_seconds": IDLE_SECONDS,
            }


# Module-level singleton — lives for the lifetime of the app container.
_limiter = SessionLimiter()


def check_and_track(user_id: str, session_id: Optional[str]) -> tuple[bool, int, int]:
    return _limiter.check_and_track(user_id, session_id)


def stats() -> dict:
    return _limiter.stats()


# Test hook — clears all tracked sessions. Production code should never call this.
def _reset_for_testing() -> None:
    with _limiter._lock:
        _limiter._sessions.clear()
