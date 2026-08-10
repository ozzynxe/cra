"""Browser sessions for the console. The only stateful auth in this service.

Everything else here is deliberately sessionless — `/access`, the OAuth consent
page and `/billing` each carry their intent through one email-and-code exchange
and remember nothing. That is right for a one-shot act and wrong for somebody
reading their compliance state, who clicks between pages for half an hour.

## The shape

    start(email) -> code, mailed        (signup.PURPOSE_LOGIN)
    complete(challenge, code) -> cookie value
    resolve(cookie value) -> user_id or None
    revoke(cookie value) / revoke_all(user_id)

No passwords, same as everywhere else. The cookie carries `<id>.<secret>` and
only the sha256 is stored, so a database dump contains nothing replayable.

## Two expiries

`expires_at` slides forward as the session is used; `hard_expires_at` does not.
A session that renewed itself forever would be a permanent credential wearing a
cookie, which is the thing an expiry is supposed to prevent.

## Why revocable at all

Because this reads unreported exploited-vulnerability records. A signed
stateless cookie can carry an expiry but cannot be withdrawn, so "I lost my
laptop" would have no answer short of rotating a global secret and logging
everybody out. A row can be deleted.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select

from cra.db import WebSession, session_scope

log = logging.getLogger(__name__)

COOKIE = "cra_session"
# Deliberately not `coauthor_session`. That name is still live in `sso.py` and
# `oauth.py` for the inherited Coauthor path; sharing it would mean one
# service's logout silently ending the other's session.

_IDLE_DAYS = 14
_HARD_DAYS = 90
# Don't write to the database on every page view just to move a timestamp a few
# seconds. Only slide the expiry when it has actually aged.
_REFRESH_AFTER = timedelta(hours=12)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def issue(user_id: str) -> str:
    """Mint a session and return the cookie value. Always a fresh row.

    Never reuses an id across logins: reusing one would let a cookie captured
    before a login keep working after it, which is session fixation.
    """
    secret = secrets.token_urlsafe(32)
    now = _now()
    with session_scope() as db:
        row = WebSession(
            user_id=user_id,
            secret_sha256=_hash(secret),
            expires_at=now + timedelta(days=_IDLE_DAYS),
            hard_expires_at=now + timedelta(days=_HARD_DAYS),
            last_seen_at=now,
        )
        db.add(row)
        db.flush()
        sid = row.id
    log.info("console session issued for %s", user_id)
    return f"{sid}.{secret}"


def resolve(cookie_value: Optional[str]) -> Optional[str]:
    """The user this cookie belongs to, or None.

    One answer for every failure — absent, malformed, forged, expired, revoked.
    A caller learning *which* would learn whether a session id exists, and the
    only use for that is deciding what to attack next.
    """
    raw = (cookie_value or "").strip()
    sid, _, secret = raw.partition(".")
    if not sid or not secret:
        return None
    try:
        uuid.UUID(sid)
    except ValueError:
        return None

    now = _now()
    with session_scope() as db:
        row = db.get(WebSession, sid)
        if row is None or not secrets.compare_digest(row.secret_sha256, _hash(secret)):
            return None
        if row.revoked_at is not None:
            return None
        if row.expires_at <= now or row.hard_expires_at <= now:
            return None

        if row.last_seen_at is None or (now - row.last_seen_at) > _REFRESH_AFTER:
            row.last_seen_at = now
            # Slide, but never past the hard cap.
            row.expires_at = min(
                now + timedelta(days=_IDLE_DAYS), row.hard_expires_at
            )
        return row.user_id


def revoke(cookie_value: Optional[str]) -> None:
    """End one session. Silent about whether it existed."""
    raw = (cookie_value or "").strip()
    sid, _, _secret = raw.partition(".")
    if not sid:
        return
    try:
        uuid.UUID(sid)
    except ValueError:
        return
    with session_scope() as db:
        row = db.get(WebSession, sid)
        if row is not None and row.revoked_at is None:
            row.revoked_at = _now()


def revoke_all(user_id: str) -> int:
    """End every session for an account. Returns how many were live.

    The answer to "I lost my laptop", and the reason these are rows.
    """
    now = _now()
    with session_scope() as db:
        rows = list(
            db.execute(
                select(WebSession).where(
                    WebSession.user_id == user_id,
                    WebSession.revoked_at.is_(None),
                    WebSession.expires_at > now,
                )
            ).scalars()
        )
        for row in rows:
            row.revoked_at = now
    log.info("revoked %d console session(s) for %s", len(rows), user_id)
    return len(rows)


def cookie_kwargs(*, secure: bool = True) -> dict:
    """Flags for `set_cookie`. `secure=False` only for local http testing."""
    return {
        "httponly": True,      # no script can read it; there is no script anyway
        "secure": secure,      # https only
        "samesite": "lax",     # blocks cross-site POSTs while allowing normal links
        "path": "/",
        "max_age": _IDLE_DAYS * 24 * 3600,
    }
