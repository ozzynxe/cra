"""Verify JWTs from an external identity provider and cache the user locally.

The provider issues HS256 tokens carrying a user id claim. Configuration is
entirely environmental — `SKARP_JWT_SECRET` for the signing key and
`SKARP_AUTH_ME_URL` for the profile endpoint — and this module holds no
credential of its own.

**Symmetric signing means the verifying secret is also a signing secret.** An
HS256 key that can check a token can mint one, so anything with read access to
this service's environment can forge identities for the issuer, not just for
this service. That is a property of the algorithm rather than of this code, and
it is the reason the key belongs only in the environment, is never logged, and
is not shared with any component that does not need to verify.

On first sight of a user, profile metadata is fetched once and cached in the
local `users` table; later verifications read only that cache.

Independent of HTTP — `oauth.py` wraps `verify_token()` and `get_user()`.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from cra.db import User, session_scope

log = logging.getLogger(__name__)


JWT_ALGORITHM = "HS256"
SKARP_AUTH_ME_DEFAULT = "https://api-creator.skarp.app/auth/me"


class SsoError(Exception):
    pass


class JwtInvalid(SsoError):
    pass


class JwtExpired(SsoError):
    pass


class SkarpUnreachable(SsoError):
    pass


@dataclass
class VerifiedToken:
    user_id: str
    raw_claims: dict


def _secret() -> str:
    s = os.environ.get("SKARP_JWT_SECRET")
    if not s:
        raise SsoError("SKARP_JWT_SECRET is not set")
    return s


def verify_token(token: str) -> VerifiedToken:
    """Verify a Skarp-issued JWT. Returns user_id + raw claims, or raises."""
    secret = _secret()
    try:
        claims = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as e:
        raise JwtExpired(str(e)) from e
    except jwt.InvalidTokenError as e:
        raise JwtInvalid(str(e)) from e

    user_id = claims.get("userId") or claims.get("user_id") or claims.get("sub")
    if not user_id:
        raise JwtInvalid("token missing userId claim")
    return VerifiedToken(user_id=str(user_id), raw_claims=claims)


def get_user(user_id: str) -> Optional[User]:
    """Read our cached user. None if not yet seen."""
    with session_scope() as s:
        u = s.scalar(select(User).where(User.id == user_id))
        if u is not None:
            # detach so the caller can read attrs after session closes
            s.expunge(u)
        return u


def fetch_user_from_skarp(token: str, *, base_url: Optional[str] = None, timeout_s: float = 5.0) -> dict:
    """Call Skarp's /auth/me with the user's own JWT. Returns the JSON body."""
    url = base_url or os.environ.get("SKARP_AUTH_ME_URL") or SKARP_AUTH_ME_DEFAULT
    try:
        r = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout_s,
        )
    except httpx.HTTPError as e:
        raise SkarpUnreachable(f"could not reach skarp /auth/me: {e}") from e
    if r.status_code != 200:
        raise SkarpUnreachable(f"skarp /auth/me returned {r.status_code}: {r.text[:200]}")
    return r.json()


def upsert_user_from_skarp_profile(profile: dict, user_id: Optional[str] = None) -> User:
    """Insert-or-update a user row based on Skarp's profile JSON.

    Expected profile shape (from Skarp's /auth/me):
        { "id": "<uuid>", "email": "...", "username": "..." }
    """
    uid = user_id or profile.get("id")
    if not uid:
        raise SsoError("profile missing id")
    email = profile.get("email")
    if not email:
        raise SsoError("profile missing email")
    display_name = profile.get("username") or profile.get("display_name") or profile.get("name")
    now = datetime.now(timezone.utc)

    with session_scope() as s:
        # Postgres-flavored ON CONFLICT upsert
        stmt = (
            pg_insert(User.__table__)
            .values(id=uid, email=email, display_name=display_name, last_seen_at=now)
            .on_conflict_do_update(
                index_elements=[User.__table__.c.id],
                set_={
                    "email": email,
                    "display_name": display_name,
                    "last_seen_at": now,
                },
            )
        )
        s.execute(stmt)
        u = s.scalar(select(User).where(User.id == uid))
        assert u is not None
        s.expunge(u)
        return u


def verify_and_upsert(token: str, *, fetch_profile: bool = True) -> User:
    """Verify a JWT, ensure the user exists locally, return the User row.

    If `fetch_profile=True` and the user is unknown to us, calls Skarp's
    /auth/me with the JWT to populate email/display_name. If False, raises
    SsoError when the user is unknown — caller is responsible for providing
    the profile (e.g. via a callback that received it from the SPA).
    """
    verified = verify_token(token)
    existing = get_user(verified.user_id)
    if existing is not None:
        # Touch last_seen_at on every verify so we get useful telemetry
        with session_scope() as s:
            s.query(User).filter(User.id == verified.user_id).update(
                {User.last_seen_at: datetime.now(timezone.utc)}
            )
        return existing

    if not fetch_profile:
        raise SsoError(f"unknown user_id {verified.user_id}; profile fetch disabled")

    profile = fetch_user_from_skarp(token)
    return upsert_user_from_skarp_profile(profile, user_id=verified.user_id)
