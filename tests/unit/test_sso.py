"""SSO unit tests — JWT verification only (no DB calls).

Live-Postgres tests for `verify_and_upsert` live in tests/integration/test_sso_live.py
and are skipped without a real DATABASE_URL.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest


SECRET = "test-secret-do-not-use-in-prod"


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch):
    monkeypatch.setenv("SKARP_JWT_SECRET", SECRET)


def _mint(claims: dict, secret: str = SECRET) -> str:
    return jwt.encode(claims, secret, algorithm="HS256")


def test_verify_token_happy_path():
    from cra.server import sso

    token = _mint({"userId": "user-uuid-abc"})
    v = sso.verify_token(token)
    assert v.user_id == "user-uuid-abc"
    assert v.raw_claims["userId"] == "user-uuid-abc"


def test_verify_token_with_sub_claim():
    """Some JWT sources put the id under `sub` instead of `userId`. We accept both."""
    from cra.server import sso

    token = _mint({"sub": "user-from-sub"})
    v = sso.verify_token(token)
    assert v.user_id == "user-from-sub"


def test_verify_token_rejects_unsigned():
    from cra.server import sso

    bogus = jwt.encode({"userId": "x"}, "wrong-secret", algorithm="HS256")
    with pytest.raises(sso.JwtInvalid):
        sso.verify_token(bogus)


def test_verify_token_rejects_missing_user_id():
    from cra.server import sso

    token = _mint({"foo": "bar"})
    with pytest.raises(sso.JwtInvalid):
        sso.verify_token(token)


def test_verify_token_rejects_expired():
    from cra.server import sso

    expired_at = int(time.time()) - 10
    token = _mint({"userId": "x", "exp": expired_at})
    with pytest.raises(sso.JwtExpired):
        sso.verify_token(token)


def test_verify_token_missing_secret(monkeypatch):
    from cra.server import sso

    monkeypatch.delenv("SKARP_JWT_SECRET", raising=False)
    with pytest.raises(sso.SsoError):
        sso.verify_token(_mint({"userId": "x"}))
