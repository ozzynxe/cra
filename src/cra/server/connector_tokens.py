"""Per-user (and optionally per-document) bearer tokens for chatbot connectors.

Token format:  ``coauth_<32 url-safe chars>``
- The first 8 chars after the prefix are the lookup index (`prefix` column).
- The full token is bcrypt-hashed into `token_hash`.
- The plaintext token is shown to the user once at mint time and never again.

This module is independent of HTTP. The auth middleware imports `verify_token`
to resolve a presented bearer to (user_id, product_id, role).
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from sqlalchemy import select

from cra.db import ConnectorToken, ProductMember, User, session_scope

log = logging.getLogger(__name__)


TOKEN_PREFIX = os.environ.get("CRA_TOKEN_PREFIX", "cra_")
LOOKUP_PREFIX_CHARS = 8  # how many chars of the random part go into the `prefix` column
RANDOM_CHARS = 32         # length of the random part after `coauth_`


class TokenError(Exception):
    pass


class TokenInvalid(TokenError):
    pass


class TokenRevoked(TokenError):
    pass


class TokenExpired(TokenError):
    pass


@dataclass
class TokenVerification:
    user_id: str
    product_id: Optional[str]
    role: Optional[str]   # role on the scoped product, if product_id is set
    token_id: str


def is_connector_token(presented: str) -> bool:
    """Does this bearer look like one of ours?

    Public because the auth middleware has to make the same judgement, and it
    previously did so with its own hardcoded literal — which is how the prefix
    and its check drifted apart the moment the fork renamed it.
    """
    return presented.startswith(TOKEN_PREFIX)


# Back-compat alias for the private name used elsewhere in this module.
_is_coauth_token = is_connector_token


def _split_prefix(presented: str) -> str:
    """Return the `prefix` column value derived from a presented token."""
    body = presented[len(TOKEN_PREFIX):]
    return body[:LOOKUP_PREFIX_CHARS]


def mint_token(
    *,
    user_id: str,
    product_id: Optional[str] = None,
    label: Optional[str] = None,
) -> tuple[str, ConnectorToken]:
    """Mint a new connector token. Returns (plaintext_token, row).

    The plaintext is shown ONCE; only the bcrypt hash is stored. Caller is
    responsible for surfacing the plaintext to the user (e.g. as the API
    response from POST /api/documents/{id}/connector_tokens).
    """
    body = secrets.token_urlsafe(RANDOM_CHARS)[:RANDOM_CHARS]
    token = f"{TOKEN_PREFIX}{body}"
    prefix = body[:LOOKUP_PREFIX_CHARS]

    token_hash = bcrypt.hashpw(token.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("ascii")

    with session_scope() as s:
        row = ConnectorToken(
            user_id=user_id,
            product_id=product_id,
            label=label,
            token_hash=token_hash,
            prefix=prefix,
        )
        s.add(row)
        s.flush()
        s.refresh(row)
        s.expunge(row)
    return token, row


def verify_token(presented: str) -> TokenVerification:
    """Resolve a presented bearer to user_id (+ product_id + role if scoped).

    Raises TokenInvalid / TokenExpired / TokenRevoked.
    """
    if not _is_coauth_token(presented):
        raise TokenInvalid("not a coauth_* token")
    if len(presented) != len(TOKEN_PREFIX) + RANDOM_CHARS:
        raise TokenInvalid("token length wrong")
    prefix = _split_prefix(presented)

    with session_scope() as s:
        row = s.scalar(select(ConnectorToken).where(ConnectorToken.prefix == prefix))
        if row is None:
            raise TokenInvalid("unknown token prefix")

        if row.revoked_at is not None:
            raise TokenRevoked(f"token revoked at {row.revoked_at}")

        if row.expires_at is not None and row.expires_at < datetime.now(timezone.utc):
            raise TokenExpired(f"token expired at {row.expires_at}")

        if not bcrypt.checkpw(presented.encode("utf-8"), row.token_hash.encode("ascii")):
            raise TokenInvalid("token hash mismatch")

        # Touch last_used_at (cheap, single row)
        row.last_used_at = datetime.now(timezone.utc)
        s.flush()

        # If scoped to a document, look up the role
        role: Optional[str] = None
        if row.product_id is not None:
            mem = s.scalar(
                select(ProductMember).where(
                    ProductMember.product_id == row.product_id,
                    ProductMember.user_id == row.user_id,
                )
            )
            if mem is None:
                # Token is scoped to a doc the user is no longer a member of
                raise TokenInvalid(
                    f"user {row.user_id} is not a member of product {row.product_id}"
                )
            role = mem.role

        return TokenVerification(
            user_id=row.user_id,
            product_id=row.product_id,
            role=role,
            token_id=row.id,
        )


def revoke_token(token_id: str) -> bool:
    """Soft-delete (sets revoked_at). Returns True if the row was updated."""
    with session_scope() as s:
        row = s.scalar(select(ConnectorToken).where(ConnectorToken.id == token_id))
        if row is None:
            return False
        if row.revoked_at is not None:
            return False
        row.revoked_at = datetime.now(timezone.utc)
        return True


def list_tokens_for_user(user_id: str, *, product_id: Optional[str] = None) -> list[dict]:
    """List a user's tokens (no secrets). Optionally scoped to a document."""
    with session_scope() as s:
        q = select(ConnectorToken).where(ConnectorToken.user_id == user_id)
        if product_id is not None:
            q = q.where(ConnectorToken.product_id == product_id)
        rows = s.scalars(q.order_by(ConnectorToken.created_at.desc())).all()
        return [
            {
                "id": r.id,
                "label": r.label,
                "prefix": r.prefix,
                "product_id": r.product_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            }
            for r in rows
        ]


def list_user_wide_tokens(user_id: str) -> list[dict]:
    """List a user's USER-WIDE tokens (product_id IS NULL). No secrets."""
    with session_scope() as s:
        rows = s.scalars(
            select(ConnectorToken)
            .where(ConnectorToken.user_id == user_id)
            .where(ConnectorToken.product_id.is_(None))
            .order_by(ConnectorToken.created_at.desc())
        ).all()
        return [
            {
                "id": r.id,
                "label": r.label,
                "prefix": r.prefix,
                "product_id": None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            }
            for r in rows
        ]
