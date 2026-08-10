"""Bearer-token auth helpers + Starlette middleware for per-party MCP mounts.

Two token paths supported on every MCP mount:

1. **Legacy static bearer** (`tok_a_*` / `tok_b_*`): per-party env var. The
   request acts as the closure-bound `party_id`; the dispatcher uses that.
2. **`coauth_*` connector token** (Phase 4+): resolved against the Postgres
   `connector_tokens` table to (user_id, product_id). The auth middleware
   stashes those into request-level contextvars; the dispatcher then OVERRIDES
   its closure-bound `party_id` and the tool-arg `session_id` accordingly.

Static tokens come from env (`CRA_TOKEN_<PARTY_ID_UPPER>`); if a token env
var is unset for a party, the legacy fall-through returns 503 (misconfigured).
But a `coauth_*` token works on ANY mount because it's self-describing.

Admin endpoints use a separate `CRA_ADMIN_TOKEN` env var.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger(__name__)


def token_for_party(party_id: str) -> str | None:
    return os.environ.get(f"CRA_TOKEN_{party_id.upper()}")


def admin_token() -> str | None:
    return os.environ.get("CRA_ADMIN_TOKEN")


def check_bearer(request: Request, expected: str | None, header: str = "authorization") -> bool:
    """Constant-time compare. Accepts either `Bearer <tok>` or raw header."""
    if not expected:
        return False
    raw = request.headers.get(header, "")
    if not raw:
        return False
    presented = raw.split(" ", 1)[1].strip() if raw.lower().startswith("bearer ") else raw.strip()
    return secrets.compare_digest(presented, expected)


def admin_authorized(request: Request) -> bool:
    expected = admin_token()
    return check_bearer(request, expected, header="x-admin-token") or check_bearer(request, expected)


def _extract_bearer(request: Request) -> str:
    raw = request.headers.get("authorization", "")
    if not raw:
        return ""
    return raw.split(" ", 1)[1].strip() if raw.lower().startswith("bearer ") else raw.strip()


def _unauthorized(request: Request, payload: dict) -> Response:
    """401 with the challenge that tells a client where to authenticate.

    Without `WWW-Authenticate`, a 401 from an MCP mount is a dead end. RFC 9728
    and the MCP authorization spec both have the client read
    `resource_metadata` off this header to discover the authorization server;
    a bare 401 gives it nowhere to go, so it fails quietly — no prompt, no
    browser, no email. Which is precisely the silent connector failure this
    repo already warns about from the Caddy side, reached by a different route.

    The origin is reconstructed the way `oauth._public_url` does it, from the
    forwarded headers Caddy sets, so the URL advertised here is the one the
    client actually reached us on. Imported locally because `oauth` imports
    this module.
    """
    from cra.server.oauth import _public_url

    origin = _public_url(request)
    return JSONResponse(
        payload,
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Bearer realm="{origin}", '
                f'resource_metadata="{origin}/.well-known/oauth-protected-resource"'
            )
        },
    )


class PartyAuthMiddleware(BaseHTTPMiddleware):
    """Per-mount bearer-token gate. Accepts both legacy static tokens (closure-
    bound to `party_id`) AND new `coauth_*` connector tokens (which resolve
    via Postgres and override the closure-bound party at request time)."""

    def __init__(self, app, party_id: str):
        super().__init__(app)
        self._party_id = party_id

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        from cra.server import connector_tokens  # local: avoids an import cycle

        presented = _extract_bearer(request)

        # Path 1 — a connector token. Self-describing, so it works on any
        # mount. The prefix test goes through `connector_tokens` rather than a
        # literal here: this line held its own copy of the prefix, and the two
        # drifted the moment the fork renamed it, producing a 401 on every
        # freshly minted token.
        if connector_tokens.is_connector_token(presented):
            return await self._dispatch_coauth(request, call_next, presented)

        # Path 2 — legacy static bearer (per-party env var).
        return await self._dispatch_legacy(request, call_next, presented)

    async def _dispatch_legacy(
        self, request: Request, call_next, presented: str
    ) -> Response:
        # The dynamic `/mcp/{doc_id}` mount and the user-wide `/mcp/me` mount
        # both require `coauth_*` tokens — no static-bearer fallback. Anything
        # else → 401, not 503.
        if self._party_id in {"dynamic", "me"}:
            # `code` is wire-visible: it is the body of the very first response
            # any new client sees. It said `coauth_required` until 2026-08-08,
            # which named the wrong product to everyone who looked. Renaming it
            # diverges this file from the upstream it was forked from, so a
            # cherry-pick will conflict here and should keep this side.
            return _unauthorized(
                request,
                {
                    "error": "unauthorized — connector token required",
                    "code": "connector_token_required",
                },
            )
        expected = token_for_party(self._party_id)
        if not expected:
            return JSONResponse(
                {"error": f"server misconfigured: CRA_TOKEN_{self._party_id.upper()} not set"},
                status_code=503,
            )
        if not presented or not secrets.compare_digest(presented, expected):
            return _unauthorized(request, {"error": "unauthorized"})
        return await call_next(request)

    async def _dispatch_coauth(
        self, request: Request, call_next, presented: str
    ) -> Response:
        # Local imports to avoid pulling DB at module load
        from cra.server import connector_tokens
        from cra.server.request_context import current_product_id, current_user_id

        try:
            verified = connector_tokens.verify_token(presented)
        except connector_tokens.TokenInvalid as e:
            return _unauthorized(
                request, {"error": f"invalid connector token: {e}", "code": "token_invalid"}
            )
        except connector_tokens.TokenExpired as e:
            return _unauthorized(
                request, {"error": f"token expired: {e}", "code": "token_expired"}
            )
        except connector_tokens.TokenRevoked as e:
            return _unauthorized(
                request, {"error": f"token revoked: {e}", "code": "token_revoked"}
            )
        except Exception as e:  # noqa: BLE001 — DB / unexpected
            log.exception("coauth token verify failed")
            return JSONResponse(
                {"error": f"auth backend error: {e}", "code": "auth_backend_error"},
                status_code=503,
            )

        # URL ↔ token scope check.
        #
        # `/mcp/me/mcp` (literal mount, party_id="me"): only user-wide tokens
        # belong here — `verified.product_id` must be None.
        #
        # `/mcp/<doc_id>/mcp` (parametric mount, party_id="dynamic"): the URL
        # carries a doc_id; the token must either match exactly (per-doc token)
        # or be user-wide (in which case the agent is opting into operating on
        # the URL's doc_id, validated for membership at the transition layer).
        #
        # `/mcp/a/mcp`, `/mcp/b/mcp` (legacy literal mounts): pass through —
        # `_dispatch_coauth` skips role check for legacy mounts.
        url_product_id = (
            request.scope.get("path_params", {}).get("doc_id")
            if isinstance(request.scope.get("path_params"), dict)
            else None
        )
        if self._party_id == "me":
            # User-wide URL — reject doc-scoped tokens.
            if verified.product_id is not None:
                return JSONResponse(
                    {
                        "error": "a product-scoped token cannot use the user-wide URL; use the product-specific one",
                        "code": "token_scope_mismatch",
                    },
                    status_code=403,
                )
        elif (
            url_product_id
            and url_product_id not in {"a", "b"}  # legacy literal mounts pass through
            and verified.product_id
            and url_product_id != verified.product_id
        ):
            return JSONResponse(
                {
                    "error": "token does not authorize this document",
                    "code": "token_doc_mismatch",
                },
                status_code=403,
            )

        # Concurrent-session cap per user. Only `coauth_*` (user-attributable)
        # tokens are tracked. Static `tok_a_*` / `tok_b_*` legacy tokens skip
        # the limiter because they have no user identity.
        from cra.server import session_limiter

        mcp_session_id = request.headers.get("mcp-session-id")
        allowed, count, limit = session_limiter.check_and_track(
            verified.user_id, mcp_session_id
        )
        if not allowed:
            log.info(
                "session_limit_exceeded user=%s active=%d limit=%d",
                verified.user_id, count, limit,
            )
            return JSONResponse(
                {
                    "error": (
                        f"Too many concurrent connector sessions ({count}/{limit}). "
                        "Disconnect an unused connector and retry, or contact support "
                        "to raise the limit for your account."
                    ),
                    "code": "session_limit_exceeded",
                    "limit": limit,
                    "active_sessions": count,
                },
                status_code=429,
            )

        # Stash verified identity into request-scoped contextvars; the
        # dispatcher overrides closure-bound party_id with verified.user_id.
        user_token = current_user_id.set(verified.user_id)
        product_token = current_product_id.set(verified.product_id)
        try:
            return await call_next(request)
        finally:
            current_user_id.reset(user_token)
            current_product_id.reset(product_token)
