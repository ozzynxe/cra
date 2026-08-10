"""Public HTTP MCP app: mounted FastMCP servers with bearer auth.

There is no SPA and no REST surface — the MCP wire is the product. The
Coauthor-era `/admin/*` session-lifecycle routes are gone (see `admin.py` for
why); products are created through the tool surface under a real identity,
which is what makes the audit trail meaningful.

Topology:

    GET  /health                        — liveness (no auth)
    GET  /version                       — service metadata (no auth)
    GET  /.well-known/oauth-*           — connector discovery (no auth)
    *    /oauth/*                       — OAuth 2.1 shim for Claude.ai / Codex
    POST /mcp/me/mcp                    — user-wide mount, `cra_*` token
    POST /mcp/{product_id}/mcp          — product-scoped mount, `cra_*` token
    POST /mcp/a/mcp, /mcp/b/mcp         — legacy static-bearer party mounts

Tokens are env-driven:
    CRA_TOKEN_<PARTY>    — static bearer for a legacy party mount
    CRA_PARTIES          — comma-separated party ids (default "a,b")

If a party token is unset, that legacy mount returns 503. `CRA_ADMIN_TOKEN` is
read by `auth.admin_authorized()` but nothing is mounted behind it today.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import AsyncExitStack, asynccontextmanager, suppress

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount, Route

from cra.server import (
    access,
    admin,
    advisory_sweeper,
    billing_web,
    console,
    deadline_sweeper,
    oauth,
)
from cra.server.auth import PartyAuthMiddleware
from cra.server.rate_limit import RateLimitMiddleware
from cra.server.tools import register_tools

log = logging.getLogger(__name__)


def _init_sentry() -> None:
    """Initialize Sentry if `SENTRY_DSN` is set; no-op otherwise.

    Idempotent — safe to call multiple times. Sets `environment` from
    `CRA_ENV` (default "production"), and `release` from
    `CRA_RELEASE` if set (we don't have automatic git-based release
    tagging yet, so this is opt-in).
    """
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.starlette import StarletteIntegration

        from cra.buildinfo import release

        sentry_sdk.init(
            dsn=dsn,
            environment=os.environ.get("CRA_ENV", "production"),
            # Falls back to the deployed commit when CRA_RELEASE is unset, so
            # errors are tagged with the build that produced them without an
            # operator having to keep a env var in step with every deploy.
            release=release(),
            # Lower than default — backend gets a lot of MCP traffic and we
            # don't want to pay for full tracing of every tool call.
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.05")),
            send_default_pii=False,
            integrations=[StarletteIntegration()],
        )
        log.info("Sentry initialized (env=%s)", os.environ.get("CRA_ENV", "production"))
    except Exception:  # noqa: BLE001 — never break startup on Sentry init failure
        log.exception("failed to initialize Sentry; continuing without it")


_init_sentry()


def _party_ids() -> tuple[str, ...]:
    raw = os.environ.get("CRA_PARTIES", "a,b")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def _allowed_hosts() -> list[str]:
    """Hosts allowed by FastMCP's DNS-rebinding protection.

    Reads `CRA_ALLOWED_HOSTS` (comma-separated, e.g. "cra.skarp.app,localhost").
    When unset, allows only loopback (the FastMCP default).
    """
    raw = os.environ.get("CRA_ALLOWED_HOSTS", "")
    extra = [h.strip() for h in raw.split(",") if h.strip()]
    base = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    # Add both bare and `:*` patterns for each configured host (FastMCP supports either)
    expanded: list[str] = []
    for h in extra:
        expanded.append(h)
        if ":" not in h:
            expanded.append(f"{h}:*")
    return base + expanded


def _allowed_origins() -> list[str]:
    """Origin allowlist for CORS-like checks. Mirrors `_allowed_hosts` over https/http."""
    raw = os.environ.get("CRA_ALLOWED_HOSTS", "")
    extra = [h.strip() for h in raw.split(",") if h.strip()]
    base = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    expanded: list[str] = []
    for h in extra:
        expanded.append(f"https://{h}")
        expanded.append(f"http://{h}")
    return base + expanded


def _make_mcp(party_id: str):
    """Build a FastMCP server with all tools closure-bound to `party_id`."""
    from mcp.server.fastmcp import FastMCP
    from mcp.server.transport_security import TransportSecuritySettings

    from cra.server.mcp_instructions import instructions_for

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts(),
        allowed_origins=_allowed_origins(),
    )
    mcp = FastMCP(
        f"cra-{party_id}",
        instructions=instructions_for(party_id),
        transport_security=security,
    )
    register_tools(mcp, actor_id=party_id, product_id_default=None)
    return mcp


class ShortMcpPath:
    """Make `https://<host>/mcp` mean the user-wide mount.

    That is the URL shape every other MCP server uses and the one a person
    guesses or truncates to — Claude Code's own help example is
    `https://mcp.sentry.dev/mcp`. It used to 404, and a connector pointed at it
    failed with nothing in any log to explain why.

    A rewrite rather than a second mount, for two reasons. Starlette's
    `Mount("/mcp")` matches only `/mcp/...` — bare `/mcp` falls through to the
    router's trailing-slash redirect, so mounting cannot serve it without a 307,
    and a redirect on POST works for clients that follow one and fails silently
    for those that do not. And a second FastMCP instance would mean a second
    session manager: the same URL would behave differently depending on which
    spelling the client happened to use. This way `/mcp` *is* `/mcp/me/mcp` —
    one mount, one session manager, one auth path, nothing to keep in step.

    Outermost in the stack, so rate limiting, CORS and auth all see the real
    path they would have seen anyway.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") in ("/mcp", "/mcp/"):
            scope = dict(scope)
            scope["path"] = "/mcp/me/mcp"
            scope["raw_path"] = b"/mcp/me/mcp"
        await self.app(scope, receive, send)


def build_app() -> Starlette:
    """Compose the parent Starlette app.

    FastMCP's `streamable_http_app()` returns a Starlette sub-app whose lifespan
    starts a session-manager task group. When mounted, the parent's lifespan
    must enter each sub-app's `session_manager.run()` — otherwise tool requests
    fail with `RuntimeError("Task group is not initialized")`.
    """
    routes = [
        Route("/health", admin.health, methods=["GET"]),
        Route("/version", admin.version, methods=["GET"]),
        # OAuth shim — required by Claude.ai's connector UI, which has no
        # static-bearer field. The token it issues is validated by
        # PartyAuthMiddleware on the /mcp mounts exactly as before.
        Route("/.well-known/oauth-protected-resource", oauth.well_known_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/{rest:path}", oauth.well_known_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth.well_known_authorization_server, methods=["GET"]),
        Route("/oauth/register", oauth.register, methods=["POST"]),
        # RFC 7592. Without DELETE a client cannot remove its own
        # registration, which is how a connector ends up stuck in a list:
        # the cleanup call 404s and the removal never completes.
        Route("/oauth/register/{client_id}", oauth.read_registration, methods=["GET"]),
        Route("/oauth/register/{client_id}", oauth.unregister, methods=["DELETE"]),
        Route("/oauth/authorize", oauth.authorize_get, methods=["GET"]),
        Route("/oauth/authorize", oauth.authorize_post, methods=["POST"]),
        Route("/oauth/token", oauth.token_endpoint, methods=["POST"]),
        # Self-serve access. The only pages this app renders that a stranger
        # reaches, and the completion page is the one place a freshly minted
        # token is ever displayed — which is why it cannot be a static file.
        Route("/access", access.access_form, methods=["GET"]),
        Route("/api/access/request", access.request_access, methods=["POST"]),
        Route("/api/access/complete", access.complete, methods=["GET"]),
        # Billing. The webhook is what grants a plan; /billing is only where
        # Stripe sends the customer's browser afterwards.
        Route("/api/stripe/webhook", billing_web.stripe_webhook, methods=["POST"]),
        Route("/pricing", billing_web.pricing_page, methods=["GET"]),
        Route("/billing", billing_web.billing_page, methods=["GET"]),
        Route("/billing", billing_web.billing_submit, methods=["POST"]),
        # The read-only console. Every page dispatches as the signed-in user;
        # nothing here writes. See server/console.py.
        Route("/app", console.products, methods=["GET"]),
        Route("/app/login", console.login_form, methods=["GET"]),
        Route("/app/login", console.login_submit, methods=["POST"]),
        Route("/app/logout", console.logout, methods=["POST"]),
        Route("/app/p/{product_id}", console.product, methods=["GET"]),
        Route("/app/p/{product_id}/requirements", console.requirements, methods=["GET"]),
        Route("/app/p/{product_id}/report", console.report, methods=["GET"]),
        # No REST surface. The MCP wire below is the whole product, and the
        # console above is a read-only view onto it.
    ]

    party_servers = []
    for pid in _party_ids():
        mcp = _make_mcp(pid)
        sub_app = mcp.streamable_http_app()
        party_servers.append(mcp)
        routes.append(
            Mount(
                f"/mcp/{pid}",
                app=sub_app,
                middleware=[Middleware(PartyAuthMiddleware, party_id=pid)],
            )
        )

    # User-wide MCP mount: `/mcp/me/mcp`. Used with `cra_*` tokens that have
    # `product_id IS NULL` — i.e., the agent acts as the user across any product
    # they have access to, picking one by passing `product_id=...` to each tool
    # call. Mount BEFORE the parametric `/mcp/{doc_id}` so the literal "me"
    # segment matches first. This is the mount real clients use.
    me_mcp = _make_mcp("me")
    me_sub_app = me_mcp.streamable_http_app()
    party_servers.append(me_mcp)
    routes.append(
        Mount(
            "/mcp/me",
            app=me_sub_app,
            middleware=[Middleware(PartyAuthMiddleware, party_id="me")],
        )
    )

    # Per-product URL pattern: `/mcp/<product_id>/mcp`, for a token scoped to a
    # single product. (Coauthor advertised this from its SPA's Connectors page;
    # here it is issued by hand.) The token carries (user_id, product_id) — the
    # `PartyAuthMiddleware._dispatch_coauth` path stashes both into contextvars,
    # and the tool dispatcher overrides closure-bound `party_id` accordingly.
    # Mount AFTER the literal party mounts so /mcp/a and /mcp/b stay legacy.
    dyn_mcp = _make_mcp("dynamic")
    dyn_sub_app = dyn_mcp.streamable_http_app()
    party_servers.append(dyn_mcp)
    routes.append(
        Mount(
            "/mcp/{doc_id}",
            app=dyn_sub_app,
            middleware=[Middleware(PartyAuthMiddleware, party_id="dynamic")],
        )
    )

    @asynccontextmanager
    async def lifespan(_app):
        async with AsyncExitStack() as stack:
            for mcp in party_servers:
                await stack.enter_async_context(mcp.session_manager.run())

            # The deadline sweeper. It needs a database — with no DATABASE_URL
            # every pass would raise, so it is not started at all rather than
            # left logging an exception every five minutes while appearing to
            # run.
            sweeper = advisories = None
            if os.environ.get("DATABASE_URL"):
                sweeper = deadline_sweeper.start_sweeper_task()
                # The other direction: the deadline sweeper chases obligations
                # that exist, this one looks for the event that creates them.
                advisories = advisory_sweeper.start_sweeper_task()
            else:
                log.warning(
                    "deadline sweeper not started: DATABASE_URL is unset. "
                    "Nothing in this process will chase reporting deadlines."
                )
            try:
                yield
            finally:
                for task in (sweeper, advisories):
                    if task is not None:
                        task.cancel()
                        with suppress(asyncio.CancelledError):
                            await task

    # CORS. There is no browser client yet; this is carried over and kept
    # narrow via CRA_CORS_ORIGINS. Cookies cross-origin require
    # allow_credentials=True + a non-`*` origin list.
    cors_origins_raw = os.environ.get(
        "CRA_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
    middleware = [
        # First in the list is outermost: rewrite before anything routes.
        Middleware(ShortMcpPath),
        Middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Admin-Token"],
            expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
        ),
        # Per-IP rate limit on REST endpoints — see `rate_limit.py` for the
        # rule table. Mounted AFTER CORS so preflight OPTIONS requests skip
        # the limiter (Starlette evaluates middleware stack outside-in).
        Middleware(RateLimitMiddleware),
    ]

    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


app = build_app()


def run() -> None:
    """Entry for `cra-http`. Honors CRA_HOST / CRA_PORT / CRA_LOG_LEVEL."""
    import uvicorn

    host = os.environ.get("CRA_HOST", "0.0.0.0")
    port = int(os.environ.get("CRA_PORT", "8000"))
    uvicorn.run(
        "cra.server.http_app:app",
        host=host,
        port=port,
        log_level=os.environ.get("CRA_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    run()
