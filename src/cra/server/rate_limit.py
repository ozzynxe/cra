"""Per-IP rate-limit middleware.

Implements a fixed-window counter per (rule, identifier) pair backed by Redis
INCR + EXPIRE. Fixed windows are slightly less fair than sliding windows but
much cheaper (1 INCR + at-most-1 EXPIRE per request) and good enough to absorb
a sudden traffic spike.

## What's covered

**The rule table is inherited and most of it is inert here.** `DEFAULT_RULES`
still describes the API surface of the product this code was forked from, whose
paths this service does not serve, so those entries never match. They are kept
so the module stays diffable against upstream — a security fix there should
apply cleanly here. What fires for this service are the rules on `/oauth/*`,
`/api/access/*`, `/billing` and `/app/login`.

**Nothing here matches `/mcp/*`,** and `_match_rule` has no catch-all, so the
MCP wire is unlimited by this middleware. That is survivable because every MCP
mount is behind bearer validation and `session_limiter`, but it is a gap rather
than a decision, and a rule belongs here.

The inherited table targets:

  - Anonymous reads — `/api/discover`, `/api/documents/<id>`, etc. (60/min/IP)
  - Auth writes — login / register / forgot_password (20/hour/IP)
  - Document creation — `POST /api/documents` (10/hour/IP)
  - Comment posts — `POST /api/documents/<id>/comments` (60/hour/IP)

Per-USER caps (e.g. doc creation cap by tier) are enforced inside the route
handlers — see `_doc_cap_for_tier` in `api.py`. This middleware is the first
line of defence against bursts; the route-level checks are the second.

## Failure modes

If Redis is unreachable (shared stack down, network partition, etc.) the
middleware **fails open** and logs the failure. Availability matters more than
strict rate limiting here: the limits exist to absorb abuse, and refusing every
request because the counter is unreachable would turn a dependency outage into
a full one.

## Identifying the caller

We trust `X-Forwarded-For` from Caddy. Caddy is the only thing fronting our
container and strips inbound `X-Forwarded-For` before setting its own. Without
a header, we fall back to `request.client.host` (which would be the Caddy
container's IP — fine as a single bucket if Caddy ever stops setting the
header for some reason).

## Tunables (env)

  - `REDIS_URL`               — connection string, default `redis://deploy-redis-1:6379/1`
  - `CRA_RATE_LIMIT_OFF` — set to "1" to disable enforcement (still does
                                Redis ops, useful for shadow testing)
  - Per-rule overrides: see DEFAULT_RULES — env names listed in each rule.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Optional, Pattern, Sequence

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger(__name__)


# ---- rule definition --------------------------------------------------------


@dataclass(frozen=True)
class RateLimitRule:
    """One row in the rate-limit table.

    `name`           — short identifier; used as part of the Redis key + log lines
    `method`         — HTTP method to match (or '*' for any)
    `path_re`        — compiled regex; matched against `request.url.path`
    `limit_default`  — requests per `window_seconds`, default value
    `limit_env`      — env var that overrides `limit_default` at runtime
    `window_seconds` — fixed-window length in seconds
    """

    name: str
    method: str
    path_re: Pattern[str]
    limit_default: int
    limit_env: str
    window_seconds: int

    def limit(self) -> int:
        raw = os.environ.get(self.limit_env)
        if raw:
            try:
                return int(raw)
            except ValueError:
                log.warning("%s=%r is not int; using default %d", self.limit_env, raw, self.limit_default)
        return self.limit_default


DEFAULT_RULES: tuple[RateLimitRule, ...] = (
    # Anonymous catalog reads — the most exposed endpoint. Generous so a normal
    # browse session (filter chips, scroll) never trips it; tight enough to
    # break a script.
    RateLimitRule(
        name="anon-read-discover",
        method="GET",
        path_re=re.compile(r"^/api/discover$"),
        limit_default=60,
        limit_env="CRA_RL_DISCOVER_PER_MIN",
        window_seconds=60,
    ),
    # Inherited: a cross-document live feed, on the same anon-read budget as
    # discovery. The client polled every 15s, so one open tab burned ~4/min;
    # 60/min let a visitor keep several tabs open without tripping.
    RateLimitRule(
        name="anon-read-feed",
        method="GET",
        path_re=re.compile(r"^/api/feed$"),
        limit_default=60,
        limit_env="CRA_RL_FEED_PER_MIN",
        window_seconds=60,
    ),
    # Doc download (Phase 12.9) — Markdown / Word. Renders are cheap (md is
    # microseconds, docx is ~100ms), but cheap × abuse can still hurt. 60/min
    # matches discover/feed and is more than enough for a human clicking
    # "Download" a few times. Tighten to 20/min if scraping becomes an issue.
    RateLimitRule(
        name="anon-read-download",
        method="GET",
        path_re=re.compile(r"^/api/documents/[^/]+/download$"),
        limit_default=60,
        limit_env="CRA_RL_DOWNLOAD_PER_MIN",
        window_seconds=60,
    ),
    RateLimitRule(
        name="anon-read-doc",
        method="GET",
        path_re=re.compile(r"^/api/documents/[^/]+$"),
        limit_default=120,
        limit_env="CRA_RL_READ_DOC_PER_MIN",
        window_seconds=60,
    ),
    RateLimitRule(
        name="anon-read-section",
        method="GET",
        path_re=re.compile(r"^/api/documents/[^/]+/sections/[^/]+$"),
        limit_default=240,
        limit_env="CRA_RL_READ_SECTION_PER_MIN",
        window_seconds=60,
    ),
    # Auth writes — Skarp's email verify is a friction barrier, but no point
    # letting someone hammer registration to fish out which emails are taken.
    RateLimitRule(
        name="auth-register",
        method="POST",
        path_re=re.compile(r"^/api/auth/register$"),
        limit_default=5,
        limit_env="CRA_RL_REGISTER_PER_HOUR",
        window_seconds=3600,
    ),
    RateLimitRule(
        name="auth-login",
        method="POST",
        path_re=re.compile(r"^/api/auth/(login|skarp_callback|google)$"),
        limit_default=30,
        limit_env="CRA_RL_LOGIN_PER_HOUR",
        window_seconds=3600,
    ),
    RateLimitRule(
        name="auth-forgot",
        method="POST",
        path_re=re.compile(r"^/api/auth/forgot_password$"),
        limit_default=10,
        limit_env="CRA_RL_FORGOT_PER_HOUR",
        window_seconds=3600,
    ),
    # OAuth DCR (RFC 7591). Real clients call this once per install — the
    # client_id is then reused for every authorize/token round-trip. 10/hr per
    # IP is far above any legitimate use and shuts down the unbounded-memory
    # vector (oauth.py keeps `_clients` in process; no rate limit here meant
    # an anonymous attacker could mint client records until OOM).
    RateLimitRule(
        name="oauth-dcr",
        method="POST",
        path_re=re.compile(r"^/oauth/register$"),
        limit_default=10,
        limit_env="CRA_RL_DCR_PER_HOUR",
        window_seconds=3600,
    ),
    # Self-serve access. This endpoint makes the service send mail to an
    # address a stranger supplies, which is a spam cannon if left open — and
    # the address is somebody else's. Tight on purpose: a person signing up
    # needs one or two attempts, never twenty. `signup.py` additionally caps
    # live links per address, because rate limiting by IP alone does not
    # protect the person being targeted.
    RateLimitRule(
        name="access-request",
        method="POST",
        path_re=re.compile(r"^/api/access/request$"),
        limit_default=5,
        limit_env="CRA_RL_ACCESS_REQUEST_PER_HOUR",
        window_seconds=3600,
    ),
    # Completion is a guess-resistant 256-bit secret, so this is about noise
    # rather than brute force.
    RateLimitRule(
        name="access-complete",
        method="GET",
        path_re=re.compile(r"^/api/access/complete$"),
        limit_default=30,
        limit_env="CRA_RL_ACCESS_COMPLETE_PER_HOUR",
        window_seconds=3600,
    ),
    # The browser billing flow: an email step that mails a code to whoever was
    # named, and a code step guessing at twenty bits. Same shape as the OAuth
    # consent endpoint and limited the same way; `signup.py` holds the inner
    # rings (five wrong codes spend the challenge, three live per address).
    RateLimitRule(
        name="billing-web",
        method="POST",
        path_re=re.compile(r"^/billing$"),
        limit_default=40,
        limit_env="CRA_RL_BILLING_PER_HOUR",
        window_seconds=3600,
    ),
    # Console sign-in. Mails a code to whoever is named, then accepts guesses
    # at twenty bits — the same two exposures as the billing flow, limited the
    # same way. `signup.py` holds the inner rings.
    RateLimitRule(
        name="console-login",
        method="POST",
        path_re=re.compile(r"^/app/login$"),
        limit_default=40,
        limit_env="CRA_RL_CONSOLE_LOGIN_PER_HOUR",
        window_seconds=3600,
    ),
    # OAuth consent. Three things post here and each is a guessing surface:
    # a pasted `cra_…` token (bcrypt makes each attempt expensive), an email
    # address (which sends mail to whoever was named), and a six-digit code
    # (twenty bits — the weakest of the three, and the reason this rule is not
    # generous). `signup.py` holds the inner rings: five wrong codes spend the
    # challenge, and one address may hold only three live at a time.
    #
    # 40/hr rather than 30 because the code flow costs two round-trips where
    # the paste cost one, and a shared office NAT should not lock out the
    # second person to connect.
    RateLimitRule(
        name="oauth-authorize",
        method="POST",
        path_re=re.compile(r"^/oauth/authorize$"),
        limit_default=40,
        limit_env="CRA_RL_OAUTH_AUTHORIZE_PER_HOUR",
        window_seconds=3600,
    ),
    # Per-user write caps. We only have IP here (cookie isn't decoded yet),
    # so this is the OUTER ring — the doc cap in `create_document` is the
    # inner ring. Together: an attacker can't spam from one IP, and even with
    # multiple IPs they hit the doc cap.
    RateLimitRule(
        name="write-doc",
        method="POST",
        path_re=re.compile(r"^/api/documents$"),
        limit_default=20,
        limit_env="CRA_RL_DOCS_PER_HOUR",
        window_seconds=3600,
    ),
    RateLimitRule(
        name="write-comment",
        method="POST",
        path_re=re.compile(r"^/api/documents/[^/]+/comments$"),
        limit_default=60,
        limit_env="CRA_RL_COMMENTS_PER_HOUR",
        window_seconds=3600,
    ),
)


# ---- redis helpers ----------------------------------------------------------


_REDIS_CLIENT = None


def _redis_url() -> str:
    return os.environ.get("REDIS_URL", "redis://deploy-redis-1:6379/1")


def _get_redis():
    """Lazily-initialised redis-py client. Same instance for the process.

    `decode_responses=True` so INCR returns an int directly. Short timeouts
    so a hung Redis can't hold a request hostage — we'd rather fail-open
    than queue.
    """
    global _REDIS_CLIENT
    if _REDIS_CLIENT is not None:
        return _REDIS_CLIENT
    import redis as _redis

    _REDIS_CLIENT = _redis.from_url(
        _redis_url(),
        socket_timeout=2.0,
        socket_connect_timeout=2.0,
        decode_responses=True,
    )
    return _REDIS_CLIENT


def _client_ip(request: Request) -> str:
    """Pull the real client IP from `X-Forwarded-For` (set by Caddy).

    Falls back to `request.client.host` if the header is missing — that's
    fine since the only path where it could be missing is direct internal
    access (a developer with shell on the box poking via curl), which is
    a single bucket that doesn't matter.
    """
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        # XFF can be a chain ("client, proxy1, proxy2"); the first entry is the
        # original client. Caddy puts the real client first.
        return fwd.split(",")[0].strip() or "unknown"
    if request.client:
        return request.client.host
    return "unknown"


# ---- middleware -------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware enforcing `DEFAULT_RULES`.

    On match: INCR a Redis counter keyed by (rule, IP). If the count exceeds
    the limit, return 429 with `Retry-After`. On the first INCR for a fresh
    window, set EXPIRE so old buckets evict.

    On Redis failure, fail-open and log. We'd rather serve traffic than 503
    every request because Redis is hiccupping.

    ## Headers added on every matched request
      - `X-RateLimit-Limit`     — the limit for this bucket
      - `X-RateLimit-Remaining` — requests left in this window (clamped to 0)
      - `Retry-After` (429 only) — seconds until the window resets
    """

    def __init__(self, app, rules: Optional[Sequence[RateLimitRule]] = None):
        super().__init__(app)
        self.rules = tuple(rules) if rules is not None else DEFAULT_RULES

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        rule = self._match_rule(request)
        if rule is None:
            return await call_next(request)

        # Shadow mode — count but don't enforce. Useful for tuning thresholds
        # before flipping enforcement on.
        enforce = os.environ.get("CRA_RATE_LIMIT_OFF") != "1"

        identifier = _client_ip(request)
        key = f"coauthor:rl:{rule.name}:{identifier}"
        limit = rule.limit()

        try:
            r = _get_redis()
            count = r.incr(key)
            if count == 1:
                # Fresh window — set TTL.
                r.expire(key, rule.window_seconds)
            ttl = r.ttl(key)
        except Exception:  # noqa: BLE001 — never block traffic on rate-limit failure
            log.exception(
                "rate_limit middleware failed for rule=%s ip=%s; failing open",
                rule.name,
                identifier,
            )
            return await call_next(request)

        if count > limit and enforce:
            retry_after = ttl if (ttl is not None and ttl > 0) else rule.window_seconds
            log.info(
                "rate_limit triggered: rule=%s ip=%s count=%d/%d retry_after=%ds",
                rule.name,
                identifier,
                count,
                limit,
                retry_after,
            )
            return JSONResponse(
                {
                    "error": (
                        "Too many requests. Slow down a bit — "
                        f"try again in {retry_after} seconds."
                    ),
                    "code": "rate_limited",
                    "retry_after_seconds": retry_after,
                },
                status_code=429,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response: Response = await call_next(request)
        # Surface remaining quota so well-behaved clients can throttle.
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count))
        return response

    def _match_rule(self, request: Request) -> Optional[RateLimitRule]:
        method = request.method
        path = request.url.path
        for rule in self.rules:
            if rule.method != "*" and rule.method != method:
                continue
            if rule.path_re.match(path):
                return rule
        return None
