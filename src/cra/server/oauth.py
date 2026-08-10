"""OAuth 2.1 + PKCE shim for connecting MCP clients (Claude.ai, Codex web, …).

There are TWO supported flows behind the same endpoints:

  1. **User-wide** (DEFAULT). The authorize page proves who the browser is,
     then mints a fresh `cra_*` user-wide token tied to that user_id and
     returns it as the OAuth `access_token`. Claude.ai then uses it as the
     Bearer for every subsequent MCP call, hitting `/mcp/me/mcp` where
     party_id resolves to the user_id.

     Three ways it can know who you are, in order of preference:
       a. an emailed six-digit code — the default, and the only one that works
          for somebody who has never used this service before;
       b. a pasted `cra_…` connector token — the fallback, and the way in when
          mail delivery is down or self-serve is switched off;
       c. a `coauthor_session` cookie — inherited from Coauthor, and inert
          here: this deployment has neither a login page nor an SSO secret.

     (a) is why the flow needs no session and no cookie of its own. Both steps
     post back to this endpoint carrying the whole OAuth request as hidden
     fields, so the only server-side state is the challenge row `signup.py`
     already keeps.

  2. **Legacy POC** (only for operators with `tok_a_*` / `tok_b_*` env tokens).
     Triggered when the inbound URL has `party=a/b` query / form data, or
     when the resource URL matches `/mcp/a/mcp` or `/mcp/b/mcp`. Shows the
     paste-static-bearer form; access_token IS the static token. Used by
     the POC two-party demo and operator-side smoke tests.

Discovery (`.well-known`) and DCR are shared. The fork happens at
`/oauth/authorize`. The token endpoint just looks up the auth code and
returns whatever `access_token` was stored on the record.

Endpoints:
  GET  /.well-known/oauth-protected-resource[/{rest:path}]   (RFC 9728)
  GET  /.well-known/oauth-authorization-server               (RFC 8414)
  POST /oauth/register                                       (RFC 7591)
  GET  /oauth/authorize                                      (HTML form OR redirect-to-login)
  POST /oauth/authorize                                      (form submission)
  POST /oauth/token

PKCE S256 is required (Claude.ai always sends it).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from cra.server import connector_tokens, signup, sso
from cra.server.auth import token_for_party

log = logging.getLogger(__name__)

# In-memory: one-time auth codes → metadata. Single-instance only; ephemeral.
_codes: dict[str, dict] = {}
_CODE_TTL = 300  # 5 minutes

# Hard cap on `_codes` (defence-in-depth alongside TTL/lazy GC). An abandoned-
# code flood — register → authorize → never call /token — can otherwise grow
# the dict until OOM, since `_gc_codes()` only runs on /token and authorize
# branches. When we approach the cap we GC eagerly; if every entry is still
# in-TTL we drop the oldest by `created_at` to make room.
_MAX_CODES = 100_000

# Issued client_ids (from DCR). We don't enforce them strictly — DCR with
# `token_endpoint_auth_method=none` is essentially a no-op identity ceremony.
# Soft cap + TTL keep the dict from growing unboundedly under DCR flood (the
# `/oauth/register` rate-limit rule is the outer ring; this is the inner).
_MAX_CLIENTS = 10_000
_CLIENT_TTL = 90 * 24 * 3600  # 90 days from issuance


# DCR client records live in Postgres, not in this process.
#
# They were a module-level dict, which meant a container restart forgot every
# client that had ever connected — and a deploy is a restart. Every ship broke
# every live connector, quietly: an unknown client falls through to the host
# allowlist rather than failing loudly, so the damage only showed up later as a
# connector that could neither reconnect nor be removed.
#
# Reads fail *open*, the same rule `entitlements.plan_for` follows. If the
# database cannot be reached, "we could not check whether this client is
# registered" must not become "this client is forbidden" — the redirect_uri
# host allowlist is the real open-redirect gate and it does not depend on this
# table at all.


def _client_record(client_id: str) -> Optional[dict]:
    """The stored registration, or None if unknown or unreadable."""
    if not client_id:
        return None
    from cra.db import session_scope
    from cra.db.models import OAuthClient

    try:
        with session_scope() as db:
            row = db.get(OAuthClient, client_id)
            if row is None:
                return None
            return {
                "client_id": row.client_id,
                "client_name": row.client_name,
                "redirect_uris": list(row.redirect_uris or []),
                "issued_at": int(row.issued_at.timestamp()) if row.issued_at else 0,
                "registration_access_token_hash": row.registration_access_token_hash,
            }
    except Exception:  # noqa: BLE001 — see the fail-open note above
        log.exception("could not read OAuth client %s; treating as unknown", client_id)
        return None

# Long-lived issued-token expires_in: tell Claude.ai the token is good for a
# year. Saves the user from re-pasting. (The static token doesn't actually
# expire server-side; this is just the JWT-style metadata we report.)
_ACCESS_TOKEN_TTL = 365 * 24 * 3600


def _public_url(request: Request) -> str:
    """Reconstruct the public URL the way Caddy presents it to the world."""
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


def _allowed_parties() -> tuple[str, ...]:
    raw = os.environ.get("CRA_PARTIES", "a,b")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


# --- redirect_uri allowlist (open-redirect defense) ----------------------------
#
# OAuth's authorize endpoint redirects the user-agent to whatever
# `redirect_uri` the client passed. Without validation that's an open-redirect:
# a malicious site can register a client with its own redirect URI and trick
# a signed-in Coauthor user through the consent flow, exfiltrating the auth
# code (and from there, a Bearer token) to an attacker host.
#
# Defense: every redirect_uri must match an allowlisted host OR be in the set
# the client registered via DCR (RFC 6749 §3.1.2.3). Operators tune the
# allowlist via `CRA_OAUTH_REDIRECT_HOSTS` (comma-separated host suffixes).
# Subdomains match: `claude.ai` permits `foo.claude.ai`. http:// is permitted
# only for the loopback hosts so local dev still works.

_DEFAULT_REDIRECT_HOSTS = (
    "claude.ai",
    "anthropic.com",
    "chatgpt.com",
    "openai.com",  # covers chat.openai.com, codex.openai.com, etc.
    "smithery.ai",  # community MCP directory
    "smithery.run",  # Smithery's runtime / OAuth callback host

    "localhost",
    "127.0.0.1",
)


def _allowed_redirect_hosts() -> tuple[str, ...]:
    raw = os.environ.get("CRA_OAUTH_REDIRECT_HOSTS")
    if not raw:
        return _DEFAULT_REDIRECT_HOSTS
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def _is_loopback_host(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def _redirect_uri_allowed(redirect_uri: str) -> bool:
    """Validate a redirect_uri against the allowlist + scheme rules.

    Rejects: empty, non-http(s) schemes (javascript:/data:/file:/…), and
    any host not on the allowlist (exact match OR subdomain).
    Allows http:// only for loopback hosts (dev).
    """
    if not redirect_uri:
        return False
    try:
        parsed = urlparse(redirect_uri)
    except Exception:  # noqa: BLE001
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if parsed.scheme == "http" and not _is_loopback_host(host):
        return False  # plaintext is loopback-only
    for allowed in _allowed_redirect_hosts():
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def _redirect_uri_registered(client_id: str, redirect_uri: str) -> bool:
    """If we know this client (DCR), the redirect_uri must be in its
    registered set. If we don't know the client, fall through to the
    allowlist check upstream — DCR isn't strictly required by RFC.
    """
    record = _client_record(client_id)
    if record is None:
        return True  # no DCR record; allowlist is the only gate
    registered = record.get("redirect_uris") or []
    if not registered:
        return True  # client registered with empty set; allowlist still applies
    return redirect_uri in registered


def _gc_codes() -> None:
    """Drop expired auth codes. Also enforces `_MAX_CODES`: when the dict is
    at or past the cap after TTL eviction, evict the oldest entries by
    `created_at` so a flood of in-TTL abandoned codes can't grow without
    bound. The cap is well above any legitimate burst; hitting it means
    abuse, and dropping the oldest in-TTL entry is the right failure mode."""
    now = time.time()
    for c, v in list(_codes.items()):
        if v["created_at"] + _CODE_TTL < now:
            _codes.pop(c, None)
    if len(_codes) >= _MAX_CODES:
        oldest = sorted(_codes.items(), key=lambda kv: kv[1].get("created_at", 0))
        for c, _v in oldest[: len(_codes) - _MAX_CODES + 1]:
            _codes.pop(c, None)


def _gc_clients() -> None:
    """Evict expired registrations, then enforce the cap oldest-first.

    Same policy the dict had, moved to SQL. Best-effort: a failure here must
    not stop somebody registering, so it logs and returns."""
    from sqlalchemy import func as _func, select

    from cra.db import session_scope
    from cra.db.models import OAuthClient

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_CLIENT_TTL)
    try:
        with session_scope() as db:
            db.query(OAuthClient).filter(OAuthClient.issued_at < cutoff).delete(
                synchronize_session=False
            )
            total = db.execute(select(_func.count()).select_from(OAuthClient)).scalar_one()
            if total >= _MAX_CLIENTS:
                doomed = (
                    db.query(OAuthClient)
                    .order_by(OAuthClient.issued_at.asc())
                    .limit(total - _MAX_CLIENTS + 1)
                    .all()
                )
                for row in doomed:
                    db.delete(row)
    except Exception:  # noqa: BLE001 — housekeeping, never a reason to refuse
        log.exception("OAuth client GC failed")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _verify_pkce_s256(verifier: str, challenge: str) -> bool:
    if not verifier or not challenge:
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return secrets.compare_digest(_b64url(digest), challenge)


def _party_from_resource(resource: Optional[str]) -> Optional[str]:
    """Extract `a` or `b` from a resource URL like https://host/mcp/a/mcp."""
    if not resource:
        return None
    for p in _allowed_parties():
        for pat in (f"/mcp/{p}/mcp", f"/mcp/{p}"):
            if pat in resource:
                return p
    return None


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---- Discovery ----------------------------------------------------------------


async def well_known_protected_resource(request: Request) -> Response:
    """RFC 9728 protected-resource metadata.

    MCP spec asks clients to query
    `/.well-known/oauth-protected-resource/<mcp-path>`. We respond with the same
    payload regardless of the path suffix — all our MCP mounts share an issuer.
    """
    server = _public_url(request)
    return JSONResponse(
        {
            "resource": server,
            "authorization_servers": [server],
            "scopes_supported": ["mcp"],
            "bearer_methods_supported": ["header"],
        }
    )


async def well_known_authorization_server(request: Request) -> Response:
    """RFC 8414 authorization-server metadata."""
    server = _public_url(request)
    return JSONResponse(
        {
            "issuer": server,
            "authorization_endpoint": f"{server}/oauth/authorize",
            "token_endpoint": f"{server}/oauth/token",
            "registration_endpoint": f"{server}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
        }
    )


# ---- Dynamic Client Registration ---------------------------------------------


async def register(request: Request) -> Response:
    """RFC 7591 DCR. Validates `redirect_uris` against the host allowlist
    so a malicious client can't register a callback that points off-platform.
    """
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    redirect_uris = body.get("redirect_uris") or []
    client_name = body.get("client_name") or "unnamed"

    # Every URI must pass the host allowlist + scheme check. RFC 7591 says
    # we MAY restrict; for an open-internet OAuth shim we MUST.
    if not isinstance(redirect_uris, list):
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be a list of strings",
            },
            status_code=400,
        )
    bad = [u for u in redirect_uris if not _redirect_uri_allowed(u)]
    if bad:
        # Log explicitly — DCR clients often hide the response body from
        # their UI, so the operator only sees the generic "not on allowlist"
        # message. Log here so prod logs show which URI to add next.
        log.warning(
            "dcr_rejected_redirect_uri client_name=%s rejected=%s",
            client_name,
            bad,
        )
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": (
                    "one or more redirect_uris are not on the allowlist "
                    "(hosts: "
                    + ", ".join(_allowed_redirect_hosts())
                    + ")"
                ),
                "rejected": bad,
            },
            status_code=400,
        )

    _gc_clients()

    import bcrypt

    from cra.db import session_scope
    from cra.db.models import OAuthClient

    client_id = "client_" + secrets.token_urlsafe(16)
    # RFC 7592. A client_id is not a secret — it is in every authorize URL —
    # so deletion needs its own bearer. Returned once; only the hash is kept.
    registration_token = "regtok_" + secrets.token_urlsafe(32)
    token_hash = bcrypt.hashpw(
        registration_token.encode("utf-8"), bcrypt.gensalt(rounds=10)
    ).decode("ascii")

    issued = datetime.now(timezone.utc)
    try:
        with session_scope() as db:
            db.add(
                OAuthClient(
                    client_id=client_id,
                    client_name=client_name,
                    redirect_uris=redirect_uris,
                    registration_access_token_hash=token_hash,
                    issued_at=issued,
                )
            )
    except Exception:  # noqa: BLE001
        log.exception("could not persist OAuth client registration")
        return JSONResponse(
            {"error": "server_error", "error_description": "could not store the registration"},
            status_code=500,
        )

    server = _public_url(request)
    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(issued.timestamp()),
            "redirect_uris": redirect_uris,
            "client_name": client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            # RFC 7592: where to manage this registration, and what to present.
            "registration_access_token": registration_token,
            "registration_client_uri": f"{server}/oauth/register/{client_id}",
        },
        status_code=201,
    )


async def unregister(request: Request) -> Response:
    """RFC 7592 — a client removing its own registration.

    Its absence is why a stale connector could not be deleted: the client asks
    to clean up, gets a 404, and refuses to finish, leaving an entry that can
    neither connect nor be removed.

    Authorisation is the `registration_access_token` handed back at
    registration, not the `client_id`. The id travels in every authorize URL
    and in browser history; treating it as proof would let anyone who has seen
    one delete that registration. Compared in constant time via bcrypt, and a
    missing or wrong token is 401 either way — the response must not reveal
    whether the client exists.

    Idempotent by design: a client retrying a delete it already completed
    should see success, not an error that strands the entry again. So an
    unknown id returns 204 rather than 404.
    """
    import bcrypt

    from cra.db import session_scope
    from cra.db.models import OAuthClient

    client_id = request.path_params.get("client_id", "")
    presented = ""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        presented = header[7:].strip()

    if not presented:
        return JSONResponse(
            {"error": "invalid_token", "error_description": "registration access token required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="registration"'},
        )

    try:
        with session_scope() as db:
            row = db.get(OAuthClient, client_id)
            if row is None:
                # Already gone. Saying so would both leak existence and re-strand
                # a client that is simply retrying.
                return Response(status_code=204)
            stored = row.registration_access_token_hash or ""
            ok = bool(stored) and bcrypt.checkpw(
                presented.encode("utf-8"), stored.encode("ascii")
            )
            if not ok:
                log.warning("rejected registration delete for %s: bad token", client_id)
                return JSONResponse(
                    {"error": "invalid_token"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Bearer realm="registration"'},
                )
            db.delete(row)
    except Exception:  # noqa: BLE001
        log.exception("could not delete OAuth client %s", client_id)
        return JSONResponse({"error": "server_error"}, status_code=500)

    log.info("OAuth client %s deleted its own registration", client_id)
    return Response(status_code=204)


async def read_registration(request: Request) -> Response:
    """RFC 7592 read. Same bearer, same silence about existence."""
    import bcrypt

    from cra.db import session_scope
    from cra.db.models import OAuthClient

    client_id = request.path_params.get("client_id", "")
    header = request.headers.get("authorization", "")
    presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
    unauthorized = JSONResponse(
        {"error": "invalid_token"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="registration"'},
    )
    if not presented:
        return unauthorized
    try:
        with session_scope() as db:
            row = db.get(OAuthClient, client_id)
            if row is None or not row.registration_access_token_hash:
                return unauthorized
            if not bcrypt.checkpw(
                presented.encode("utf-8"), row.registration_access_token_hash.encode("ascii")
            ):
                return unauthorized
            return JSONResponse(
                {
                    "client_id": row.client_id,
                    "client_name": row.client_name,
                    "redirect_uris": list(row.redirect_uris or []),
                    "client_id_issued_at": int(row.issued_at.timestamp()) if row.issued_at else 0,
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                }
            )
    except Exception:  # noqa: BLE001
        log.exception("could not read OAuth client %s", client_id)
        return JSONResponse({"error": "server_error"}, status_code=500)


# ---- Authorization endpoint ---------------------------------------------------


# The consent screen's stylesheet, inlined into every template below.
#
# This is the deliberate exception to the site's "no inline styles" rule, and
# the reason is the page itself: an unstyled page asking for a credential is
# exactly what users are taught to distrust. It has to render correctly with no
# stylesheet, on a deployment that has not published the site, and without a
# request to any other host — so it carries its own.
#
# The values are the design tokens as literals rather than `var()` references
# into /style.css. That is what makes it self-contained. It is a minimal
# subset — the type stack, the ink/paper pair, the keyline card, the button —
# and the result is visually plainer than the rest of the site, which is the
# right way round for a page that must not depend on anything.
_CONSENT_STYLE = """<style>
  :root {
    --paper:#faf8f4; --card:#ffffff; --ink:#14130f; --ink-2:#3d3830;
    --muted:#5a544a; --faint:#6b6459; --rule:#ddd7cd; --rule-2:#efece6;
    --wash:#f4f1eb; --accent:oklch(0.44 0.13 288); --alert:oklch(0.48 0.14 30);
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --paper:#14130f; --card:#1a1815; --ink:#f2efe9; --ink-2:#d9d4cb;
      --muted:#a9a297; --faint:#8e877b; --rule:#332f29; --rule-2:#282521;
      --wash:#1f1c19; --accent:oklch(0.78 0.12 288); --alert:oklch(0.72 0.15 30);
    }
  }
  *,*::before,*::after { box-sizing:border-box; }
  body {
    margin:0 auto; max-width:34rem; padding:3.5rem 1.5rem;
    background:var(--paper); color:var(--ink);
    font:16px/1.6 var(--sans); -webkit-font-smoothing:antialiased;
  }
  .brand {
    font:0.78125rem/1 var(--mono); letter-spacing:0.07em; text-transform:uppercase;
    color:var(--faint); margin-bottom:1.5rem;
  }
  h1 { margin:0 0 0.5rem; font-size:1.625rem; font-weight:650; letter-spacing:-0.02em; line-height:1.12; }
  p { margin:0 0 1rem; }
  .subtitle { color:var(--ink-2); margin-bottom:1.5rem; }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  :focus-visible { outline:2px solid var(--accent); outline-offset:2px; border-radius:2px; }
  .grant {
    border:2px solid var(--ink); border-radius:3px; background:var(--card);
    padding:1.25rem 1.5rem; margin:0 0 1.5rem;
  }
  .grant p:last-child, .grant ul:last-child { margin-bottom:0; }
  ul { padding-left:1.2em; margin:0 0 1rem; color:var(--ink-2); }
  li { margin:0.25rem 0; }
  .you {
    background:var(--wash); border:1px solid var(--rule); border-radius:3px;
    padding:0.6875rem 0.875rem; font-size:0.9375rem; color:var(--ink-2);
    margin-bottom:1.25rem;
  }
  .you b { color:var(--ink); }
  label { display:block; font-size:0.9375rem; font-weight:500; margin-bottom:0.375rem; }
  input[type=text], input[type=email], input[type=password] {
    width:100%; font:1rem var(--sans); color:var(--ink); background:var(--card);
    border:1px solid var(--rule); border-radius:3px; padding:0.75rem 1rem;
  }
  input[type=password] { font-family:var(--mono); font-size:0.875rem; }
  input.code { font-family:var(--mono); font-size:1.5rem; letter-spacing:0.3em; text-align:center; }
  button {
    display:inline-block; font:500 0.9375rem/1 var(--sans); padding:0.75rem 1.375rem;
    border:1px solid var(--ink); border-radius:3px; background:var(--ink);
    color:var(--paper); cursor:pointer; margin:1rem 0.5rem 0 0;
  }
  button:hover { opacity:0.88; }
  button.cancel { background:transparent; color:var(--ink); border-color:var(--rule); }
  button.cancel:hover { opacity:1; border-color:var(--ink); }
  .error {
    border-left:3px solid var(--alert); background:var(--card);
    padding:0.75rem 1rem; margin:1rem 0 0; font-size:0.9375rem;
  }
  .hint { color:var(--muted); font-size:0.84375rem; line-height:1.55; margin:0.5rem 0 0; }
  .alt, .footer {
    margin-top:2rem; padding-top:1rem; border-top:1px solid var(--rule);
    font-size:0.84375rem; color:var(--muted);
  }
  .footer a, .alt a { color:var(--muted); }
  code {
    font-family:var(--mono); font-size:0.875em; background:var(--wash);
    border:1px solid var(--rule-2); border-radius:2px; padding:0.1em 0.35em;
  }
</style>"""


_AUTH_HTML = """\
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize a client — Skarp CRA</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
{{style}}</head><body>
<div class="brand">Skarp CRA</div>
<h1>Authorize a client</h1>
<p class="subtitle">Connecting <b>{{client}}</b> as party <b>{{party}}</b>.</p>
<form method="post" action="/oauth/authorize">
{{hidden}}
  <label>Bearer token</label>
  <input type="password" name="bearer_token" placeholder="tok_{{party}}_..." autofocus required>
  <p class="hint">Paste the <code>CRA_TOKEN_{{PARTY_UPPER}}</code> value from your deployment. This proves you are authorized to act as party {{party}}.</p>
{{error}}
  <button type="submit">Authorize</button>
</form>
</body></html>
"""


# User-wide consent. Shown when the caller has a valid session cookie. One
# click → mint a fresh user-wide `cra_*` token tied to the user, return it to
# the OAuth client.
#
# The capability list below is what the token actually grants — the tool
# surface in `server/tools.py`. It is a consent screen, so it has to stay true
# to that list; a stale one is a misrepresentation, not a cosmetic wart.
#
# The Terms / Privacy links are same-origin paths, served as static files by
# Caddy from /var/cra-www rather than by this app. Relative on purpose: the
# consent page is reached on whatever host the deployment answers on, and a
# hardcoded origin would send a user to the wrong one — or to a dead link in a
# deployment that has not published the site.
_USER_AUTH_HTML = """\
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize {{client}} — Skarp CRA</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
{{style}}</head><body>
<div class="brand">Skarp CRA</div>
<h1>Authorize {{client}}</h1>
<p class="subtitle">{{client}} is asking for permission to access your CRA compliance records.</p>
<div class="you">Signed in as <b>{{user_email}}</b></div>
<div class="grant">
<p>If you continue, {{client}} can, for every product you are a member of:</p>
<ul>
  <li>Read your compliance status, requirements, evidence and reporting deadlines</li>
  <li>Record vulnerabilities and incidents, which starts statutory reporting clocks</li>
  <li>Draft reports, freeze the technical file, and sign off on your behalf</li>
</ul>
</div>
<p>Every action is written to the audit trail against your name. To revoke
this connection, email <a href="mailto:cra@skarp.app">cra@skarp.app</a>.</p>
<form method="post" action="/oauth/authorize">
{{hidden}}
{{error}}
  <button type="submit">Authorize</button>
  <a href="{{cancel_url}}"><button type="button" class="cancel">Cancel</button></a>
</form>
<div class="footer">
  Not you? <a href="{{relogin_url}}">Sign in as a different user</a>.
  <br>
  By authorizing you agree to the <a href="/terms.html" target="_blank" rel="noopener">Terms of Service</a> and <a href="/privacy.html" target="_blank" rel="noopener">Privacy</a>.
</div>
</body></html>
"""


# Connector-token sign-in + consent, in one page.
#
# The fallback, not the front door, since emailed codes landed: it stays
# because existing users hold tokens, and because it is the only way in if mail
# delivery is broken — which would otherwise take the whole connector flow down
# with it. Reached from the email page's "paste a connector token instead".
#
# No external assets: this page is the one thing a user sees before granting
# access to unreported vulnerability records, and it should not depend on
# another host being up, or leak a referrer to one.
_TOKEN_AUTH_HTML = """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authorize {{client}} — Skarp CRA</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
{{style}}</head><body>
<div class="brand">Skarp CRA</div>
<h1>Authorize {{client}}</h1>
<p class="subtitle">{{client}} is asking to connect to your Skarp CRA account.</p>
<div class="grant">
<p>If you continue, {{client}} can, acting as you:</p>
<ul>
  <li>Read and change your product and compliance records</li>
  <li>Record vulnerabilities and incidents, including unreported ones</li>
  <li>Draft reports and conformity evidence on your behalf</li>
</ul>
</div>
<form method="post" action="/oauth/authorize" autocomplete="off">
{{hidden}}
  <label for="connector_token">Your connector token</label>
  <input type="password" id="connector_token" name="connector_token"
         placeholder="cra_..." autocomplete="off" spellcheck="false" autofocus required>
  <p class="hint">The <code>cra_…</code> token issued for your account. It identifies
  you to this service; authorizing creates a <b>separate</b> token for {{client}},
  which you can revoke on its own without affecting the one you paste here.</p>
{{error}}
  <button type="submit">Authorize</button>
  <a href="{{cancel_url}}"><button type="button" class="cancel">Cancel</button></a>
</form>
</body></html>
"""


# Email sign-in + consent. The default way in.
#
# Two states, one template: ask for an address, then ask for the code mailed to
# it. The capability list is on both, because the second submit is the act of
# consent — there is no third "Approve" page, and there shouldn't be. The user
# went to their inbox and fetched a code specifically for this client, whose
# name the email also carries. A click-through after that adds ceremony, not
# information.
#
# Why not a magic link here: see `signup.py`. The link would open on a phone
# while the OAuth flow waits in a laptop tab, and the callback would land in a
# browser with no client session.
#
# No external assets: this page is the one thing a user sees before granting
# access to unreported vulnerability records, and it should not depend on
# another host being up, or leak a referrer to one.
_EMAIL_AUTH_HTML = """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authorize {{client}} — Skarp CRA</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
{{style}}</head><body>
<div class="brand">Skarp CRA</div>
<h1>Authorize {{client}}</h1>
<p class="subtitle">{{client}} is asking to connect to your Skarp CRA account.</p>
<div class="grant">
<p>If you continue, {{client}} can, acting as you:</p>
<ul>
  <li>Read and change your product and compliance records</li>
  <li>Record vulnerabilities and incidents, including unreported ones</li>
  <li>Draft reports and conformity evidence on your behalf</li>
</ul>
</div>
<form method="post" action="/oauth/authorize" autocomplete="off">
{{hidden}}
{{form}}
{{error}}
  <button type="submit">{{submit}}</button>
  <a href="{{cancel_url}}"><button type="button" class="cancel">Cancel</button></a>
</form>
<p class="alt">{{alt}}</p>
</body></html>
"""


# Bake the shared stylesheet into every page template. Done once, at import
# time, so no render path can forget it and ship an unstyled credential page.
_AUTH_HTML = _AUTH_HTML.replace("{{style}}", _CONSENT_STYLE)
_USER_AUTH_HTML = _USER_AUTH_HTML.replace("{{style}}", _CONSENT_STYLE)
_TOKEN_AUTH_HTML = _TOKEN_AUTH_HTML.replace("{{style}}", _CONSENT_STYLE)
_EMAIL_AUTH_HTML = _EMAIL_AUTH_HTML.replace("{{style}}", _CONSENT_STYLE)

_EMAIL_STEP = """\
  <input type="hidden" name="step" value="email">
  <label for="email">Your email address</label>
  <input type="email" id="email" name="email" autocomplete="email"
         spellcheck="false" autofocus required>
  <p class="hint">We will send a six-digit code to confirm it is you. If you
  have not used Skarp CRA before, this creates your account.</p>
"""

_CODE_STEP = """\
  <input type="hidden" name="step" value="code">
  <label for="code">Code sent to {{email}}</label>
  <input type="text" id="code" name="code" class="code" inputmode="numeric"
         pattern="[0-9 ]*" autocomplete="one-time-code" maxlength="7"
         autofocus required>
  <p class="hint">Entering the code authorizes {{client}}. It creates a token
  belonging to {{client}} alone, which you can revoke without affecting
  anything else. The code expires in a few minutes.</p>
"""


def _render_form(*, client_id: str, party: str, hidden_fields: dict[str, str], error: Optional[str] = None, status: int = 200) -> Response:
    """Render the legacy paste-static-bearer form (POC operator path)."""
    hidden = "\n".join(
        f'  <input type="hidden" name="{k}" value="{_html_escape(v)}">'
        for k, v in hidden_fields.items()
        if v is not None
    )
    error_html = f'<div class="error">{_html_escape(error)}</div>' if error else ""
    html = (
        _AUTH_HTML
        .replace("{{client}}", _html_escape(client_id or "client"))
        .replace("{{party}}", _html_escape(party))
        .replace("{{PARTY_UPPER}}", party.upper())
        .replace("{{hidden}}", hidden)
        .replace("{{error}}", error_html)
    )
    return HTMLResponse(html, status_code=status)


def _client_name(client_id: str) -> str:
    """Friendly name a client registered via DCR, falling back to its id."""
    record = _client_record(client_id) or {}
    return record.get("client_name") or client_id or "OAuth client"


def _switch_account_url(from_path_qs: str) -> str:
    """URL that re-runs authorize while ignoring any session cookie.

    This is the "not you?" escape hatch on the cookie consent page. It cannot
    point at a login page, because this deployment has none — so it points back
    here with `switch_account=1`, which forces the connector-token form.
    """
    qs = urlencode({**dict(parse_qsl(from_path_qs)), "switch_account": "1"})
    return f"/oauth/authorize?{qs}"


def _render_user_form(
    *,
    client_id: str,
    client_name: str,
    user_email: str,
    hidden_fields: dict[str, str],
    cancel_url: str,
    relogin_url: str,
    error: Optional[str] = None,
    status: int = 200,
) -> Response:
    """Render the user-wide consent page for signed-in users.

    `relogin_url` is where "sign in as a different user" goes — built by
    `_switch_account_url`, which comes back here and asks for a connector
    token instead, because there is no login page to send anyone to.
    """
    hidden = "\n".join(
        f'  <input type="hidden" name="{k}" value="{_html_escape(v)}">'
        for k, v in hidden_fields.items()
        if v is not None
    )
    error_html = f'<div class="error">{_html_escape(error)}</div>' if error else ""
    # Display name: prefer DCR-registered client_name, fall back to client_id, then "the connector".
    display = client_name or client_id or "the connector"
    html = (
        _USER_AUTH_HTML
        .replace("{{client}}", _html_escape(display))
        .replace("{{user_email}}", _html_escape(user_email))
        .replace("{{hidden}}", hidden)
        .replace("{{error}}", error_html)
        .replace("{{cancel_url}}", _html_escape(cancel_url or "/"))
        .replace("{{relogin_url}}", _html_escape(relogin_url))
    )
    return HTMLResponse(html, status_code=status)


def _verified_user_from_cookie(request: Request) -> Optional[sso.User]:
    """Read `coauthor_session` cookie and return the upserted User row, or None.

    None covers: no cookie, expired JWT, malformed JWT, no DB row yet. Caller
    decides what to do (typically: redirect to /login for the user-wide flow).
    """
    cookie = request.cookies.get("coauthor_session")
    if not cookie:
        return None
    try:
        verified = sso.verify_token(cookie)
    except sso.SsoError:
        return None
    return sso.get_user(verified.user_id)


class _TokenSignInError(Exception):
    """A presented connector token cannot identify a user for the OAuth grant."""


def _user_from_connector_token(presented: str) -> sso.User:
    """Resolve a pasted `cra_…` connector token to the user it belongs to.

    Raises `_TokenSignInError` with a message safe to show the browser.

    Deliberately refuses product-scoped tokens. The grant this flow issues is
    user-wide, so honouring a narrowly-scoped token here would let a token that
    can only touch one product mint one that can touch everything — privilege
    escalation through the consent screen.
    """
    presented = (presented or "").strip()
    if not presented:
        raise _TokenSignInError("Paste your connector token to continue.")
    if not connector_tokens.is_connector_token(presented):
        raise _TokenSignInError("That does not look like a connector token.")
    try:
        verified = connector_tokens.verify_token(presented)
    except connector_tokens.TokenRevoked:
        raise _TokenSignInError("That token has been revoked.") from None
    except connector_tokens.TokenExpired:
        raise _TokenSignInError("That token has expired.") from None
    except connector_tokens.TokenError:
        # Do not distinguish "no such token" from "wrong token" — that is a
        # guessing oracle.
        raise _TokenSignInError("That token was not accepted.") from None

    if verified.product_id is not None:
        raise _TokenSignInError(
            "That token is scoped to a single product. Authorizing an app "
            "needs an account-wide token."
        )

    user = sso.get_user(verified.user_id)
    if user is None:
        raise _TokenSignInError("That token's account no longer exists.")
    return user


def _render_token_form(
    *,
    client_id: str,
    hidden_fields: dict[str, str],
    cancel_url: str,
    error: Optional[str] = None,
    status: int = 200,
) -> Response:
    """Render the connector-token sign-in + consent page."""
    hidden = "\n".join(
        f'  <input type="hidden" name="{k}" value="{_html_escape(v)}">'
        for k, v in hidden_fields.items()
    )
    error_html = f'<p class="error">{_html_escape(error)}</p>' if error else ""
    client = _html_escape(_client_name(client_id))
    html = (
        _TOKEN_AUTH_HTML
        .replace("{{client}}", client)
        .replace("{{hidden}}", hidden)
        .replace("{{cancel_url}}", _html_escape(cancel_url))
        .replace("{{error}}", error_html)
    )
    return HTMLResponse(html, status_code=status)


@dataclass(frozen=True)
class _Identity:
    """Who the consent page decided it is talking to.

    Both sign-in paths converge here so the grant below cannot accidentally
    depend on which one was used.
    """

    id: str
    email: str


def _base(hidden_fields: dict[str, str]) -> dict[str, str]:
    """The OAuth request without the sign-in progress layered on top."""
    return {
        k: v for k, v in hidden_fields.items()
        if k not in ("challenge_id", "email", "code", "step", "signin")
    }


def _authorize_url(hidden_fields: dict[str, str], **extra: str) -> str:
    """Re-enter authorize with the OAuth parameters intact.

    Every escape hatch on these pages has to carry the whole OAuth request with
    it. Dropping a parameter sends the user back to the client to start over,
    which reads as "this connector is broken".
    """
    params = {k: v for k, v in {**hidden_fields, **extra}.items() if v}
    return f"/oauth/authorize?{urlencode(params)}"


def _render_email_form(
    *,
    client_id: str,
    hidden_fields: dict[str, str],
    cancel_url: str,
    error: Optional[str] = None,
    status: int = 200,
) -> Response:
    """Step one: ask for an address."""
    return _render_email_page(
        client_id=client_id,
        hidden_fields=hidden_fields,
        cancel_url=cancel_url,
        form=_EMAIL_STEP,
        submit="Send me a code",
        alt=(
            'Already have a <code>cra_…</code> token? '
            f'<a href="{_html_escape(_authorize_url(hidden_fields, signin="token"))}">'
            "Paste it instead</a>."
        ),
        error=error,
        status=status,
    )


def _render_code_form(
    *,
    client_id: str,
    email: str,
    hidden_fields: dict[str, str],
    cancel_url: str,
    error: Optional[str] = None,
    status: int = 200,
) -> Response:
    """Step two: ask for the code that was mailed."""
    client = _html_escape(_client_name(client_id))
    form = (
        _CODE_STEP
        .replace("{{email}}", _html_escape(email))
        .replace("{{client}}", client)
    )
    return _render_email_page(
        client_id=client_id,
        hidden_fields=hidden_fields,
        cancel_url=cancel_url,
        form=form,
        submit=f"Authorize {_client_name(client_id)}",
        alt=(
            f'<a href="{_html_escape(_authorize_url(_base(hidden_fields)))}">'
            "Use a different address</a>, or request a new code from there if "
            "this one did not arrive."
        ),
        error=error,
        status=status,
    )


def _render_email_page(
    *,
    client_id: str,
    hidden_fields: dict[str, str],
    cancel_url: str,
    form: str,
    submit: str,
    alt: str,
    error: Optional[str],
    status: int,
) -> Response:
    hidden = "\n".join(
        f'  <input type="hidden" name="{k}" value="{_html_escape(v)}">'
        for k, v in hidden_fields.items()
        if v is not None
    )
    error_html = f'<p class="error">{_html_escape(error)}</p>' if error else ""
    html = (
        _EMAIL_AUTH_HTML
        .replace("{{client}}", _html_escape(_client_name(client_id)))
        .replace("{{hidden}}", hidden)
        .replace("{{form}}", form)
        .replace("{{submit}}", _html_escape(submit))
        .replace("{{alt}}", alt)
        .replace("{{cancel_url}}", _html_escape(cancel_url))
        .replace("{{error}}", error_html)
    )
    return HTMLResponse(html, status_code=status)


async def authorize_get(request: Request) -> Response:
    qp = request.query_params
    client_id = qp.get("client_id", "")
    redirect_uri = qp.get("redirect_uri", "")
    state = qp.get("state", "")
    code_challenge = qp.get("code_challenge", "")
    code_challenge_method = qp.get("code_challenge_method", "")
    response_type = qp.get("response_type", "")
    resource = qp.get("resource", "")
    scope = qp.get("scope", "")

    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    if code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "PKCE S256 required"},
            status_code=400,
        )
    if not redirect_uri:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri required"},
            status_code=400,
        )
    # Open-redirect defense (see `_redirect_uri_allowed` for rationale).
    # Reject BEFORE rendering any HTML or bouncing the user-agent.
    if not _redirect_uri_allowed(redirect_uri):
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": (
                    "redirect_uri host is not on the OAuth allowlist"
                ),
            },
            status_code=400,
        )
    if not _redirect_uri_registered(client_id, redirect_uri):
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": (
                    "redirect_uri does not match any registered URI for this client"
                ),
            },
            status_code=400,
        )

    # Branch: legacy POC path requires an explicit `party` signal (either as a
    # query param or via a `/mcp/<party>/mcp` resource URL). Anything else
    # falls through to the user-wide path. Default DOES NOT pre-select party "a"
    # anymore — that was the bug that silently broke every existing connection.
    legacy_party = qp.get("party") or _party_from_resource(resource)

    common_hidden = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "response_type": response_type,
        "resource": resource,
        "scope": scope,
    }

    if legacy_party:
        # Operator path — show the paste-static-bearer form, unchanged.
        return _render_form(
            client_id=client_id,
            party=legacy_party,
            hidden_fields={**common_hidden, "party": legacy_party},
        )

    # The "Cancel" button takes the user back to the OAuth client's redirect
    # URI with `error=access_denied` per RFC 6749 §4.1.2.1. We don't have the
    # full URL handy here without parsing — keep it simple: just redirect to
    # the redirect_uri. The client (Claude.ai / Codex) will figure out what to
    # do with an empty success param.
    sep = "&" if "?" in redirect_uri else "?"
    cancel_url = f"{redirect_uri}{sep}{urlencode({'error': 'access_denied', 'state': state})}"

    # User-wide path. A session cookie is honoured when one is present and SSO
    # is configured, but this deployment has neither a login page nor an SSO
    # secret, so in practice one of the two forms below is the way in.
    user = None if qp.get("switch_account") else _verified_user_from_cookie(request)
    if user is None:
        # Email is the default; the token form is reachable from it, and is
        # forced when self-serve is switched off — an address cannot be proven
        # on a deployment that will not mail anyone.
        if qp.get("signin") == "token" or not signup.signup_enabled():
            return _render_token_form(
                client_id=client_id,
                hidden_fields=common_hidden,
                cancel_url=cancel_url,
            )
        return _render_email_form(
            client_id=client_id,
            hidden_fields=common_hidden,
            cancel_url=cancel_url,
        )

    return _render_user_form(
        client_id=client_id,
        client_name=_client_name(client_id),
        user_email=user.email,
        hidden_fields=common_hidden,  # no `party` — that's how the POST routes
        cancel_url=cancel_url,
        relogin_url=_switch_account_url(request.url.query),
    )


async def authorize_post(request: Request) -> Response:
    form = await request.form()
    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")
    state = form.get("state", "")
    code_challenge = form.get("code_challenge", "")
    code_challenge_method = form.get("code_challenge_method", "")
    response_type = form.get("response_type", "")
    resource = form.get("resource", "")
    scope = form.get("scope", "")
    # `party` presence is the discriminator between legacy + user-wide paths.
    # Empty string == user-wide (the GET handler did NOT auto-default to "a"
    # for the user-wide branch, and the consent form doesn't carry a party
    # hidden field).
    party = (form.get("party") or "").strip()

    # Open-redirect defense — same as authorize_get. We re-check on POST
    # because a malicious page could craft its own form submission that
    # bypasses the GET-time check.
    if not redirect_uri or not _redirect_uri_allowed(redirect_uri):
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": (
                    "redirect_uri host is not on the OAuth allowlist"
                ),
            },
            status_code=400,
        )
    if not _redirect_uri_registered(client_id, redirect_uri):
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": (
                    "redirect_uri does not match any registered URI for this client"
                ),
            },
            status_code=400,
        )

    common_hidden = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "response_type": response_type,
        "resource": resource,
        "scope": scope,
    }

    if party:
        # ---- Legacy POC path (operators only) -------------------------------
        bearer_token = (form.get("bearer_token") or "").strip()
        expected = token_for_party(party)
        legacy_hidden = {**common_hidden, "party": party}

        if not expected:
            return _render_form(
                client_id=client_id, party=party, hidden_fields=legacy_hidden,
                error=f"server misconfigured: CRA_TOKEN_{party.upper()} not set",
                status=503,
            )
        if not bearer_token or not secrets.compare_digest(bearer_token, expected):
            return _render_form(
                client_id=client_id, party=party, hidden_fields=legacy_hidden,
                error="Token did not match. Try again.",
                status=401,
            )

        access_token = expected
        _gc_codes()
        code = secrets.token_urlsafe(32)
        _codes[code] = {
            "access_token": access_token,
            "code_challenge": code_challenge,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "created_at": time.time(),
            # Audit-only — what kind of grant produced this code:
            "kind": "legacy_party",
            "party_id": party,
        }
        sep = "&" if "?" in redirect_uri else "?"
        redirect = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state})}"
        return RedirectResponse(redirect, status_code=302)

    # ---- User-wide path (default) ------------------------------------------
    sep = "&" if "?" in redirect_uri else "?"
    cancel_url = f"{redirect_uri}{sep}{urlencode({'error': 'access_denied', 'state': state})}"

    cookie_user = _verified_user_from_cookie(request)
    identity = (
        _Identity(id=cookie_user.id, email=cookie_user.email) if cookie_user else None
    )

    # Which form came back. Failure always re-renders the same step with the
    # OAuth state intact — losing it would send the user back to the client to
    # start over, which reads as a broken connector rather than a typo.
    step = (form.get("step") or "").strip()

    if identity is None and step == "email":
        email = str(form.get("email") or "")
        try:
            challenge_id = signup.start_code_challenge(
                email, client_name=_client_name(client_id)
            )
        except signup.SignupError as e:
            return _render_email_form(
                client_id=client_id,
                hidden_fields=common_hidden,
                cancel_url=cancel_url,
                error=str(e),
                status=400,
            )
        return _render_code_form(
            client_id=client_id,
            email=signup.normalise_email(email),
            hidden_fields={
                **common_hidden,
                "challenge_id": challenge_id,
                "email": signup.normalise_email(email),
            },
            cancel_url=cancel_url,
        )

    if identity is None and step == "code":
        challenge_id = str(form.get("challenge_id") or "")
        email = str(form.get("email") or "")
        code_hidden = {
            **common_hidden,
            "challenge_id": challenge_id,
            "email": email,
        }
        try:
            proven = signup.verify_code(challenge_id, str(form.get("code") or ""))
        except signup.SignupError as e:
            return _render_code_form(
                client_id=client_id,
                email=email,
                hidden_fields=code_hidden,
                cancel_url=cancel_url,
                error=str(e),
                status=401,
            )
        identity = _Identity(id=proven["user_id"], email=proven["email"])

    if identity is None:
        # The fallback form: a pasted connector token.
        try:
            signed_in = _user_from_connector_token(form.get("connector_token") or "")
        except _TokenSignInError as e:
            return _render_token_form(
                client_id=client_id,
                hidden_fields=common_hidden,
                cancel_url=cancel_url,
                error=str(e),
                status=401,
            )
        identity = _Identity(id=signed_in.id, email=signed_in.email)

    user = identity

    # Mint a fresh user-wide cra_* token tied to this user. Label includes the
    # OAuth client_name so the user can find and revoke it later.
    client_name = _client_name(client_id)
    label = f"OAuth: {client_name}"
    try:
        plaintext, _row = connector_tokens.mint_token(
            user_id=user.id,
            product_id=None,  # user-wide
            label=label,
        )
    except Exception:  # noqa: BLE001
        # The exception text can carry database detail; log it, show the user a
        # generic failure and let them retry without losing the OAuth state.
        log.exception("could not mint OAuth token for client %s", client_id)
        return _render_token_form(
            client_id=client_id,
            hidden_fields=common_hidden,
            cancel_url=cancel_url,
            error="Could not issue a token. Please try again.",
            status=500,
        )

    _gc_codes()
    code = secrets.token_urlsafe(32)
    _codes[code] = {
        "access_token": plaintext,
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "created_at": time.time(),
        # Audit:
        "kind": "user_wide",
        "user_id": user.id,
    }
    sep = "&" if "?" in redirect_uri else "?"
    redirect = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state})}"
    return RedirectResponse(redirect, status_code=302)


# ---- Token endpoint -----------------------------------------------------------


async def token_endpoint(request: Request) -> Response:
    form = await request.form()
    grant_type = form.get("grant_type", "")
    code = form.get("code", "")
    code_verifier = form.get("code_verifier", "")
    redirect_uri = form.get("redirect_uri", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    _gc_codes()
    record = _codes.pop(code, None)
    if record is None:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "code unknown or expired"},
            status_code=400,
        )

    if record["redirect_uri"] != redirect_uri:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    if not _verify_pkce_s256(code_verifier, record["code_challenge"]):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )

    return JSONResponse(
        {
            "access_token": record["access_token"],
            "token_type": "Bearer",
            "expires_in": _ACCESS_TOKEN_TTL,
            "scope": "mcp",
        }
    )
