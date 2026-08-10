"""The three pages of self-serve access.

    GET  /access                  the form
    POST /api/access/request      → "check your email"
    GET  /api/access/complete     → the token, once

Plain HTML forms and full page loads, no JavaScript. Partly because the static
site ships a `default-src 'none'` CSP and a scripted flow would need it
loosened, and partly because a page that shows a credential exactly once should
not depend on a fetch succeeding.

The token page is rendered by the application rather than by Caddy, which is
the whole reason these routes exist in the app at all: it is the only page here
that has ever seen a secret.

## Why the token page looks like nothing else on the site

It is the highest-stakes screen here: miss it and the credential is gone, and
the user has to start again. So it is the one page that renders on an inverted
ground whatever the visitor's colour scheme, with no masthead and no footer —
nothing to click that is not the thing they came for — and the "shown once"
line above the heading rather than below the token.

There is no copy button, because there is no JavaScript. Selecting the text
works. A control that only appears to work is worse than no control on the one
page where a mistake cannot be undone.
"""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import Response

from cra.server import signup, webui
from cra.server.webui import esc

log = logging.getLogger(__name__)


def _invite_field(value: str = "") -> str:
    if not signup._required_invite_code():
        return ""
    return (
        "<div>"
        '<label for="invite">Invite code</label>'
        f'<input type="text" id="invite" name="invite_code" value="{esc(value)}" '
        'required autocomplete="off" spellcheck="false">'
        "</div>"
    )


def _access_form(*, email: str = "", invite: str = "", error: str = "") -> str:
    """The form itself, so the error path can re-render it with what was typed.

    The homepage posts straight here with only an email. When a deployment
    requires an invite code that submission fails, and the recovery has to be
    this page with the address still in the field — otherwise the visitor types
    it twice to learn about a field the homepage could not know existed.
    """
    return (
        "<div class='stack'>"
        "<h1>Get a connector token</h1>"
        "<p class='lede'>Enter your email and we will send a single-use link. "
        "It shows you a connector token — the only time it is shown.</p>"
        + (f"<p class='error'>{esc(error)}</p>" if error else "")
        # The faster path first, and phrased as a shortcut rather than a
        # disclaimer. Most people arriving here want to connect a client, not
        # to hold a credential, so the one-line route is the right default and
        # the email round-trip is the fallback.
        + "<div class='card'><p class='small'><strong>Quicker, if you are "
        "connecting an app:</strong> in Claude, ChatGPT or any client with a "
        "connector list, add <code>https://cra.skarp.app/mcp</code> "
        "there instead. It verifies your email with a short code and handles "
        "the credential itself, so there is nothing to copy or store. A token "
        "here is for scripts, CI jobs and anything that cannot open a "
        "browser.</p></div>"
        '<form class="stack" method="post" action="/api/access/request">'
        "<div>"
        '<label for="email">Email</label>'
        f'<input type="email" id="email" name="email" value="{esc(email)}" required '
        'autofocus autocomplete="email" spellcheck="false">'
        "</div>"
        + _invite_field(invite)
        + '<p class="small muted">By continuing you agree to the '
        '<a href="/terms.html">Terms of Service</a> and '
        '<a href="/privacy.html">Privacy</a>.</p>'
        '<p><button class="btn cta" type="submit">Send my link</button></p>'
        "</form>"
        "<p class='small muted'>Already have an account and lost your token? "
        "Same form — it issues a new one.</p>"
        "</div>"
    )


async def access_form(request: Request) -> Response:
    """The form. Also the 'I lost my token' path — same flow, no separate
    reset to rot from disuse."""
    if not signup.signup_enabled():
        return webui.page(
            "Access",
            "<div class='stack'>"
            "<h1>Access is not self-serve here</h1>"
            "<p class='lede'>This deployment has self-serve access switched "
            'off. Write to <a href="mailto:cra@skarp.app">cra@skarp.app</a>.</p>'
            "</div>",
            status=403,
            narrow=True,
        )
    return webui.page("Get access", _access_form(), narrow=True)


async def request_access(request: Request) -> Response:
    form = await request.form()
    email = str(form.get("email") or "")
    invite = str(form.get("invite_code") or "")
    try:
        result = signup.request_access(email, invite_code=invite)
    except signup.SignupError as e:
        return webui.page(
            "Get access",
            _access_form(email=email, invite=invite, error=str(e)),
            status=400,
            narrow=True,
        )
    return webui.page(
        "Check your email",
        "<div class='stack'>"
        "<h1>Check your email</h1>"
        f"<p class='lede'>{esc(result['message'])}</p>"
        "<p class='muted'>Nothing is created until you open the link. If it "
        "does not arrive, check spam — it comes from "
        "<code>alerts@skarp.app</code>.</p>"
        "</div>",
        narrow=True,
    )


async def complete(request: Request) -> Response:
    presented = request.query_params.get("t", "")
    try:
        out = signup.complete(presented)
    except signup.SignupError as e:
        return webui.page(
            "Link not valid",
            "<div class='stack'>"
            f"<h1>That link is not usable</h1><p class='lede'>{esc(e)}</p>"
            '<p><a class="btn cta" href="/access">Request a new one</a></p>'
            "</div>",
            status=400,
            narrow=True,
        )

    token = esc(out["token"])
    greeting = "Your account is ready" if out["new_account"] else "Here is a new token"
    return webui.page(
        "Your connector token",
        "<div class='stack'>"
        "<p class='once'>Shown once — this page cannot be reopened</p>"
        f"<h1>{greeting}</h1>"
        "<p class='muted'>We do not store a copy — only a hash — so it cannot "
        "be recovered. If you leave this page without saving it, request a new "
        "link and this one stops working.</p>"
        "<div class='credential'>"
        "<p class='eyebrow'>Connector token</p>"
        f"<code>{token}</code>"
        "</div>"
        "<p class='small muted'>Add it to your agent:</p>"
        "<pre class='term'>claude mcp add --transport http skarp-cra \\\n"
        "  https://cra.skarp.app/mcp \\\n"
        f'  --header "Authorization: Bearer {token}"</pre>'
        "<p class='small muted'>Then ask your agent what the Cyber Resilience "
        "Act requires of the product you ship. Start with "
        "<code>cra_overview</code>.</p>"
        "<p class='small muted'>Store it in a password manager or your CI "
        "secret store. It acts with your account's authority, and everything "
        "done with it is recorded against your name in the audit trail. Do not "
        "commit it or paste it into a shared channel.</p>"
        "</div>",
        narrow=True,
        chrome=False,
        body_class="inverted",
    )
