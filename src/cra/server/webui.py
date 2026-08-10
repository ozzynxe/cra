"""Shared page chrome for everything this app renders itself.

`/pricing`, `/billing` and the console all draw the same header, footer and
stylesheet. Two copies would drift, and the copy that drifts is always the one
with the security-relevant header on it.

## The CSP is the reason this is a module

Pages served from disk get a Content-Security-Policy from Caddy's static
handler. Pages rendered here do not — they are proxied, and the `@api` block
sets no policy. So it is set per-response, here, once.

`style-src 'self'` and nothing else: no inline styles, no scripts at all, no
external anything. The console has no JavaScript by design, so `default-src
'none'` costs nothing and rules out an entire class of mistake in pages that
display unreported vulnerability records.

The OAuth consent page is the exception and keeps its own chrome, because it
carries an inline `<style>` — an unstyled page asking for a credential is
exactly what users are told to distrust.

## Chrome shape

The shell is masthead → `<main>` → sitefoot, matching the static pages in
`www/` so that crossing from `/` to `/pricing` to `/app` does not change the
furniture. Callers hand in the contents of `<main>`. By default it is wrapped
in a `<section class="wrap">`; the report page passes `wrap=False` because it
supplies its own `<article class="report">`, which is a fixed 816px column
rather than the 1100px page measure.

The disclaimer in the footer is not decoration. Every domain page has to carry
it, and putting it in one place is how that stays true.
"""

from __future__ import annotations

import html as _html
from typing import Optional

from starlette.responses import HTMLResponse, Response

def _csp(form_action: str = "'self'") -> str:
    """The policy header, with `form-action` the only part any page varies.

    **`form-action` governs redirects, not just the POST target**, and that is
    not obvious. A form here posts same-origin, the handler answers `303` to
    somewhere else, and the browser checks the *redirect destination* against
    this directive — then blocks the navigation silently if it does not match.
    No error page, nothing in the server log, only a console warning. The
    server records a successful redirect and the user sees a page that did not
    move.

    That is what happened to `/billing`: `verify_code` spent the one-time code,
    Stripe returned a checkout URL, the 303 went out, and Chrome refused it
    because `checkout.stripe.com` is not `'self'`. Pressing the button again
    then met "that code has been used".

    So it stays `'self'` everywhere by default — the console lists unreported
    vulnerabilities and should not be able to post them anywhere — and only the
    billing pages widen it, to the two Stripe hosts they actually redirect to.
    """
    return (
        "default-src 'none'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        f"form-action {form_action}; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"
    )


CSP = _csp()

_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Skarp CRA</title>
<meta name="description" content="{description}">
<meta name="referrer" content="no-referrer">
{robots}
<link rel="stylesheet" href="/style.css">
</head>
<body{body_class}>
{masthead}<main>
{body}
</main>
{sitefoot}</body>
</html>"""

_MASTHEAD = """<header class="masthead">
  <div class="wrap">
    <a class="brand" href="{home}">Skarp CRA</a>
    <nav>
{nav}
    </nav>
  </div>
</header>
"""

_SITEFOOT = """<footer class="sitefoot">
  <div class="wrap">
    <p>{disclaimer}</p>
    <nav>
{footer}
    </nav>
  </div>
</footer>
"""

_DISCLAIMER = (
    "Skarp CRA is a working aid. It records what you have decided and "
    "evidenced and shows what is missing; it cannot certify conformity or "
    "replace a notified body."
)

_PUBLIC_NAV = (
    '      <a href="/#covers">What it covers</a>\n'
    '      <a href="/pricing">Pricing</a>\n'
    '      <a href="/billing">Billing</a>\n'
    '      <a class="btn cta small" href="/#access">Start free</a>'
)

_PUBLIC_FOOTER = (
    '      <a href="/">Home</a>\n'
    '      <a href="/coverage">Coverage</a>\n'
    '      <a href="/terms.html">Terms</a>\n'
    '      <a href="/privacy.html">Privacy</a>\n'
    '      <a href="mailto:cra@skarp.app">cra@skarp.app</a>'
)


def _signed_in_nav(email: str) -> str:
    # Logout is a POST. As a GET it would be triggerable by any image tag on any
    # page — harmless but irritating, and the fix is one form. `.linklike`
    # exists so the button sits in a row of nav links without announcing itself
    # as a different kind of thing.
    return (
        '      <a href="/app">Products</a>\n'
        '      <a href="/pricing">Pricing</a>\n'
        '      <a href="/billing">Billing</a>\n'
        f'      <span class="small muted">{_html.escape(email)}</span>\n'
        '      <form method="post" action="/app/logout" class="inline">'
        '<button class="linklike" type="submit">Sign out</button></form>'
    )


def page(
    title: str,
    body: str,
    *,
    status: int = 200,
    description: str = "",
    indexable: bool = False,
    wide: bool = False,
    narrow: bool = False,
    wrap: bool = True,
    chrome: bool = True,
    body_class: str = "",
    signed_in_as: Optional[str] = None,
    form_action: str = "'self'",
) -> Response:
    """Render a page with the shared chrome and the policy header.

    `chrome=False` drops the masthead and footer. Exactly one page uses it —
    the token display — because every link out of that page is a way to lose a
    credential that is shown once and cannot be recovered.
    """
    if wrap:
        measure = " wide" if wide else " narrow" if narrow else ""
        body = f'<section class="wrap{measure}">\n{body}\n</section>'
    html = _SHELL.format(
        title=_html.escape(title),
        description=_html.escape(description),
        robots="" if indexable else '<meta name="robots" content="noindex">',
        body_class=f' class="{_html.escape(body_class)}"' if body_class else "",
        masthead=_MASTHEAD.format(
            home="/app" if signed_in_as else "/",
            nav=_signed_in_nav(signed_in_as) if signed_in_as else _PUBLIC_NAV,
        ) if chrome else "",
        sitefoot=_SITEFOOT.format(
            footer=_PUBLIC_FOOTER, disclaimer=_DISCLAIMER
        ) if chrome else "",
        body=body,
    )
    return HTMLResponse(
        html,
        status_code=status,
        headers={
            "Content-Security-Policy": _csp(form_action),
            # A console page lists products and open vulnerabilities. Nothing
            # here should sit in a shared cache or a browser's back-forward
            # store after a sign-out.
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


def section(body: str, *, measure: str = "") -> str:
    """One page block.

    Vertical rhythm between blocks comes from `section`'s bottom padding, not
    from margins on whatever happens to be last inside one. A page with more
    than one idea on it emits several of these and passes `wrap=False`; a page
    with exactly one (a form, an error) lets `page()` wrap it.
    """
    return f'<section class="wrap{(" " + measure) if measure else ""}">\n{body}\n</section>'


def esc(value) -> str:
    return _html.escape("" if value is None else str(value))
