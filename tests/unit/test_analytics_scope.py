"""Visitor counting reaches the public pages and nothing else.

Plausible was added to measure the marketing site. The risk it carries here is
not the analytics — it is cookieless, proxied through this domain, and stores
nothing on a device — it is *where the script runs*. A console URL is
`/app/p/{uuid}/...`, and a page-view event carries the path. Putting the script
on the console would ship product identifiers to a third party from the one
surface that lists unreported exploited vulnerabilities.

So the scope is keyed off `indexable`, which already meant "this is a public
marketing page", rather than a second flag that could disagree with it. These
tests pin the consequence rather than the mechanism: whatever the flag is
called, no page carrying `noindex` may carry the counter, and no such page may
have a policy header that would let any script run.
"""

from __future__ import annotations

import pathlib
import re

from cra.server import webui

WWW = pathlib.Path(__file__).resolve().parents[2] / "www"


def test_a_public_page_is_counted():
    body = webui.page("Pricing", "<p>x</p>", indexable=True).body.decode()
    assert "/js/pa-init.js" in body
    assert "/js/pa-ABgx6h03ec2oxLWaYBeb3.js" in body


def test_the_console_is_not():
    """The one that matters. `indexable` defaults to False, so every console
    and account page takes this branch."""
    page = webui.page("Product", "<p>x</p>", signed_in_as="someone@example.test")
    body = page.body.decode()
    assert 'name="robots" content="noindex"' in body
    assert "pa-init.js" not in body
    assert "plausible" not in body.lower()


def test_a_page_that_is_not_counted_cannot_run_any_script():
    """Belt and braces, and the half that survives a templating mistake.

    If the script tag were ever reintroduced into the shared shell by accident,
    this is what stops it executing on the console: no `script-src`, under
    `default-src 'none'`, means no script from any origin at all.
    """
    csp = webui.page("Product", "<p>x</p>").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp

    public = webui.page("Pricing", "<p>x</p>", indexable=True).headers[
        "content-security-policy"
    ]
    assert "script-src 'self'" in public
    # Never the vendor host: both the script and the events are proxied by
    # Caddy. Naming plausible.io here would mean the proxy had been abandoned.
    assert "plausible.io" not in public
    assert "unsafe-inline" not in public


def test_the_endpoint_is_overridden_to_this_origin():
    """The whole proxy turns on this one line.

    The vendor script hard-codes `https://plausible.io/api/event` and does not
    derive it from its own `src`, so proxying the script alone would still send
    every event to plausible.io from the visitor's browser — while looking
    exactly like it was working. If this override is dropped, the privacy page
    and the footer both become false.
    """
    init = (WWW / "js" / "pa-init.js").read_text()
    assert re.search(r'endpoint:\s*"/pa/event"', init), init
    assert "plausible.io" not in init


def test_the_static_pages_agree_with_the_rendered_ones():
    """`www/*.html` are hand-written and `webui.page` renders the rest. Both
    carry the same two tags, and a page that gained one without the other would
    either count nothing or count without the endpoint override."""
    for page in sorted(WWW.glob("*.html")):
        html = page.read_text()
        vendor = "/js/pa-ABgx6h03ec2oxLWaYBeb3.js" in html
        init = "/js/pa-init.js" in html
        assert vendor == init, f"{page.name}: vendor={vendor} init={init}"


def test_the_footer_no_longer_claims_there_is_no_analytics():
    """The claim was on every page and is now false in one clause. It is worth
    a test because the copy and the script live in different files, and the
    version that keeps the old sentence beside the new script is the one that
    matters — a privacy claim contradicted by the page carrying it."""
    for page in sorted(WWW.glob("*.html")):
        html = page.read_text()
        if "/js/pa-init.js" not in html:
            continue
        assert "runs no analytics" not in html, page.name
        assert "no analytics or tracking of any kind" not in html, page.name
