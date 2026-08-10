"""Paying from a browser, plus the webhook Stripe talks to.

    GET  /pricing              public: the plans, priced from Stripe
    GET  /billing              start, or land here after Stripe
    POST /billing              email → code → redirect to Stripe
    POST /api/stripe/webhook   the only thing that grants a plan

## Why this exists when the agent can already do it

`get_upgrade_link` works and is right for "I have just hit a limit". It is the
wrong and only path for two other people: someone deciding whether to buy at
all, who wants a price before connecting anything; and the person who actually
pays, who on a team plan frequently has no MCP client and no reason to acquire
one to hand over money.

There is also a habit worth not teaching. If upgrading always means clicking a
payment link your AI agent produced, then a prompt-injected agent or a
lookalike connector has a ready-made channel, and the user has been trained not
to look. Typing the domain and finding the billing page there is the pattern
every other service uses, and the safer one.

## Why there is still no session

Same construction as the OAuth consent page: the intent — which plan, or "open
the portal" — is carried in hidden fields through the email/code exchange, and
the redirect to Stripe happens the moment the code is verified. Nothing is
remembered between requests, so there is no cookie, no session table and no
logout to get wrong. Doing two things means proving the address twice, which
for actions this rare is a fair trade against a session concept the rest of
this deployment does not have.

The code carries `purpose="billing"`, so one mailed to connect an app cannot
open somebody's billing page. Both prove the same address; they are not worth
the same thing.
"""

from __future__ import annotations

import html as _html
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response  # noqa: F401

from cra.db import User, session_scope
from cra.server import billing, entitlements, pricing, signup, webui

log = logging.getLogger(__name__)


# ---- the webhook -------------------------------------------------------------


async def stripe_webhook(request: Request) -> Response:
    """Verify, then hand off to `billing.handle_event`.

    Status codes here are a protocol, not decoration. Stripe retries on 5xx for
    about three days and gives up on 4xx, so:

      * a bad signature is 400 — retrying will not fix it, and this endpoint is
        unauthenticated apart from that signature;
      * a handler that could not do its job returns **200 with the failure in
        the log**, because the retry would fail identically and the useful
        outcome is a human reading the log, not three days of noise;
      * an unexpected exception is 500, so Stripe *does* retry — that is the
        case where the next attempt might genuinely work.
    """
    if not billing.is_billing_configured():
        log.warning("stripe webhook received but billing is not configured")
        return JSONResponse({"ok": False, "error": "billing not configured"}, status_code=400)

    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        event = billing.verify_webhook(payload, signature)
    except billing.WebhookSignatureError as e:
        log.warning("stripe webhook signature rejected: %s", e)
        return JSONResponse({"ok": False, "error": "bad signature"}, status_code=400)

    result = billing.handle_event(event)
    if not result.get("ok"):
        log.error("stripe webhook %s handled with error: %s", event.get("id"), result)
    return JSONResponse({"received": True}, status_code=200)


# ---- page chrome -------------------------------------------------------------


# Same chrome as the console and the static site. `/pricing` is the one page
# in this app worth indexing, so it is also the one that passes indexable=True.
#
# The one difference is `form-action`. These pages end in a 303 to Stripe, and
# that directive is checked against the *redirect destination* as well as the
# POST target — so under the default `'self'` the browser blocks the navigation
# after the code has already been spent, silently, with nothing in the server
# log. Named hosts rather than a wildcard: these are the only two places a form
# on this site is ever allowed to end up.
_STRIPE_FORM_TARGETS = "'self' https://checkout.stripe.com https://billing.stripe.com"


def _page(*args, **kwargs) -> Response:
    kwargs.setdefault("form_action", _STRIPE_FORM_TARGETS)
    return webui.page(*args, **kwargs)


# ---- /pricing ----------------------------------------------------------------


# The free tier is not a peer card.
#
# The boundary it sits on is a different kind of thing from the differences
# between the paid plans: those vary by capacity, this one by whether the legal
# act is available at all. Four cards in a row expressed none of that, so free
# is a full-width keyline block above the paid
# row, and the paid plans sit under a rule labelled with what paying buys.
#
# The €0 is the one figure on this page that is not read from Stripe, because
# it is not a Stripe product — there is nothing to charge and nothing to fetch.
# Every other number here comes from the payment provider at render time.
# screen: allow: the free tier's zero, in the block below and in line 117
# screen: allow-file money: the only amount rendered here is that zero; every
# other figure on the page is fetched from the payment provider at render time.
_FREE_ONRAMP = """
<div class="card keyline onramp">
  <div class="stack">
    <h2>Free <span class="eyebrow">No card, no expiry, one product</span></h2>
    <p>Do the whole job: scope classification, the Article 13(2) risk assessment
    and every revision of it, all 22 Annex I requirements and the Annex II user
    information with your evidence recorded against them, your SBOM scanned
    daily against OSV and CISA KEV, and the Article 14 reporting clocks if
    something happens.</p>
    <p class="small muted">Your whole team, under their own names — we do not
    charge per person. The Annex VII file renders as a gap report on the free
    plan. <a href="/sample-report">Here is one</a>.</p>
  </div>
  <div class="stack">
    <p class="price">€0</p>
    <a class="btn cta" href="/#access">Start free</a>
    <p class="small muted">One line in your MCP client.</p>
  </div>
</div>
"""


def _cadence_toggle(rows: list[dict], cadence: str) -> str:
    """Monthly / annual, as two links.

    Links rather than a control, because there is no JavaScript anywhere on
    this site — the CSP served with every page is `default-src 'none'`, and a
    toggle that did nothing would be worse than none. Each choice is a real URL,
    so it is shareable and bookmarkable, which a scripted toggle would not be.
    """
    offered: list[str] = []
    for row in rows:
        for c in row.get("prices", {}):
            if c not in offered:
                offered.append(c)
    if len(offered) < 2:
        return ""

    label = {"monthly": "Monthly", "annual": "Annual", "yearly": "Annual"}
    links = "".join(
        f'<a class="{"on" if c == cadence else ""}" href="/pricing?cadence={_html.escape(c)}">'
        f'{_html.escape(label.get(c, c.title()))}</a>'
        for c in offered
    )
    return f'<div class="cadence-toggle" role="group" aria-label="Billing period">{links}</div>'


def _plan_card(row: dict, cadence: str = "monthly") -> str:
    name = row["plan"].title()
    prices = row["prices"]
    if row["price_unavailable"]:
        # Never invent one, and never render a blank where a figure belongs —
        # a prospect reads both as a claim. See pricing.py. The button degrades
        # to a contact link, because sending someone to a checkout we cannot
        # price is worse than asking them to write to us.
        price_html = (
            "<p class='price-unavailable'>Price temporarily unavailable</p>"
            "<p class='small muted'>We could not reach our payment provider "
            "just now. Please reload, or "
            "<a href='mailto:cra@skarp.app'>ask us</a> and we will confirm "
            "it.</p>"
        )
        action = (
            "<a class='btn' href='mailto:cra@skarp.app'>Contact us</a>"
        )
    else:
        # The chosen cadence is the headline; the other is the quiet line under
        # it. Both were shown before, with monthly always the headline and
        # nothing carrying the choice through — so the page advertised an
        # annual figure that no button could actually buy.
        chosen = prices.get(cadence)
        # A plan need not be sold at every cadence: `sellable_plans()` reads
        # that off the environment. Falling back to one it *is* sold at keeps
        # the card honest and the button working, rather than rendering a blank
        # where a figure belongs.
        sold_at = cadence if chosen else next(iter(prices), cadence)
        if chosen is None:
            chosen = prices.get(sold_at)
        rest = [(c, p) for c, p in prices.items() if c != sold_at]

        interval = _html.escape((chosen.get("interval") if chosen else "") or "month")
        price_html = (
            f"<p class='price'>{_html.escape(chosen['amount'])} "
            f"<small>/ {interval}</small></p>"
            if chosen
            else ""
        )
        for other, p in rest:
            # Stripe's interval is a noun — "year" — and "billed year" is not
            # English. The headline above reads "/ year", where the noun is
            # right; this line needs the adverb.
            interval_word = p["interval"] or other
            adverb = {
                "year": "annually", "annual": "annually", "yearly": "annually",
                "month": "monthly", "monthly": "monthly",
                "week": "weekly", "day": "daily",
            }.get(interval_word, interval_word)
            price_html += (
                f"<p class='small muted'>or {_html.escape(p['amount'])} billed "
                f"{_html.escape(adverb)} — "
                f"<a href='/pricing?cadence={_html.escape(other)}'>switch</a></p>"
            )
        action = (
            '<form method="post" action="/billing">'
            # `start`, not `email`: this button carries no address, and posting
            # `step=email` made the handler try to validate an empty one and
            # answer with "That does not look like an email address" on a form
            # the visitor had not filled in yet.
            '<input type="hidden" name="step" value="start">'
            '<input type="hidden" name="action" value="subscribe">'
            f'<input type="hidden" name="plan" value="{_html.escape(row["plan"])}">'
            f'<input type="hidden" name="cadence" value="{_html.escape(sold_at)}">'
            f'<button class="btn" type="submit">Choose {_html.escape(name)}</button>'
            "</form>"
        )

    # Products only. Members used to be a bullet here and stopped being one when
    # every plan went unlimited — a line reading "Unlimited members" on all four
    # cards is noise, and the free card says it in prose where it is a selling
    # point rather than a row in a comparison nobody can lose.
    products = row["max_products"]
    limits = [
        f"{products} product{'' if products == 1 else 's'}" if products else "Unlimited products",
    ]
    # `.get` rather than `[]`: an unmapped feature constant used to 500 the
    # public pricing page, which is a poor way to find out someone added one.
    adds = "".join(
        f"<li>{_html.escape(_FEATURE_COPY.get(a, a))}</li>" for a in row["adds"]
    )

    return f"""
<div class="card plan">
  <div><h3>{_html.escape(name)}</h3></div>
  {price_html}
  <ul>
    {''.join(f'<li>{_html.escape(l)}</li>' for l in limits)}
    {adds}
  </ul>
  {action}
</div>
"""


# `pricing.table()` computes each card's bullets as `features - FREE.features`,
# so with CONFORMITY the only paid feature this dict is down to one line that
# does the entire selling. It is written as what you get rather than as a
# feature name for that reason. The others are kept: they cost nothing, and
# they are what the cards would say again if the line ever moved.
_FEATURE_COPY = {
    entitlements.EVIDENCE: "Record evidence against every requirement",
    entitlements.CONFORMITY: (
        "Place it on the market: freeze the Annex VII file, draw up the "
        "Declaration of Conformity, sign off, and record releases"
    ),
    entitlements.REASSESSMENT: "Re-assess when the product changes",
    entitlements.REPORTING: "Article 14 reporting clocks and ENISA drafts",
    entitlements.ADVISORIES: "Daily SBOM scanning against OSV and CISA KEV",
}


def _faq(question_answers) -> str:
    return "<div class='faq'>" + "".join(
        f"<div><div class='qa'><h3>{q}</h3><p class='muted'>{a}</p></div></div>"
        for q, a in question_answers
    ) + "</div>"


async def pricing_page(request: Request) -> Response:
    rows = pricing.table() if billing.is_billing_configured() else []

    # Validated against what is actually for sale rather than accepted as
    # given: `?cadence=` reaches the Stripe lookup through the plan card's
    # hidden field, and an unrecognised value would 400 the visitor at the code
    # step — after their one-time code had been spent.
    offered = [c for row in rows for c in row.get("prices", {})]
    cadence = request.query_params.get("cadence", "monthly")
    if cadence not in offered:
        cadence = "monthly" if "monthly" in offered else (offered[0] if offered else "monthly")

    if not rows:
        paid = (
            "<p class='lede'>Paid plans are not on sale here yet. "
            "<a href='mailto:cra@skarp.app'>Email us</a> and we will sort it "
            "out directly.</p>"
        )
        tail = ""
    else:
        paid = (
            "<p class='eyebrow rule-label'>Paid plans — for placing a product "
            "on the market</p>"
            + _cadence_toggle(rows, cadence)
            + f"<div class='grid cols-3'>{''.join(_plan_card(r, cadence) for r in rows)}</div>"
        )
        tail = (
            "<div class='section-head'><h2>Questions</h2></div>"
            + _faq(
                [
                    (
                        "What happens to my data if I stop paying?",
                        "Nothing is deleted, and you drop to the free plan "
                        "rather than losing access — you keep working the "
                        "checklist, the scanning and the clocks. What stops is "
                        "freezing and signing. Anything already frozen stays "
                        "readable: technical documentation has to be kept for "
                        "ten years under Article 13(13), and a plan lapsing is "
                        "not a reason to take it from you.",
                    ),
                    (
                        "Can I cancel?",
                        "Any time, from the billing page. The plan runs until the "
                        "end of the period you have already paid for — reporting "
                        "deadlines do not stop mid-obligation.",
                    ),
                    (
                        "Do you take card details?",
                        "Never. Payment happens on Stripe's own pages; this "
                        "service never sees a card number.",
                    ),
                    (
                        "Is VAT included?",
                        "Shown at checkout, calculated by Stripe from your "
                        "billing country.",
                    ),
                    (
                        "Do you charge per person?",
                        "No. Every plan has unlimited members, including free. "
                        "An Article 14 clock runs for 24 hours, and a plan that "
                        "permits one login makes that person a single point of "
                        "failure on a legal deadline.",
                    ),
                ]
            )
        )

    return _page(
        "Pricing",
        webui.section(
            "<div class='stack'>"
            "<h1>Free until you place it on the market.</h1>"
            "<p class='lede'>Doing the work costs nothing: the risk assessment, "
            "the Annex I and Annex II checklists with your evidence against "
            "them, daily scanning of what you ship, and the Article 14 clocks. "
            "You pay when you sign — to freeze the technical file, draw up the "
            "Declaration of Conformity and record a release.</p></div>"
        )
        + webui.section(_FREE_ONRAMP)
        + webui.section(paid)
        + (webui.section(tail) if tail else "")
        + webui.section(
            "<p class='small muted'>Prices are read from our payment provider "
            "when this page renders, so what you see is what you are charged. "
            "VAT is added where applicable. Already subscribed? "
            "<a href='/billing'>Manage your subscription</a> — change your "
            "card, read invoices, or cancel.</p>"
        ),
        wrap=False,
        description=(
            "Skarp CRA pricing. The risk assessment, the Annex I and Annex II "
            "checklists with evidence, daily SBOM scanning and the Article 14 "
            "reporting clocks are free for one product, with unlimited members. "
            "Paid plans freeze the technical file, the Declaration of "
            "Conformity and releases."
        ),
        indexable=True,
    )


# ---- /billing ----------------------------------------------------------------


def _hidden(fields: dict) -> str:
    return "".join(
        f'<input type="hidden" name="{k}" value="{_html.escape(str(v))}">'
        for k, v in fields.items()
        if v
    )


def _email_step(fields: dict, error: str = "") -> str:
    doing = (
        f"subscribe to the <strong>{_html.escape(fields.get('plan', ''))}</strong> plan"
        if fields.get("action") == "subscribe"
        else "manage your subscription"
    )
    return (
        "<div class='stack'>"
        "<h1>Confirm it's you</h1>"
        f"<p class='lede'>You are about to {doing}. Enter the email address on "
        "your Skarp CRA account and we will send a six-digit code.</p>"
        + (f"<p class='error'>{_html.escape(error)}</p>" if error else "")
        + '<form class="stack" method="post" action="/billing" autocomplete="off">'
        + _hidden({**fields, "step": "email"})
        + "<div>"
        '<label for="email">Email</label>'
        '<input type="email" id="email" name="email" required autofocus '
        'autocomplete="email" spellcheck="false">'
        "</div>"
        "<p class='small muted'>By continuing you agree to the "
        "<a href='/terms.html'>Terms of Service</a> and "
        "<a href='/privacy.html'>Privacy</a>.</p>"
        '<p><button class="btn cta" type="submit">Send my code</button></p>'
        "</form>"
        "</div>"
    )


def _code_step(fields: dict, error: str = "") -> str:
    return (
        "<div class='stack'>"
        "<h1>Enter your code</h1>"
        f"<p class='lede'>We sent a six-digit code to "
        f"<strong>{_html.escape(fields.get('email', ''))}</strong>. It expires "
        "in a few minutes.</p>"
        + (f"<p class='error'>{_html.escape(error)}</p>" if error else "")
        + '<form class="stack" method="post" action="/billing" autocomplete="off">'
        + _hidden({**fields, "step": "code"})
        + "<div>"
        '<label for="code">Code</label>'
        '<input type="text" id="code" name="code" inputmode="numeric" '
        'pattern="[0-9 ]*" autocomplete="one-time-code" maxlength="7" required '
        'autofocus>'
        "</div>"
        '<p><button class="btn cta" type="submit">Continue to Stripe</button></p>'
        "</form>"
        "<p class='small muted'><a href='/billing'>Start again</a> with a "
        "different address.</p>"
        "</div>"
    )


async def billing_page(request: Request) -> Response:
    """The form, or where Stripe sent the browser back to."""
    outcome = request.query_params.get("checkout", "")

    if outcome == "cancel":
        return _page(
            "Checkout cancelled",
            "<div class='stack'>"
            "<h1>Nothing was charged</h1>"
            "<p class='lede'>You closed the checkout before paying, so your "
            "plan is unchanged.</p>"
            "<p><a class='btn cta' href='/pricing'>Back to pricing</a></p>"
            "</div>",
            narrow=True,
        )
    if outcome == "success":
        return _page(
            "Payment received",
            "<div class='stack'>"
            "<h1>Thank you — that's gone through</h1>"
            "<p class='lede'>Stripe has your payment. Your plan updates as soon "
            "as Stripe confirms it to us, usually within a few seconds.</p>"
            "<p>Ask your agent to run <code>cra_overview()</code> — it reports "
            "the plan it can actually see, which is the only version worth "
            "trusting. If it still shows the old one after a minute, email "
            "<a href='mailto:cra@skarp.app'>cra@skarp.app</a>; nothing is lost, "
            "because the payment is recorded either way.</p>"
            "<h2>Managing it later</h2>"
            "<p>Card, invoices and cancellation all live at "
            "<a href='/billing'><strong>cra.skarp.app/billing</strong></a> — "
            "bookmark it. You will be asked for your email and a code each "
            "time; there is no password to lose. We have also emailed you this "
            "link.</p>"
            "</div>",
            narrow=True,
        )

    if not billing.is_billing_configured():
        return _page(
            "Billing",
            "<div class='stack'>"
            "<h1>Billing is not set up here</h1>"
            "<p class='lede'>This deployment cannot take payments. Email "
            "<a href='mailto:cra@skarp.app'>cra@skarp.app</a>.</p>"
            "</div>",
            status=503,
            narrow=True,
        )

    plan = request.query_params.get("plan", "")
    action = "subscribe" if plan else "manage"
    return _page(
        "Billing", _email_step({"action": action, "plan": plan}), narrow=True
    )


async def billing_submit(request: Request) -> Response:
    """email → code → straight to Stripe. No session in between."""
    if not billing.is_billing_configured():
        return _page(
            "Billing",
            "<div class='stack'>"
            "<h1>Billing is not set up here</h1>"
            "<p class='lede'>Email <a href='mailto:cra@skarp.app'>"
            "cra@skarp.app</a>.</p>"
            "</div>",
            status=503,
            narrow=True,
        )

    form = await request.form()
    step = str(form.get("step") or "")
    action = str(form.get("action") or "manage")
    plan = str(form.get("plan") or "")
    # Carried like `action` and `plan`. It was not, so it defaulted to monthly
    # at the point of checkout no matter what the pricing page had shown —
    # every annual figure on that page was unbuyable.
    cadence = str(form.get("cadence") or "monthly")
    fields = {"action": action, "plan": plan, "cadence": cadence}

    # A plan button carries the intent but no address, so it lands here to have
    # the email form rendered clean. Posting `step=email` made the handler
    # validate an empty string and answer "That does not look like an email
    # address" before the visitor had typed anything.
    if step == "start":
        return _page("Billing", _email_step(fields), narrow=True)

    if step == "email":
        email = str(form.get("email") or "")
        what = (
            f"Someone asked to subscribe to the {plan} plan on Skarp CRA "
            "using this address."
            if action == "subscribe"
            else "Someone asked to open the Skarp CRA billing portal for "
            "this address."
        )
        try:
            challenge = signup.start_code_challenge(
                email, purpose=signup.PURPOSE_BILLING, what=what
            )
        except signup.SignupError as e:
            return _page(
                "Billing", _email_step(fields, str(e)), status=400, narrow=True
            )
        return _page(
            "Billing",
            _code_step(
                {
                    **fields,
                    "email": signup.normalise_email(email),
                    "challenge_id": challenge,
                }
            ),
            narrow=True,
        )

    if step != "code":
        return _page("Billing", _email_step(fields), narrow=True)

    carried = {
        **fields,
        "email": str(form.get("email") or ""),
        "challenge_id": str(form.get("challenge_id") or ""),
    }
    try:
        proven = signup.verify_code(
            carried["challenge_id"],
            str(form.get("code") or ""),
            purpose=signup.PURPOSE_BILLING,
        )
    except signup.SignupError as e:
        return _page(
            "Billing", _code_step(carried, str(e)), status=401, narrow=True
        )

    with session_scope() as db:
        user = db.get(User, proven["user_id"])
        db.expunge(user)

    try:
        if action == "subscribe":
            url = billing.create_checkout_session(
                user, plan=plan, cadence=cadence
            ).url
        else:
            if not user.stripe_customer_id:
                return _page(
                    "Billing",
                    "<div class='stack'>"
                    "<h1>Nothing to manage yet</h1>"
                    f"<p class='lede'>Your address is confirmed. This account "
                    f"is on the "
                    f"<strong>{_html.escape(entitlements.plan_for(user.id).name)}</strong> "
                    "plan and has never been billed, so there is no Stripe "
                    "subscription to open.</p>"
                    # Said plainly, because the button promised Stripe and this
                    # is not Stripe — and because the next thing anyone does is
                    # press it again and meet "that code has been used".
                    "<p class='small muted'>Your code has been used. Choosing a "
                    "plan below will ask for a fresh one.</p>"
                    "<p><a class='btn cta' href='/pricing'>See the plans</a></p>"
                    "</div>",
                    narrow=True,
                )
            url = billing.create_portal_session(user)
    except ValueError as e:
        # The code step, not the email step. Bouncing to the start after the
        # one-time code had been spent looked to the visitor like the form
        # resetting itself, and left them unable to retry.
        return _page(
            "Billing", _code_step(carried, str(e)), status=400, narrow=True
        )
    except Exception:  # noqa: BLE001 — Stripe detail is not the visitor's problem
        log.exception("could not send %s to Stripe for %s", action, proven["email"])
        return _page(
            "Billing",
            "<div class='stack'>"
            "<h1>Stripe could not be reached</h1>"
            "<p class='lede'>Nothing was charged and nothing changed. Try "
            "again shortly, or email "
            "<a href='mailto:cra@skarp.app'>cra@skarp.app</a>.</p>"
            "</div>",
            status=502,
            narrow=True,
        )

    log.info("billing: sending %s to Stripe for %s", action, proven["email"])
    return RedirectResponse(url, status_code=303)
