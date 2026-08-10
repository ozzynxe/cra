"""The read-only console: log in, see your products, print a report.

    GET  /app                        your products
    GET  /app/login    POST          email → six digits → session
    POST /app/logout
    GET  /app/p/{id}                 one product's state
    GET  /app/p/{id}/requirements    all 22, with evidence counts
    GET  /app/p/{id}/report          the Annex VII gap report, printable

## Every read goes through `dispatch`

Not one query in this module touches `products` or the state blob. Each page
resolves a session to a user, puts that user into `request_context`, and calls
the same tools an agent calls.

That is a rule, not a preference. Membership checks live inside the handlers
(`scoping._member`); entitlement gates live in `dispatch` and in four handlers.
Both were built against exactly one path to the data. A console reading the
database directly would be a second path with its own bugs, and the first one
to drift would be the membership check on a page showing unreported
exploited-vulnerability records.

Two things fall out of it. The console needs no entitlement logic — a free
account hits `upgrade_required` and the page renders that as a plan limit
rather than an error. And no page can display anything its viewer could not
already have fetched through MCP, which makes "can this person see this?" a
question with one answer instead of two.

## What it deliberately cannot do

Nothing here writes. Work happens in the agent, next to the code the answers
come from; a browser cannot see the repository. Adding a write path would mean
re-deriving the membership check, the entitlement gate and the audit row that
`dispatch` already gets right.

## Rendering rules these pages are built to

From the design brief, and they are the reason the markup looks the way it
does rather than being a table of everything at one weight:

* **Weight follows consequence.** An overdue statutory obligation gets a 2px
  `--alert` frame at the top of the page; `lifecycle: in_development` gets a
  quiet table row near the bottom. Both used to be rows in the same definition
  list.
* **Applicability and progress stay two figures.** Merging them into one
  percentage would hide the risk assessment's entire output behind a number
  that looks like a score.
* **An absence of knowledge never renders as knowledge of absence.** Deadlines
  that could not be read, a product with no checklist seeded, a plan that does
  not retain evidence — each gets a `.note` that says so in words, never a zero
  or a blank cell. `_counts` and `_figures` both refuse to return an empty
  string for this reason.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from cra.agents import dispatch as _dispatch
from cra.db import User, session_scope
from cra.server import entitlements, request_context, sessions, signup, webui
from cra.server.webui import esc

log = logging.getLogger(__name__)

_MCP_URL = "https://cra.skarp.app/mcp"


# ---- identity ----------------------------------------------------------------


class _Viewer:
    __slots__ = ("id", "email")

    def __init__(self, uid: str, email: str):
        self.id = uid
        self.email = email


def _retention_line(retention: Optional[dict]) -> str:
    """One line: what Article 13(13) keeps, and until when.

    Said "10 years — Annex VII requires technical documentation to be retained
    that long" until 2026-08-09. Annex VII lists what the file contains; the
    duty is Article 13(13), and it is ten years *or the support period,
    whichever is longer*, so the flat number was short for any product
    supported beyond a decade.
    """
    if not retention:
        return "—"
    covers = "the technical documentation and the EU declaration of conformity"
    if not retention.get("until"):
        return (
            f"Not started. Article 13(13) keeps {covers} for 10 years from "
            "placing on the market; that has not been recorded yet."
        )
    until = str(retention["until"])[:10]
    basis = (
        "the support period, which runs longer"
        if retention.get("basis") == "support_period"
        else "10 years from placing on the market"
    )
    return f"Until {until} — Article 13(13) keeps {covers} for {basis}."


def _viewer(request: Request) -> Optional[_Viewer]:
    user_id = sessions.resolve(request.cookies.get(sessions.COOKIE))
    if not user_id:
        return None
    with session_scope() as db:
        user = db.get(User, user_id)
        if user is None:
            return None
        return _Viewer(user.id, user.email)


def _call(viewer: _Viewer, tool: str, product_id: str = "", **args) -> dict:
    """Dispatch as this viewer.

    The contextvars are the same seam `auth.PartyAuthMiddleware` uses for
    connector tokens (`auth.py:214`) — `dispatch._resolve_identity` prefers
    them over its arguments, so a page cannot accidentally act as anyone else.
    """
    token = request_context.current_user_id.set(viewer.id)
    product_token = request_context.current_product_id.set(product_id or None)
    try:
        return _dispatch.dispatch(tool, product_id, viewer.id, args)
    finally:
        request_context.current_user_id.reset(token)
        request_context.current_product_id.reset(product_token)


def _login_redirect(request: Request) -> Response:
    return RedirectResponse(f"/app/login?next={request.url.path}", status_code=303)


# ---- login -------------------------------------------------------------------


def _safe_next(raw: str) -> str:
    """Only same-site console paths. An open redirect on a login page is how a
    credential ends up somewhere else."""
    if raw.startswith("/app") and not raw.startswith("//"):
        return raw
    return "/app"


async def login_form(request: Request) -> Response:
    if _viewer(request):
        return RedirectResponse(_safe_next(request.query_params.get("next", "/app")), 303)
    return _render_login(_safe_next(request.query_params.get("next", "/app")))


def _error(message: str) -> str:
    """Server-rendered, above the field it belongs to. There is no JavaScript
    to validate anything, which is the point."""
    return f"<p class='error'>{esc(message)}</p>" if message else ""


def _render_login(next_path: str, *, error: str = "", status: int = 200) -> Response:
    return webui.page(
        "Sign in",
        "<div class='stack'>"
        "<h1>Sign in</h1>"
        "<p class='lede'>Enter your email and we will send a six-digit code. "
        "There is no password.</p>"
        + _error(error)
        + '<form class="stack" method="post" action="/app/login" autocomplete="off">'
        f'<input type="hidden" name="next" value="{esc(next_path)}">'
        '<input type="hidden" name="step" value="email">'
        "<div>"
        '<label for="email">Email</label>'
        '<input type="email" id="email" name="email" required autofocus '
        'autocomplete="email" spellcheck="false">'
        "</div>"
        '<p><button class="btn cta" type="submit">Send my code</button></p>'
        "</form>"
        "<p class='small muted'>No account yet? "
        "<a href='/access'>Get access</a>. It takes a minute, and the free plan "
        "covers the work — you pay when you place a product on the market.</p>"
        "</div>",
        status=status,
        narrow=True,
    )


def _render_code(next_path: str, email: str, challenge: str, *, error: str = "", status: int = 200) -> Response:
    return webui.page(
        "Enter your code",
        "<div class='stack'>"
        "<h1>Enter your code</h1>"
        f"<p class='lede'>We sent a six-digit code to <strong>{esc(email)}</strong>."
        " It expires in a few minutes.</p>"
        + _error(error)
        + '<form class="stack" method="post" action="/app/login" autocomplete="off">'
        f'<input type="hidden" name="next" value="{esc(next_path)}">'
        f'<input type="hidden" name="email" value="{esc(email)}">'
        f'<input type="hidden" name="challenge_id" value="{esc(challenge)}">'
        '<input type="hidden" name="step" value="code">'
        "<div>"
        '<label for="code">Code</label>'
        '<input type="text" id="code" name="code" inputmode="numeric" '
        'pattern="[0-9 ]*" autocomplete="one-time-code" maxlength="7" required autofocus>'
        "</div>"
        '<p><button class="btn cta" type="submit">Sign in</button></p>'
        "</form>"
        "<p class='small muted'><a href='/app/login'>Start again</a> with a "
        "different address.</p>"
        "</div>",
        status=status,
        narrow=True,
    )


async def login_submit(request: Request) -> Response:
    form = await request.form()
    next_path = _safe_next(str(form.get("next") or "/app"))
    step = str(form.get("step") or "email")

    if step == "email":
        email = str(form.get("email") or "")
        try:
            challenge = signup.start_code_challenge(
                email,
                purpose=signup.PURPOSE_LOGIN,
                what="Someone asked to sign in to the Skarp CRA console with this address.",
            )
        except signup.SignupError as e:
            return _render_login(next_path, error=str(e), status=400)
        return _render_code(next_path, signup.normalise_email(email), challenge)

    email = str(form.get("email") or "")
    challenge = str(form.get("challenge_id") or "")
    try:
        proven = signup.verify_code(
            challenge, str(form.get("code") or ""), purpose=signup.PURPOSE_LOGIN
        )
    except signup.SignupError as e:
        return _render_code(next_path, email, challenge, error=str(e), status=401)

    cookie = sessions.issue(proven["user_id"])
    response = RedirectResponse(next_path, status_code=303)
    response.set_cookie(
        sessions.COOKIE,
        cookie,
        **sessions.cookie_kwargs(secure=request.url.scheme == "https"),
    )
    return response


async def logout(request: Request) -> Response:
    sessions.revoke(request.cookies.get(sessions.COOKIE))
    response = RedirectResponse("/app/login", status_code=303)
    response.delete_cookie(sessions.COOKIE, path="/")
    return response


# ---- shared rendering --------------------------------------------------------


# Roman numerals in the enum values. `important_class_i` sentence-cased naively
# reads "Important class i", which looks like a typo on the one line of the
# page that decides whether a notified body is involved.
_NUMERALS = {"i", "ii", "iii", "iv", "v"}


def _words(value) -> str:
    """`support_period_active` → `Support period active`.

    Enum values are the wire format; a page is read by someone who did not
    choose them."""
    if not value:
        return ""
    parts = str(value).replace("_", " ").split(" ")
    words = [p.upper() if p in _NUMERALS else p for p in parts]
    if words:
        words[0] = words[0] if words[0] in _NUMERALS else words[0].capitalize()
    return esc(" ".join(words))


def _stamp(iso: Optional[str]) -> str:
    """`2026-08-07T09:14:22+00:00` → `07 Aug 2026, 09:14 UTC`.

    On a document that gets printed and forwarded, the generation time is read
    by someone who will never see the ISO string it came from. If it cannot be
    parsed it is passed through rather than dropped — a timestamp that looks
    wrong is recoverable; one that is missing is not.
    """
    if not iso:
        return "unknown"
    try:
        when = datetime.fromisoformat(iso)
    except ValueError:
        return esc(iso)
    if when.tzinfo is not None:
        when = when.astimezone(timezone.utc)
    return esc(when.strftime("%d %b %Y, %H:%M UTC"))


def _refusal(out: dict) -> Optional[str]:
    """Render a tool refusal as an explanation, not an error page.

    `upgrade_required` in particular is a plan limit, and the wording carries
    the same rule the rest of the product runs on: not covered here says
    nothing about whether the product meets the requirement.
    """
    if out.get("ok"):
        return None
    if out.get("code") == "upgrade_required":
        return (
            "<div class='note'><p><strong>Not included in your plan.</strong> "
            f"{esc(out.get('error'))} This says nothing about whether your "
            "product meets the requirement — only that this service is not "
            "tracking it for you.</p></div>"
            "<p><a class='btn' href='/pricing'>See plans</a></p>"
        )
    return f"<div class='note'><p>{esc(out.get('error') or 'Not available.')}</p></div>"


def _not_found(viewer: _Viewer) -> Response:
    """Deliberately the same answer for 'no such product' and 'not yours'.

    Distinguishing them would confirm a product id exists to somebody who is
    not on it, which is the one thing a product id must never do.
    """
    return webui.page(
        "Not found",
        "<div class='stack'>"
        "<h1>Not found</h1>"
        "<p class='lede'>No product here, or it is not one of yours.</p>"
        "<p><a class='btn' href='/app'>Back to your products</a></p>"
        "</div>",
        status=404,
        narrow=True,
        signed_in_as=viewer.email,
    )


def _counts(mapping: Optional[dict]) -> str:
    """"undetermined: 20, applicable: 2" — and never an empty string.

    A blank cell reads as zero. If there is nothing to count, say so."""
    if not mapping:
        return "nothing recorded"
    return ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in mapping.items())


_TABS = [("", "Overview"), ("/requirements", "Requirements"), ("/report", "Report")]


def _header(pid: str, name: str, here: str, *, title: str = "", extra: str = "") -> str:
    """Breadcrumb, page title and the three tabs, as one `.section-head`.

    One per page, and only one: `.section-head` carries a bottom margin and no
    top margin, on the assumption that it opens its section. Two of them in a
    row — which is what a separate title block and a separate table heading
    gave — collide.

    Tabs are links with `aria-current` on the active one. There is no
    JavaScript, and a tab that is a link is also one that can be bookmarked,
    opened in a new window, and announced for what it is.
    """
    links = " ".join(
        f"<a class='btn small' href='/app/p/{esc(pid)}{suffix}'"
        + (" aria-current='page'" if suffix == here else "")
        + f">{esc(label)}</a>"
        for suffix, label in _TABS
    )
    trail = f"<a href='/app'>Products</a> &rsaquo;"
    if here:
        # On a sub-page the product name is the crumb, and the heading names
        # the page — otherwise every page under a product has the same title.
        trail += f" <a href='/app/p/{esc(pid)}'>{esc(name)}</a> &rsaquo;"
    groups = (f"<span class='tabset'>{extra}</span>" if extra else "") + (
        f"<span class='tabset'>{links}</span>"
    )
    return (
        f"<p class='small muted'>{trail}</p>"
        f"<div class='section-head'><h1>{esc(title) if title else esc(name)}</h1>"
        f"<div class='tabsets'>{groups}</div></div>"
    )


def _footnote() -> str:
    return (
        "<p class='small muted'>This is a view of what has been recorded. "
        "Changes are made through your agent. Skarp CRA cannot certify "
        "conformity or replace a notified body.</p>"
    )


# ---- /app --------------------------------------------------------------------


async def products(request: Request) -> Response:
    viewer = _viewer(request)
    if viewer is None:
        return _login_redirect(request)

    listed = _call(viewer, "list_products")
    rows = listed.get("products", []) if listed.get("ok") else []
    plan = entitlements.describe(viewer.id)

    if not rows:
        # A genuine empty state, not an error. A new account is legitimately
        # empty because the work happens in the agent, so this gets no warning
        # colour and no empty-state illustration — a heading, the reason, and
        # the command that fixes it.
        body = (
            "<div class='stack'>"
            "<h1>No products yet</h1>"
            "<p class='lede'>This console shows what your agent has recorded. "
            "Nothing has been recorded yet.</p>"
            "<p>Connect your agent, then ask it about the product you ship:</p>"
            f"<pre class='term'>claude mcp add --transport http skarp-cra {esc(_MCP_URL)}</pre>"
            "<p>It will ask for your email and a code — the same sign-in you "
            "just used. Then say <em>&ldquo;what does the Cyber Resilience Act "
            "require of this product?&rdquo;</em> and it will work through "
            "classification and the Article 13(2) risk assessment with you.</p>"
            "</div>"
        )
    else:
        cards = "".join(
            "<div class='card'>"
            f"<h3><a href='/app/p/{esc(p['product_id'])}'>{esc(p['name'])}</a></h3>"
            f"<p class='small muted'>{_words(p.get('product_class')) or 'Unclassified'}"
            f" &middot; {_words(p.get('lifecycle')) or 'Lifecycle unknown'}</p>"
            "</div>"
            for p in rows
        )
        body = (
            "<div class='section-head'><h1>Your products</h1>"
            f"<p class='small muted'>{len(rows)} recorded</p></div>"
            f"<div class='grid cols-3'>{cards}</div>"
        )

    limits = []
    if plan.get("max_products"):
        limits.append(f"{len(rows)} of {plan['max_products']} products")
    if plan.get("not_included"):
        # Named rather than counted. With CONFORMITY the only paid feature,
        # "1 feature group(s) not included" is both ugly and less informative
        # than saying which one.
        missing = ", ".join(sorted(plan["not_included"]))
        limits.append(f"{missing} not included")
    body += (
        f"<p class='small muted'>Plan: <strong>{esc(plan['name'])}</strong>"
        + (f" — {esc(', '.join(limits))}" if limits else "")
        + " &middot; <a href='/pricing'>plans</a> &middot; <a href='/billing'>billing</a></p>"
    )
    return webui.page("Your products", body, signed_in_as=viewer.email)


# ---- /app/p/{id} -------------------------------------------------------------


def _clock(o: dict) -> str:
    """How late, or how long left, in words.

    Late is the reading that matters, so it comes first and in `--alert`. An
    obligation whose remaining hours cannot be read renders as "unknown" — not
    as a comfortable number."""
    hours = o.get("hours_remaining")
    if hours is None:
        return "<span class='status late'>timing unknown</span>"
    if hours < 0:
        late = abs(hours)
        span = f"{late:.0f} h late" if late < 48 else f"{late / 24:.0f} d late"
        return f"<span class='status late'>{span}</span>"
    span = f"{hours:.0f} h left" if hours < 48 else f"{hours / 24:.0f} d left"
    return f"<span class='status progress'>{span}</span>"


def _obligations_card(dl: dict) -> str:
    """The top-left card. Overdue work gets a 2px alert frame; open-but-not-yet
    due gets an ordinary card. Nothing due gets a sentence, because an empty
    card would read as a clean bill."""
    open_obligations = dl.get("open_obligations")
    if open_obligations is None:
        # The one case that must never render as "nothing due".
        return (
            "<div class='note'><p><strong>Reporting deadlines could not be "
            f"read.</strong> {esc(dl.get('unavailable') or '')}</p></div>"
        )
    if not open_obligations:
        return (
            "<div class='card stack'>"
            "<p class='eyebrow'>Reporting</p>"
            "<p>No open obligations recorded for this product.</p>"
            "<p class='small muted'>Obligations appear here when a "
            "vulnerability is recorded as actively exploited, or an incident "
            "is reported.</p>"
            "</div>"
        )

    overdue = [o for o in open_obligations if o.get("state") == "overdue"]
    rows = "".join(
        "<tr>"
        f"<td>{_words(o.get('stage'))}"
        # The incident id in full, not truncated: it is what you quote when
        # filing, and half of one is no use for that.
        + (f"<br><span class='mono muted'>incident {esc(o.get('incident_id'))}</span>" if o.get("incident_id") else "")
        + "</td>"
        f"<td class='num'>{_clock(o)}</td>"
        "</tr>"
        for o in open_obligations
    )
    heading = (
        f"Reporting — {len(overdue)} obligation{'' if len(overdue) == 1 else 's'} overdue"
        if overdue
        else f"Reporting — {len(open_obligations)} open"
    )
    return (
        f"<div class='card {'alert ' if overdue else ''}stack'>"
        f"<p class='eyebrow'>{esc(heading)}</p>"
        f"<table><tbody>{rows}</tbody></table>"
        "<p class='small muted'>Filed by you on ENISA's Single Reporting "
        "Platform. This service drafts and records; it never submits.</p>"
        "</div>"
    )


def _figures(reqs: dict) -> str:
    """The two figures the brief insists stay separate.

    Applicability is what the risk assessment decided. Progress is how far the
    work has got. One number covering both would be a compliance score, which
    is the thing this product does not produce.
    """
    total = reqs.get("total") or 0
    if not total:
        return (
            "<div class='note'><p><strong>No Annex I checklist yet.</strong> "
            "It is seeded when the product is classified in scope. Until then "
            "there is nothing to count here — which is not the same as nothing "
            "to do.</p></div>"
        )

    by_app = reqs.get("by_applicability") or {}
    by_status = reqs.get("by_status") or {}
    applicable = by_app.get("applicable", 0)
    not_applicable = by_app.get("not_applicable", 0)
    undetermined = by_app.get("undetermined", 0)
    progressed = by_status.get("implemented", 0) + by_status.get("verified", 0)

    settled = (
        f"{not_applicable} found not applicable"
        + (f", {undetermined} still undetermined" if undetermined else "")
        + "."
    )
    return (
        "<div class='grid cols-2'>"
        "<div class='card figure'>"
        "<p class='eyebrow'>Annex I applicable</p>"
        f"<p class='n'>{applicable} <small>of {total}</small></p>"
        f"<p class='small muted'>{esc(settled)}</p>"
        "</div>"
        "<div class='card figure'>"
        "<p class='eyebrow'>Recorded as implemented</p>"
        f"<p class='n'>{progressed} <small>of {applicable}</small></p>"
        "<p class='small muted'>Progress against what applies, not a "
        "compliance score.</p>"
        "</div>"
        "</div>"
    )


def risk_assessment_note(ra: dict) -> str:
    """The Article 13(2) caveat, or nothing.

    Annex I Part I applies *on the basis of* this assessment, so a stale or
    absent one does not merely age a field — it undermines every applicability
    decision shown above it. Both branches end on the same sentence, which is
    the rule the whole product runs on: an absence of information is not an
    absence of obligations.
    """
    if ra.get("present") and ra.get("stale"):
        return (
            "<p class='note'><strong>The risk assessment is marked stale.</strong> "
            "Annex I Part I applies on the basis of it, and the regulation "
            "expects it to be kept current for the support period. This does "
            "not mean nothing is due.</p>"
        )
    if not ra.get("present"):
        return (
            "<p class='note'><strong>No risk assessment recorded.</strong> "
            "Article 13(2) requires one, and it is what decides which Annex I "
            "requirements apply. Until it exists the applicability figures "
            "above are undetermined rather than settled. This does not mean "
            "nothing is due.</p>"
        )
    return ""


def _determination(status: dict, cls: dict, ra: dict) -> str:
    """The old definition table, demoted to two columns of quiet rows.

    Everything here is true and none of it is urgent — which is exactly why it
    sits below the alert card rather than beside it."""

    def rows(pairs) -> str:
        return "".join(
            f"<tr><th scope='row' class='muted'>{esc(label)}</th><td>{value}</td></tr>"
            for label, value in pairs
        )

    scope = cls.get("in_scope")
    scope_text = (
        "In scope" if scope is True
        else "Out of scope" if scope is False
        else "<em>Not determined</em>"
    )
    assessment = (
        f"Version {esc(ra.get('version'))}, {_words(ra.get('status'))}"
        + (" &middot; <strong>stale</strong>" if ra.get("stale") else "")
        if ra.get("present")
        else "<em>Not started</em> — this is what Annex I applicability rests on"
    )
    left = rows(
        [
            ("Scope", scope_text),
            ("Class", _words(cls.get("product_class")) or "<em>Not determined</em>"),
            ("Conformity route", _words(cls.get("conformity_route")) or "<em>Not determined</em>"),
            ("Economic operator", _words(status.get("economic_operator_role")) or "<em>Not recorded</em>"),
        ]
    )
    right = rows(
        [
            ("Lifecycle", _words(status.get("lifecycle")) or "<em>Not recorded</em>"),
            ("Risk assessment", assessment),
            ("Annex I — applies?", esc(_counts((status.get("requirements") or {}).get("by_applicability")))),
            ("Annex I — progress", esc(_counts((status.get("requirements") or {}).get("by_status")))),
        ]
    )
    return (
        "<div class='section-head'><h2>Determination</h2>"
        "<p class='small muted'>Recorded through your agent</p></div>"
        "<div class='grid cols-2'>"
        f"<div class='table-wrap'><table><tbody>{left}</tbody></table></div>"
        f"<div class='table-wrap'><table><tbody>{right}</tbody></table></div>"
        "</div>"
    )


async def product(request: Request) -> Response:
    viewer = _viewer(request)
    if viewer is None:
        return _login_redirect(request)
    pid = request.path_params["product_id"]

    status = _call(viewer, "get_compliance_status", pid)
    if not status.get("ok"):
        return _not_found(viewer)

    cls = status.get("classification", {})
    reqs = status.get("requirements", {})
    dl = status.get("deadlines", {})
    ra = _call(viewer, "get_risk_assessment", pid).get("assessment", {})

    top = (
        _header(pid, status.get("name", "Product"), "")
        + "<div class='grid cols-2'>"
        + _obligations_card(dl)
        + _figures(reqs)
        + "</div>"
    )

    top += risk_assessment_note(ra)

    body = webui.section(top) + webui.section(_determination(status, cls, ra))
    if cls.get("rationale"):
        body += webui.section(
            "<div class='section-head'><h2>Why this classification</h2></div>"
            f"<div class='card'><p>{esc(cls['rationale'])}</p></div>"
        )
    body += webui.section(_footnote())
    return webui.page(
        status.get("name", "Product"),
        body,
        wrap=False,
        signed_in_as=viewer.email,
    )


# ---- /app/p/{id}/requirements ------------------------------------------------

# Filters are links, not controls: server-rendered, bookmarkable, and working
# with no JavaScript. The vocabulary is `list_requirements`' own — inventing a
# second set for the browser would be two things to keep in step.
_FILTERS = [
    ("all", "All"),
    ("gaps", "Gaps"),
    ("part_i", "Part I"),
    ("part_ii", "Part II"),
]

_APPLICABILITY = {
    "applicable": ("Applicable", ""),
    "not_applicable": ("Not applicable", "muted"),
    "undetermined": ("Undetermined", "status gap"),
}

_STATUS = {
    "verified": ("Verified", "status ok"),
    "implemented": ("Implemented", "status ok"),
    "in_progress": ("In progress", "status progress"),
    "not_started": ("Not started", "status gap"),
}


def _requirement_row(r: dict) -> str:
    applicability = r.get("applicability") or "undetermined"
    label, app_class = _APPLICABILITY.get(applicability, (_words(applicability), ""))

    if applicability == "not_applicable":
        # Status is meaningless once a requirement is ruled out, and showing
        # "Not started" against one would read as an outstanding task.
        state = "<span class='status na'>&mdash;</span>"
        count = "<span class='status na'>&mdash;</span>"
    else:
        word, state_class = _STATUS.get(
            r.get("status") or "", (_words(r.get("status")), "status gap")
        )
        state = f"<span class='{state_class}'>{esc(word)}</span>"
        count = esc(r.get("evidence_count", 0))

    return (
        "<tr>"
        f"<td class='ref'>{esc(r.get('anchor'))}</td>"
        f"<td>{esc(r.get('summary') or '')}</td>"
        f"<td class='small{(' ' + app_class) if app_class else ''}'>{esc(label)}</td>"
        f"<td>{state}</td>"
        f"<td class='num'>{count}</td>"
        "</tr>"
    )


async def requirements(request: Request) -> Response:
    viewer = _viewer(request)
    if viewer is None:
        return _login_redirect(request)
    pid = request.path_params["product_id"]

    status = _call(viewer, "get_compliance_status", pid)
    if not status.get("ok"):
        return _not_found(viewer)

    chosen = request.query_params.get("filter", "all")
    if chosen not in dict(_FILTERS):
        chosen = "all"

    # `verbose` is what carries the requirement text. A table of anchors with
    # no wording is a table only somebody who already knows Annex I can read.
    out = _call(viewer, "list_requirements", pid, filter=chosen, verbose=True)
    name = status.get("name", "Product")

    refused = _refusal(out)
    if refused:
        return webui.page(
            "Requirements",
            _header(pid, name, "/requirements", title="Essential requirements")
            + refused,
            signed_in_as=viewer.email,
        )

    filters = " ".join(
        f"<a class='btn small' href='?filter={key}'"
        + (" aria-current='page'" if key == chosen else "")
        + f">{esc(label)}</a>"
        for key, label in _FILTERS
    )
    head = _header(
        pid, name, "/requirements", title="Essential requirements", extra=filters
    )
    rows = "".join(_requirement_row(r) for r in out.get("requirements", []))

    if not rows:
        return webui.page(
            f"{name} — requirements",
            head
            + "<div class='note'><p>"
            + esc(out.get("note") or "Nothing matches this filter.")
            + "</p></div>",
            signed_in_as=viewer.email,
        )

    body = head + (
        "<div class='table-wrap'><table>"
        f"<caption class='visually-hidden'>Annex I essential requirements for {esc(name)}</caption>"
        "<thead><tr><th scope='col'>Anchor</th><th scope='col'>Requirement</th>"
        "<th scope='col'>Applicability</th><th scope='col'>Status</th>"
        "<th scope='col' class='num'>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
        f"<p class='small muted'>{out.get('count', 0)} shown of "
        f"{status.get('requirements', {}).get('total', 0)}. "
        f"<strong>{out.get('gaps_total', 0)}</strong> would leave a hole in the "
        "technical file.</p>"
        # The content rule, in the design's own treatment: full body size, not
        # a grey footnote. A reader who takes "not started" for a finding
        # against the product has been misled by the page.
        "<p class='note'><strong>A requirement with nothing recorded against "
        "it is not a finding against your product.</strong> It means nothing "
        "has been recorded here. It does not mean the work has not been "
        "done.</p>"
    )
    prov = out.get("provenance") or {}
    if prov.get("caveat"):
        body += f"<p class='small muted'>{esc(prov['caveat'])}</p>"
    return webui.page(
        f"{name} — requirements",
        webui.section(body) + webui.section(_footnote()),
        wrap=False,
        signed_in_as=viewer.email,
    )


# ---- /app/p/{id}/report ------------------------------------------------------


def _slot(slot: dict, missing: set, deferred: set) -> str:
    """One Annex VII section.

    `break-inside: avoid` in the stylesheet keeps a slot off a page boundary.
    A slot split across two sheets of paper is how a "NOT RECORDED" ends up on
    a page by itself, reading as a verdict.
    """
    sid = slot.get("slot")
    if sid in missing:
        state, when = "NOT RECORDED", "Mandatory"
    elif sid in deferred:
        state, when = "FILLED LAST", "By design"
    elif slot.get("complete"):
        state, when = "RECORDED", f"{len(slot.get('evidence_ids') or [])} record(s)"
    else:
        state, when = "NOT RECORDED", "Optional"

    needs = "; ".join(slot.get("needs") or [])
    sourced = slot.get("sourced_from_requirements") or []
    trail = (
        f"<p class='hash'>from {esc(', '.join(sourced))}</p>" if sourced else ""
    )
    return (
        "<div class='slot'>"
        "<div>"
        f"<p><span class='mono'>{esc(slot.get('anchor'))}</span> "
        f"<strong>{esc(slot.get('title'))}</strong></p>"
        + (f"<p class='small muted'>{esc(needs)}</p>" if needs else "")
        + (f"<p class='small muted'>{esc(slot.get('missing'))}</p>" if slot.get("missing") else "")
        + trail
        + "</div>"
        "<div>"
        f"<p class='state'>{state}</p>"
        f"<p class='small muted'>{esc(when)}</p>"
        "</div>"
        "</div>"
    )


def report_article(
    name: str,
    status: dict,
    out: dict,
    *,
    sample: bool = False,
) -> str:
    """The `<article class="report">` itself, from the two tool payloads.

    Split out of the handler so `/sample-report` renders through exactly this
    code. A hand-written sample is a promise about the product that stops being
    true the first time this function changes, and nobody notices, because
    nothing tests a marketing page against the thing it depicts.

    `sample=True` changes three things and only these three, each chosen
    because the print rules strip the site chrome: a printed sample is
    otherwise byte-for-byte a printed real report. The heading stamp says so,
    a statement above the slot list says so, and the content-hash row says
    there is no hash rather than showing a plausible one. A hash is the thing
    that makes a printed copy checkable against real state, so inventing one
    for a fictional product would be forging exactly the wrong field.
    """
    cls = status.get("classification", {})
    missing = {s["slot"] for s in out.get("missing_slots", [])}
    deferred = {s["slot"] for s in out.get("deferred_slots", [])}
    prov = out.get("provenance") or {}

    # Above the slot list, never below it. The whole risk on this page is a
    # reader concluding the product has failed a requirement when the truth is
    # that this service is not tracking it for them.
    # `coverage_note` is the plan-specific version the tool supplies when
    # evidence is not retained. Without it the same rule still holds — a slot
    # this service does not hold says nothing about the product — so the
    # sentence is unconditional and only its second half varies.
    explanation = out.get("coverage_note") or (
        "Slots marked not recorded may well be satisfied by material held "
        "elsewhere."
    )
    statement = (
        "<div class='statement'><p>"
        "<strong>A gap here means &ldquo;not recorded in this service&rdquo;. "
        "It does not mean the requirement is unmet.</strong><br>"
        f"{esc(explanation)} Read this document as an inventory of what this "
        "service holds, not as an assessment of the product."
        "</p></div>"
    )
    if sample:
        statement = (
            "<div class='statement'><p>"
            "<strong>This is a sample document. It describes a product that "
            "does not exist.</strong><br>"
            "It is published so you can see the shape of an Annex VII gap "
            "report before signing up. Nothing in it was recorded by anyone, "
            "it is not evidence of anything, and it must not be filed or "
            "forwarded as though it were."
            "</p></div>"
        ) + statement

    slots = "".join(_slot(s, missing, deferred) for s in out.get("slots", []))
    facts = "".join(
        f"<p class='small'><span class='muted'>{label}</span><br>{value}</p>"
        for label, value in [
            ("Economic operator", _words(status.get("economic_operator_role")) or "Not recorded"),
            ("Product class", _words(cls.get("product_class")) or "Not determined"),
            ("Conformity route", _words(cls.get("conformity_route")) or "Not determined"),
        ]
    )

    summary = (
        "Every mandatory section has content."
        if out.get("complete")
        else f"{len(missing)} mandatory section(s) still open."
    )

    stamp = (
        "SAMPLE — not generated from recorded state"
        if sample
        else f"Generated {_stamp(out.get('assembled_at'))}"
    )
    if sample:
        hash_row = (
            "<div><span>Content hash</span><span>None. A hash ties a copy to "
            "the state it came from; this document came from no state, so "
            "there is nothing to tie it to.</span></div>"
        )
        generated_row = (
            "<div><span>Generated</span><span>Never. A real report carries the "
            "moment it was assembled, and regenerating it is how a reader "
            "checks a printed copy against current state.</span></div>"
        )
    else:
        hash_row = (
            f"<div><span>Content hash</span><code>{esc(out.get('content_hash'))}</code></div>"
        )
        generated_row = (
            f"<div><span>Generated</span><span>{_stamp(out.get('assembled_at'))} — regenerate to verify this copy against current state.</span></div>"
        )

    return (
        "<article class='report'>"
        "<div class='report-head'>"
        "<h2>Annex VII technical documentation — gap report</h2>"
        f"<p class='mono'>{stamp}</p>"
        "</div>"
        f"<h1>{esc(name)}</h1>"
        f"<div class='grid cols-3'>{facts}</div>"
        + statement
        + f"<p class='small muted'>{esc(summary)}</p>"
        + f"<div class='stack'>{slots}</div>"
        + "<div class='provenance'>"
        + hash_row
        + generated_row
        + f"<div><span>Retention</span><span>{esc(_retention_line(out.get('retention')))}</span></div>"
        + f"<div><span>State</span><span>{'Frozen' if out.get('finalized') else 'Not frozen — this is a working view, not a signed version.'}</span></div>"
        + f"<div><span>Status</span><span>{esc(out.get('disclaimer'))}</span></div>"
        + (f"<div><span>Catalogue</span><span>{esc(prov.get('caveat'))}</span></div>" if prov.get("caveat") else "")
        + "</div>"
        "</article>"
    )


async def report(request: Request) -> Response:
    """The Annex VII gap report, laid out to print.

    It renders exactly what `assemble_technical_file` returns and composes
    nothing of its own: the tool is where the file is defined, including its
    content hash, its retention period and its disclaimer. A second rendering
    of the same idea is a second thing to get out of step with the regulation.

    The page is a document, not a screen: an 816px column, a ruled head, and a
    provenance block at the foot. What a manager prints and forwards to
    somebody who has never heard of us is this page, and the print rules in
    `style.css` are the part of it that has to survive.
    """
    viewer = _viewer(request)
    if viewer is None:
        return _login_redirect(request)
    pid = request.path_params["product_id"]

    status = _call(viewer, "get_compliance_status", pid)
    if not status.get("ok"):
        return _not_found(viewer)

    out = _call(viewer, "assemble_technical_file", pid)
    name = status.get("name", "Product")

    refused = _refusal(out)
    if refused:
        return webui.page(
            "Report",
            _header(pid, name, "/report", title="Technical file gap report")
            + refused,
            signed_in_as=viewer.email,
        )

    body = (
        "<section class='wrap no-print'>"
        + _header(pid, name, "/report", title="Technical file gap report")
        + "<p class='small muted'>Print or save as PDF from your browser. The "
        "content hash at the foot ties this copy to the state it was generated "
        "from.</p></section>"
        + report_article(name, status, out)
    )
    return webui.page(
        f"{name} — Annex VII",
        body,
        signed_in_as=viewer.email,
        wrap=False,
    )
