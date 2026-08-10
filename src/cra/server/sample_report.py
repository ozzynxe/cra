"""The public sample: everything the console shows, before you sign up.

The report is the artefact that leaves the company — a manager prints it and
forwards it to somebody who has never heard of us — but it is the last of three
views, and on its own it shows neither the statutory clocks nor the gap
identification that most of the product is. So this page walks the whole
console in the order a customer meets it:

    1. where the product stands   overdue reporting obligations, the two
                                  Annex I figures, the determination table
    2. the 22 requirements        applicability, status and evidence counts,
                                  which is where gaps are actually identified
    3. the Annex VII gap report   the printable document

## Why it is generated rather than written

Every renderer here is the one the signed-in console uses —
`console._obligations_card`, `_figures`, `risk_assessment_note`,
`_determination`, `_requirement_row`, `report_article` — and the content comes
from the real catalogues: `regulation.requirements()` for the Annex I text and
anchors, `technical_file_slots()` for the Annex VII sections,
`technical_file_retention_years()` and the conformity disclaimer for the
provenance block.

Invented: which requirements are settled, which slots are filled, and the two
overdue clocks. Nothing else, because a marketing page that depicts the product
is a claim about the product, and it is the one claim on this site that nothing
else would catch going stale. `scripts/render_sample_report.py --check` fails
if the committed page has drifted, and a test runs it.

## Why it says "sample" so often

`@media print` strips the masthead, footer and navigation — that is what makes
the real report read as a document rather than a screenshot — and it strips
them here too. A printed sample would otherwise be indistinguishable from a
printed real report, and this one describes a product that does not exist.

So sections 1 and 2 carry `no-print`: printing this page yields the report
alone, exactly as printing the real console does. And the marks that matter sit
inside the printed article — the heading stamp, the product name, a
2px-bordered statement above the slot list, and the provenance block, where the
content hash would be. There is no hash. That field is what ties a printed copy
to real state, so inventing one for a fictional product would forge the only
field capable of exposing the forgery.
"""

from __future__ import annotations

from cra.regulation import (
    provenance,
    requirements,
    technical_file_retention,
    technical_file_slots,
)
from cra.server import conformity, console, webui

SAMPLE_NAME = "Atlas Gateway 4.2 — sample"

# ---- the story ---------------------------------------------------------------
#
# One product, far enough along to be interesting and typical enough to be
# useful: in scope, in a class that needs a notified body, with a confirmed but
# stale risk assessment, two statutory clocks already blown, and roughly half
# the technical file recorded. A sample where everything is green sells a
# product that does not exist; one where everything is missing sells nothing.

_FILLED_SLOTS = {"tf.1", "tf.2", "tf.3"}
_SLOT_EVIDENCE = {"tf.1": 3, "tf.2": 5, "tf.3": 2}

# Requirement id → (applicability, status, evidence count). Anything not named
# here is applicable and not started, which is where a real product begins.
_REQUIREMENT_STATE = {
    "annex_i.i.1":     ("applicable", "verified", 4),
    "annex_i.i.2.a":   ("applicable", "verified", 2),
    "annex_i.i.2.b":   ("applicable", "implemented", 3),
    "annex_i.i.2.c":   ("applicable", "implemented", 1),
    "annex_i.i.2.d":   ("applicable", "verified", 5),
    "annex_i.i.2.e":   ("applicable", "implemented", 2),
    "annex_i.i.2.f":   ("applicable", "in_progress", 1),
    "annex_i.i.2.g":   ("applicable", "in_progress", 1),
    "annex_i.i.2.h":   ("applicable", "not_started", 0),
    "annex_i.i.2.i":   ("not_applicable", "not_started", 0),
    "annex_i.i.2.j":   ("applicable", "implemented", 2),
    "annex_i.i.2.k":   ("applicable", "not_started", 0),
    "annex_i.i.2.l":   ("applicable", "implemented", 3),
    "annex_i.i.2.m":   ("not_applicable", "not_started", 0),
    "annex_i.ii.1":    ("applicable", "verified", 1),
    "annex_i.ii.2":    ("applicable", "implemented", 2),
    "annex_i.ii.3":    ("applicable", "in_progress", 4),
    "annex_i.ii.4":    ("undetermined", "not_started", 0),
    "annex_i.ii.5":    ("applicable", "implemented", 1),
    "annex_i.ii.6":    ("applicable", "verified", 1),
    "annex_i.ii.7":    ("undetermined", "not_started", 0),
    "annex_i.ii.8":    ("applicable", "not_started", 0),
}

_RISK_ASSESSMENT = {
    "present": True,
    "version": 3,
    "status": "confirmed",
    # The staleness note is a feature, not an error state: it is what stops a
    # file looking settled after the product moved underneath it.
    "stale": True,
}

_OBLIGATIONS = [
    {
        "obligation_id": "sample-obligation-1",
        "incident_id": "sample-incident-1",
        "stage": "early_warning",
        "state": "overdue",
        "hours_remaining": -31.0,
    },
    {
        "obligation_id": "sample-obligation-2",
        "incident_id": "sample-incident-1",
        "stage": "notification",
        "state": "overdue",
        "hours_remaining": -7.0,
    },
    {
        "obligation_id": "sample-obligation-3",
        "incident_id": "sample-incident-2",
        "stage": "early_warning",
        "state": "pending",
        "hours_remaining": 14.0,
    },
]


# The sample shows a product already on the market, so the Article 13(13)
# clock has started — a sample reporting "not started" would demonstrate the
# least informative branch.
_SAMPLE_RETENTION = {
    "anchor": "Article 13(13)",
    "covers": "the technical documentation and the EU declaration of conformity",
    "until": "2036-04-18T00:00:00+00:00",
    "basis": "ten_years_from_placing_on_market",
    "placed_on_market": "2026-04-18T00:00:00+00:00",
    "support_period_end": "2031-04-18T00:00:00+00:00",
}

def _requirement_views() -> list[dict]:
    """The 22, from the published catalogue, with a plausible half settled."""
    known = {r.id for r in requirements()}
    unknown = set(_REQUIREMENT_STATE) - known
    if unknown:
        raise RuntimeError(
            f"sample references requirements not in the catalogue: {sorted(unknown)}. "
            "Update _REQUIREMENT_STATE in sample_report.py."
        )
    views = []
    for req in requirements():
        applicability, status, evidence = _REQUIREMENT_STATE.get(
            req.id, ("applicable", "not_started", 0)
        )
        views.append(
            {
                "req_id": req.id,
                "anchor": req.anchor,
                "summary": req.summary,
                "applicability": applicability,
                "status": status,
                "evidence_count": evidence,
            }
        )
    return views


def _counts(views: list[dict], field: str) -> dict[str, int]:
    """Counted from the rows actually rendered, never written down twice — a
    figure that disagrees with the table under it is the one thing a sceptical
    reader will notice."""
    out: dict[str, int] = {}
    for v in views:
        out[v[field]] = out.get(v[field], 0) + 1
    return out


def _slot_views() -> list[dict]:
    known = {s.id for s in technical_file_slots()}
    unknown = (_FILLED_SLOTS | set(_SLOT_EVIDENCE)) - known
    if unknown:
        raise RuntimeError(
            f"sample references slots that are not in the catalogue: {sorted(unknown)}. "
            "Update _FILLED_SLOTS / _SLOT_EVIDENCE in sample_report.py."
        )
    views = []
    for slot in technical_file_slots():
        complete = slot.id in _FILLED_SLOTS
        view = {
            "slot": slot.id,
            "anchor": slot.anchor,
            "title": slot.title,
            "needs": list(slot.needs),
            "optional": slot.optional,
            "evidence_ids": ["sample"] * _SLOT_EVIDENCE.get(slot.id, 0),
            "sourced_from_requirements": [],
            "complete": complete,
        }
        if not complete:
            if slot.satisfied_by == "declaration_of_conformity":
                view["deferred"] = True
                view["missing"] = (
                    "Filled last, by design: freeze the file, draw up the "
                    "declaration against it, then re-freeze so this section "
                    "contains a copy."
                )
            else:
                view["missing"] = (
                    "Nothing attached. Use attach_evidence(subject_ref="
                    f"'technical_file:{slot.id}', ...)."
                )
        views.append(view)
    return views


def _payloads() -> tuple[dict, dict, list[dict]]:
    """The payloads the console renderers read, shaped as the tools shape them."""
    reqs = _requirement_views()
    slots = _slot_views()
    missing = [
        s for s in slots if not s["complete"] and not s["optional"] and not s.get("deferred")
    ]
    deferred = [s for s in slots if s.get("deferred")]

    status = {
        "ok": True,
        "name": SAMPLE_NAME,
        "economic_operator_role": "manufacturer",
        "lifecycle": "placed_on_market",
        "classification": {
            "in_scope": True,
            "product_class": "important_class_i",
            "conformity_route": "notified_body",
            "rationale": (
                "Ships a network-facing management plane and performs "
                "authentication for downstream services, which places it in the "
                "Annex III important class I category rather than the default."
            ),
        },
        "requirements": {
            "total": len(reqs),
            "by_applicability": _counts(reqs, "applicability"),
            "by_status": _counts(reqs, "status"),
        },
        "deadlines": {"open_obligations": _OBLIGATIONS, "open_count": len(_OBLIGATIONS)},
        "risk_assessment": _RISK_ASSESSMENT,
    }
    out = {
        "ok": True,
        "product_id": "sample",
        "complete": not missing,
        "slots": slots,
        "missing_slots": [
            {"slot": s["slot"], "anchor": s["anchor"], "title": s["title"]} for s in missing
        ],
        "deferred_slots": [
            {"slot": s["slot"], "anchor": s["anchor"], "why": s.get("missing")} for s in deferred
        ],
        # No content_hash and no assembled_at, deliberately. `report_article`
        # replaces both rows wholesale when sample=True; leaving the keys out
        # means a future edit that forgets the sample branch renders nothing
        # rather than something that looks like a real digest.
        "finalized": False,
        "retention": _SAMPLE_RETENTION,
        "disclaimer": conformity._DISCLAIMER,
        "provenance": provenance(),
    }
    return status, out, reqs


# ---- the page ----------------------------------------------------------------


def _intro(status: dict) -> str:
    """Figures counted from the payload, not typed into the sentence.

    The lede makes three factual claims about the example below it. Written by
    hand they would be three things to update whenever the fixture moves, and
    the version on the page is the one nobody would check."""
    counts = status["requirements"]
    overdue = sum(1 for o in status["deadlines"]["open_obligations"] if o["state"] == "overdue")
    applicable = counts["by_applicability"]["applicable"]
    done = counts["by_status"].get("implemented", 0) + counts["by_status"].get("verified", 0)
    return webui.section(
        "<div class='stack'>"
        "<p class='eyebrow'>Sample</p>"
        "<h1>What your agent produces</h1>"
        f"<p class='lede'>One product, worked through. It has missed {overdue} "
        f"statutory reporting deadlines. {applicable} of the {counts['total']} "
        f"Annex I requirements apply to it, and {applicable - done} of those "
        "have nothing recorded against them yet.</p>"
        "<p class='small muted'>It describes a product that does not exist and "
        "is not evidence of anything. Yours would carry a content hash tying it "
        "to the state it came from.</p>"
        "<p><a class='btn cta' href='/#access'>Start free</a> "
        "<a class='btn' href='/pricing'>See pricing</a></p>"
        "</div>",
        measure="no-print",
    )


def _overview(status: dict) -> str:
    """View one, as `/app/p/{id}` renders it."""
    return webui.section(
        "<div class='section-head'><h2>1. Where the product stands</h2>"
        "<p class='small muted'>The console, on opening</p></div>"
        "<div class='grid cols-2'>"
        + console._obligations_card(status["deadlines"])
        + console._figures(status["requirements"])
        + "</div>"
        + console.risk_assessment_note(status["risk_assessment"])
        + console._determination(
            status, status["classification"], status["risk_assessment"]
        )
        + "<div class='section-head'><h2>Why this classification</h2></div>"
        f"<div class='card'><p>{webui.esc(status['classification']['rationale'])}</p></div>",
        measure="no-print",
    )


def _requirements_table(reqs: list[dict], status: dict) -> str:
    """View two, as `/app/p/{id}/requirements` renders it. This is where gaps
    are actually identified, and it was the part the first sample omitted."""
    rows = "".join(console._requirement_row(r) for r in reqs)
    gaps = sum(
        1
        for r in reqs
        if r["applicability"] == "undetermined"
        or (r["applicability"] == "applicable" and r["status"] not in ("implemented", "verified"))
    )
    prov = provenance()
    return webui.section(
        "<div class='section-head'><h2>2. The 22 essential requirements</h2>"
        "<p class='small muted'>All 22, with what is recorded against each</p></div>"
        "<div class='table-wrap'><table>"
        f"<caption class='visually-hidden'>Annex I essential requirements for {webui.esc(SAMPLE_NAME)}</caption>"
        "<thead><tr><th scope='col'>Anchor</th><th scope='col'>Requirement</th>"
        "<th scope='col'>Applicability</th><th scope='col'>Status</th>"
        "<th scope='col' class='num'>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
        f"<p class='small muted'>{len(reqs)} shown of "
        f"{status['requirements']['total']}. <strong>{gaps}</strong> would leave "
        "a hole in the technical file.</p>"
        "<p class='note'><strong>A requirement with nothing recorded against it "
        "is not a finding against your product.</strong> It means nothing has "
        "been recorded here. It does not mean the work has not been done.</p>"
        + (f"<p class='small muted'>{webui.esc(prov['caveat'])}</p>" if prov.get("caveat") else ""),
        measure="no-print",
    )


def _outro() -> str:
    """What the browser does not show, said in words rather than mocked up.

    Drafting a report, attaching evidence, deciding a risk and scanning an SBOM
    all happen in the agent, next to the code. Inventing screens for them would
    be inventing product."""
    return webui.section(
        "<div class='section-head'><h2>The rest happens in the agent</h2></div>"
        "<p>This console is read-only. The work happens in your coding agent, "
        "in the repository the answers come from: settling scope, deciding each "
        "risk, attaching evidence with its provenance, recording a "
        "vulnerability as actively exploited, drafting the ENISA report. A "
        "browser cannot see your repository, which is why this is an MCP server "
        "rather than a portal.</p>"
        "<p class='small muted'>Daily SBOM scanning against OSV and CISA KEV, "
        "the Article 14 clocks that opened the obligations above, and the audit "
        "trail behind every row on this page all run there too.</p>"
        "<p><a class='btn cta' href='/#access'>Start free</a> "
        "<a class='btn' href='/'>Back to the homepage</a></p>",
        measure="no-print",
    )


def render() -> str:
    status, out, reqs = _payloads()
    return (
        _intro(status)
        + _overview(status)
        + _requirements_table(reqs, status)
        + webui.section(
            "<div class='section-head'><h2>3. The Annex VII technical file</h2>"
            "<p class='small muted'>The page that gets printed and forwarded</p></div>",
            measure="no-print",
        )
        + console.report_article(SAMPLE_NAME, status, out, sample=True)
        + _outro()
    )


def page():
    """Rendered as a response, for serving from the app if that is ever wanted.

    Today the file is static in `www/` and Caddy serves it straight off disk,
    which needs no change to the host's path matcher.
    """
    return webui.page(
        "Sample: what your agent produces",
        render(),
        description=(
            "A worked example of what Skarp CRA records: open Article 14 "
            "reporting deadlines, the 22 Annex I essential requirements with "
            "applicability and evidence, and the Annex VII technical "
            "documentation as a gap report."
        ),
        indexable=True,
        wrap=False,
    )
