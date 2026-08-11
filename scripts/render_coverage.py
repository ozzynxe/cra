#!/usr/bin/env python
"""Write www/coverage.html from docs/coverage.yaml and the regulation catalogue.

    python scripts/render_coverage.py           # write
    python scripts/render_coverage.py --check   # exit 1 if stale

Two columns and nothing else: what the CRA obligates, and what this tool does
about it.

The first version of this page rendered the engineering self-audits that
measure *the server* against the regulation. That is the right question to ask in a planning
document and the wrong one to publish, because Article 13 binds the
manufacturer, not the tool. Read that way, 13(1) — design and produce in
accordance with Annex I Part I — came out as the obligation the tool was
"furthest from meeting", which tells a reader nothing except that software
does not write software. What actually matters to them is that the requirement,
the risk that makes it applicable and the evidence all arrive in front of the
agent doing the engineering. Those documents still exist and are still useful;
they are just not this page.

Annex I and Annex VII obligation text comes from `src/cra/regulation/` rather
than the YAML, so a catalogue renumbering cannot leave this page citing
provisions that no longer exist. `annex_i.yaml`'s own header records that
happening once.

Static in `www/` so Caddy serves it off disk, the same as
`scripts/render_sample_report.py`. `tests/unit/test_coverage_page.py` runs
`--check`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.regulation import (  # noqa: E402
    provenance,
    requirements,
    technical_file_slots,
)
from cra.server import webui  # noqa: E402

TARGET = ROOT / "www" / "coverage.html"
SOURCE = ROOT / "docs" / "coverage.yaml"

BANNER = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Written by scripts/render_coverage.py from docs/coverage.yaml and the\n"
    "     catalogue in src/cra/regulation/. Edit those and regenerate. -->"
)

esc = webui.esc


def _text(value: str) -> str:
    """Escape, then let `backticks` and *asterisks* become code and emphasis.

    In that order, always. Escaping first means a span can only ever wrap text
    that has already been made inert, so a stray `<` in the YAML cannot become
    markup by being mentioned between backticks.

    Two markers is the whole vocabulary. The YAML is prose about a regulation
    and this page is a reference table; anything needing more formatting than
    a tool name and an emphasised word is saying too much.
    """
    out = esc(value.strip())
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return re.sub(r"(?<!\w)\*([^*]+)\*(?!\w)", r"<em>\1</em>", out)


def _row(anchor: str, obligation: str, support: str, tools) -> str:
    """One obligation. Left: what the law requires of you. Right: what we do."""
    tool_line = (
        f'            <p class="tools small muted mono">{esc(" · ".join(tools))}</p>\n'
        if tools
        else ""
    )
    return (
        "      <div>\n"
        f"        <dt>{esc(anchor)}</dt>\n"
        "        <dd>\n"
        # The labels are not decoration. This page puts a paraphrase of the law
        # beside a claim about our software, and a reader who cannot tell which
        # is which at a glance is being misled by the layout.
        '          <div class="obligation">\n'
        '            <p class="lbl">The obligation</p>\n'
        f"            <p>{_text(obligation)}</p>\n"
        "          </div>\n"
        '          <div class="support">\n'
        '            <p class="lbl">What Skarp CRA does</p>\n'
        f"            <p>{_text(support)}</p>\n"
        f"{tool_line}"
        "          </div>\n"
        "        </dd>\n"
        "      </div>\n"
    )


def _section(anchor: str, title: str, lede: str, rows: str) -> str:
    return webui.section(
        '<div class="section-head">\n'
        f'  <h2 id="{esc(anchor)}">{esc(title)}</h2>\n'
        "</div>\n"
        f'<p class="section-lede">{esc(lede.strip())}</p>\n'
        f'<dl class="coverage obligations">\n{rows}</dl>'
    )


def build() -> str:
    data = yaml.safe_load(SOURCE.read_text())
    prov = provenance()
    parts = []

    intro = f"""<div class="stack">
<p class="eyebrow">Coverage</p>
<h1>What the CRA requires, and what we do about it</h1>
<p class="lede">Every obligation, with the tools that address it. Where we do
nothing for an obligation, the row says so — this is the whole list, not the
flattering part of it.</p>
<p class="small muted">The tool does not carry your obligations; you do. It
does not certify conformity, file your reports, or replace a notified body.
What it does is put each requirement, the risk that makes it applicable and the
evidence for it in front of the agent working in your repository.</p>
<p class="small muted">Every obligation summary is a paraphrase, never a
quotation. The Article 13 and 14 summaries were written against the published
text on {esc(data['paraphrase_verified_at'])}; the Annex I and Annex VII
entries are the catalogue this server itself runs on, reconciled on
{esc(prov['verified_at'])}. Both against CELEX {esc(prov['celex'])}. Read them
beside <a href="{esc(prov['url'])}">the authoritative text</a>, not instead of
it — and note that Article 7(4) delegated acts can amend the annexes.</p>
<p><a class="btn cta" href="/#access">Connect your agent</a> <a class="btn" href="/docs">Setup</a> <a class="btn" href="/pricing">Pricing</a></p>
</div>"""
    parts.append(webui.section(intro))

    # Articles 13 and 14 — both columns come from the YAML.
    for section in data["sections"]:
        rows = "".join(
            _row(r["anchor"], r["obligation"], r["support"], r.get("tools") or [])
            for r in section["rows"]
        )
        parts.append(_section(section["id"], section["title"], section["lede"], rows))

    # Annex I — obligation text from the catalogue, keyed by requirement id.
    support = data["annex_i"]
    stock = data["evidence_answer"]
    ledes = data["annex_ledes"]
    for part, title in (
        ("part_i", "Annex I Part I — Essential cybersecurity requirements"),
        ("part_ii", "Annex I Part II — Vulnerability handling requirements"),
    ):
        rows = ""
        for req in (r for r in requirements() if r.part == part):
            entry = support[req.id]
            text = stock if entry["support"] == "evidence" else entry["support"]
            rows += _row(req.anchor, req.summary, text, entry.get("tools") or [])
        parts.append(_section(part.replace("_", "-"), title, ledes[part], rows))

    # Annex VII — titles and anchors from the catalogue, keyed by slot id.
    rows = ""
    for slot in technical_file_slots():
        entry = data["annex_vii"][slot.id]
        rows += _row(
            slot.anchor, slot.title, entry["support"], entry.get("tools") or []
        )
    parts.append(
        _section(
            "annex-vii",
            "Annex VII — Technical documentation",
            ledes["annex_vii"],
            rows,
        )
    )

    parts.append(
        webui.section(
            '<p class="small muted">'
            f"{esc(prov['caveat'])}"
            "</p>"
        )
    )

    response = webui.page(
        "Coverage — what the CRA requires, and what we do",
        "".join(parts),
        description=(
            "Obligation by obligation: what the EU Cyber Resilience Act requires "
            "of a manufacturer, and what Skarp CRA does to help meet it."
        ),
        indexable=True,
        wrap=False,
    )
    html = response.body.decode()
    marker = '<html lang="en">'
    return html.replace(marker, marker + "\n" + BANNER, 1) + "\n"


def main() -> int:
    fresh = build()
    if "--check" in sys.argv:
        if not TARGET.exists():
            print(f"{TARGET} is missing — run scripts/render_coverage.py", file=sys.stderr)
            return 1
        if TARGET.read_text() != fresh:
            print(
                f"{TARGET} is stale.\n"
                "The published page no longer matches docs/coverage.yaml or the "
                "regulation catalogue, which means the site is describing "
                "coverage this repo does not have. Regenerate:\n"
                "    python scripts/render_coverage.py",
                file=sys.stderr,
            )
            return 1
        print(f"{TARGET.name} is current")
        return 0

    TARGET.write_text(fresh)
    print(f"wrote {TARGET} ({len(fresh):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
