#!/usr/bin/env python
"""Write www/sample-report.html from the real report renderer.

    python scripts/render_sample_report.py           # write
    python scripts/render_sample_report.py --check   # exit 1 if stale

The page is static so Caddy serves it off disk with no change to the host's
`@api` path matcher, and so reading it never touches the application. It is
generated rather than hand-written so it cannot quietly stop
resembling the report customers actually get — `tests/unit/test_sample_report.py`
runs `--check`.

Regenerate whenever the report renderer, the Annex VII catalogue or the
retention period changes. The test will tell you.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cra.server import sample_report  # noqa: E402

TARGET = ROOT / "www" / "sample-report.html"

BANNER = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Written by scripts/render_sample_report.py from the same renderer the\n"
    "     signed-in report uses, so this page cannot drift from the product.\n"
    "     Edit src/cra/server/sample_report.py and regenerate. -->\n"
)


def build() -> str:
    response = sample_report.page()
    html = response.body.decode()
    # After <!DOCTYPE html>, so the doctype stays first.
    marker = "<html lang=\"en\">"
    return html.replace(marker, marker + "\n" + BANNER.rstrip(), 1) + "\n"


def main() -> int:
    fresh = build()
    check = "--check" in sys.argv

    if check:
        if not TARGET.exists():
            print(f"{TARGET} is missing — run scripts/render_sample_report.py", file=sys.stderr)
            return 1
        if TARGET.read_text() != fresh:
            print(
                f"{TARGET} is stale.\n"
                "The sample report no longer matches what the renderer produces, "
                "which means the page is advertising something the product does "
                "not do. Regenerate:\n"
                "    python scripts/render_sample_report.py",
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
