#!/usr/bin/env python3
"""Screen what is about to be published: the tree, and the commit messages.

    scripts/screen.py                      # working tree
    scripts/screen.py --range origin/main..HEAD
    scripts/screen.py --staged             # what is about to be committed

This repository is published, and so are its commit messages. A message is read
as often as the file it describes and no later edit to that file takes it back,
so **the message range is screened, not only the tree**. A check that reads only
files passes a clean tree whose log undoes it.

## What this can and cannot do

It catches mechanical things: currency figures, the identifying values in
`deploy/deploy.env`, a fixed vocabulary of commercial and estate-sizing phrases,
and text that announces its own redaction.

It cannot catch reasoning. An argument for where a commercial boundary sits,
written as engineering rationale, trips no pattern and is exactly the thing that
does not belong here.

**A green run is not a clearance.** It means nothing on the list was found.
Treating it as more than that would be this repository doing the thing the
product exists to prevent — letting an absence of findings read as a finding of
absence. Reading the diff is the control; this is the cheap half that runs every
time.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Skip our own vocabulary, and anything not shipped.
SKIP_PATHS = re.compile(
    r"(^|/)(\.git|\.venv|node_modules|private|__pycache__|\.mypy_cache)(/|$)"
    r"|(^|/)scripts/screen\.py$"
)

# Two forms, both requiring a reason, because the reason is the reviewable part.
#
#   screen: allow: <why>              — this line only
#   screen: allow-file <rule>: <why>  — that one rule, this whole file
#
# The file form exists because a per-line marker cannot be used inside a string
# that gets rendered: appending a comment to `<p class="price">€0</p>` puts the
# comment on the page. It names the rule so it stays narrow — a blanket
# file-level mute would turn the first inconvenient hit into permanent silence.
ALLOW = "screen: allow:"
ALLOW_FILE = re.compile(r"screen: allow-file ([a-z-]+):")

Rule = tuple[str, re.Pattern, str]

RULES: list[Rule] = [
    (
        "money",
        # `$0`/`$1` are shell positionals and `${...}` is an expansion, so a bare
        # `$` and one digit is not an amount. Require a currency symbol with a
        # decimal, a rate, a magnitude, or two or more digits.
        re.compile(
            r"[€£]\s?\d"
            r"|\$\s?\d+(?:[.,]\d+|\s*(?:/|per\b|k\b|m\b|million|bn\b)|\d)"
            r"|\b\d+\s?(?:cents?|EUR|USD)\b"
            r"|\b\d+\s?/\s?(?:mo|month)\b",
            re.I,
        ),
        "An amount. Prices live in the payment provider and are read at render "
        "time; run costs are not published at all.",
    ),
    (
        "unit-economics",
        re.compile(
            r"marginal cost|cost per (?:product|user|account|signup|call)"
            r"|costs? (?:us|nothing) to serve|(?:cheap|free) to serve|loss leader"
            r"|unit economics|per-signup cost|grows with signups|rather than with revenue",
            re.I,
        ),
        "What the service costs to run, or a claim about it.",
    ),
    (
        "strategy",
        re.compile(
            r"go.to.market|land.?grab|buyer persona|conversion (?:rate|funnel|reasoning)"
            r"|converts better|revenue foregone|the thing being sold|willingness to pay"
            r"|competitive positioning|our competitors?\b",
            re.I,
        ),
        "Commercial reasoning. A decision may be recorded; the argument for it "
        "belongs outside this repository.",
    ),
    (
        "estate",
        re.compile(
            r"one row today|the (?:first|only) customer|single point of sale"
            r"|(?:only|just) (?:one|two|three) (?:account|product|customer|user)s?\b"
            r"|runs on a single instance|no staging|small project",
            re.I,
        ),
        "How large the deployment or the customer base is.",
    ),
    (
        "self-advertising-redaction",
        re.compile(
            r"do not republish|\(withheld\)|not published here|deliberately withheld"
            r"|scrubbed (?:from|out)|private archive|figures are (?:measured|kept) but",
            re.I,
        ),
        "Text that announces something was removed, which tells a reader where "
        "to dig. Say nothing rather than saying it was withheld.",
    ),
]


def _deploy_env_values() -> list[tuple[str, str]]:
    """The identifying values, read from the gitignored file that holds them.

    Exact rather than heuristic, and the highest-value check here: it cannot
    false-positive, and it catches the instance name, bucket names, account id,
    superuser and zone id by their actual values instead of by a pattern that
    hopes to describe them. Absent on a machine that has never deployed, which
    is why its absence is reported rather than passed over in silence.
    """
    path = ROOT / "deploy" / "deploy.env"
    if not path.exists():
        return []
    out = []
    # Deliberately public. `$CRA_DOMAIN` resolves from anywhere, so keeping it
    # out of the repo would conceal nothing and would break every snippet that
    # names the service. Screening for it would be noise, and a screen that
    # cries wolf is one people learn to push past.
    public = {"CRA_DOMAIN", "CRA_REMOTE_DIR", "CRA_SSH_KEY"}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.split("#")[0].strip().strip("'\"")
        if key in public:
            continue
        # Options and paths are not identifiers; short values are regions and
        # ports, too generic to match on without drowning the real hits.
        if value.startswith("-") or " " in value or value.lower().startswith(("http", "/")):
            continue
        if len(value) >= 8:
            out.append((key, value))
    return out


def _iter_tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
    ).stdout.split("\n")
    return [ROOT / p for p in out if p and not SKIP_PATHS.search(p)]


def _scan_text(where: str, text: str, secrets: list[tuple[str, str]]) -> list[str]:
    hits = []
    muted = set(ALLOW_FILE.findall(text))
    for n, line in enumerate(text.splitlines(), 1):
        allowed = ALLOW in line
        for name, pattern, why in RULES:
            if allowed or name in muted:
                continue
            m = pattern.search(line)
            if m:
                hits.append(f"{where}:{n}: [{name}] {m.group(0)!r}\n      {why}")
        # Not covered by the line-level allowance. That form is written for a
        # phrase somebody has judged fine in context; an identifying value is
        # never fine, and letting one marker cover both means an allowance added
        # for a word silently mutes a bucket name that lands on the same line
        # later. The file form can still name `identifying-value` explicitly,
        # which at least leaves a reason to read.
        if "identifying-value" in muted:
            continue
        for key, value in secrets:
            if value in line:
                hits.append(
                    f"{where}:{n}: [identifying-value] matches ${key} from "
                    f"deploy/deploy.env\n      This value is meant to be read "
                    f"from the environment, never written down."
                )
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--range", help="commit range whose messages to screen, e.g. origin/main..HEAD")
    ap.add_argument("--staged", action="store_true", help="screen staged content instead of the tree")
    args = ap.parse_args()

    secrets = _deploy_env_values()
    hits: list[str] = []

    if args.staged:
        names = subprocess.run(
            ["git", "-C", str(ROOT), "diff", "--cached", "--name-only"],
            capture_output=True, text=True, check=True,
        ).stdout.split()
        for name in names:
            if SKIP_PATHS.search(name):
                continue
            blob = subprocess.run(
                ["git", "-C", str(ROOT), "show", f":{name}"],
                capture_output=True, text=True,
            )
            if blob.returncode == 0:
                hits += _scan_text(name, blob.stdout, secrets)
    else:
        for path in _iter_tracked_files():
            try:
                hits += _scan_text(
                    str(path.relative_to(ROOT)), path.read_text(errors="ignore"), secrets
                )
            except (OSError, UnicodeDecodeError):
                continue

    # The half that matters most, and the one a file-based check misses.
    if args.range:
        # A text separator, not a NUL: subprocess refuses an argument containing
        # an embedded null byte, so `--format` cannot carry one.
        sep = "@@screen-commit@@"
        log = subprocess.run(
            ["git", "-C", str(ROOT), "log", f"--format=%H%n%B%n{sep}", args.range],
            capture_output=True, text=True,
        )
        if log.returncode != 0:
            # A range git cannot resolve must not read as "no messages found".
            print(
                f"screen: could not read commit messages for {args.range!r} — "
                f"{log.stderr.strip()}",
                file=sys.stderr,
            )
            return 1
        else:
            for entry in log.stdout.split(sep):
                entry = entry.strip()
                if not entry:
                    continue
                sha, _, body = entry.partition("\n")
                hits += _scan_text(f"commit {sha[:9]}", body, secrets)

    if not secrets:
        print(
            "note: deploy/deploy.env not found, so identifying values were not "
            "screened by value. On a machine that deploys, they would be.",
            file=sys.stderr,
        )

    if hits:
        print(f"\nscreen: {len(hits)} thing(s) to look at before this is published.\n")
        for h in hits:
            print(f"  {h}")
        print(
            "\nEach is a prompt, not a verdict. If one is fine, say why in the "
            "file:\n"
            "  screen: allow: <why>              on that line\n"
            "  screen: allow-file <rule>: <why>  for that rule in that file\n"
            "The reason is the point — it is what a reviewer reads later.\n"
        )
        return 1

    print(
        "screen: nothing on the list found.\n"
        "This does not mean it is safe to publish. Commercial reasoning trips no "
        "pattern; read the diff."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
