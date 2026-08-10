"""The publication screen catches what it claims to, and says what it cannot.

`scripts/screen.py` is the mechanical half of the control on what leaves this
repository. It is worth testing for the same reason the entitlement tables are
swept rather than spot-checked: a screen that silently stopped matching would
look exactly like a clean tree, and the whole point of it is that a green run
must mean something.

Two properties are pinned here:

  * it reads **commit messages**, not only files. That is the failure that
    actually happened — three passes cleaned the tree and each wrote a message
    describing what it had removed, so the tree was clean and the log restored
    it. A file-only screen passes that with nothing to report.
  * an allowance requires a **reason in the file**. A mute with no reason is a
    mute nobody can review later, which is how a control becomes decoration.

**Every fixture below is invented.** An earlier version of this file used the
real sentences the screen had just been built to remove — the actual figure, the
actual removed lines — on the reasoning that testing a filter against the thing
it filters is more honest. It is not: it put the material back into the tree, in
the one file that had muted the screen so nothing could ever flag it. The
control had become the archive.

So the fixtures are nonsense with the right shape. That is all a regex needs,
and it means this file can be screened like any other. It is not muted, and it
must not be.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCREEN = ROOT / "scripts" / "screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("screen", SCREEN)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["screen"] = mod
    spec.loader.exec_module(mod)
    return mod


screen = _load()


def _scan(text: str) -> list[str]:
    return screen._scan_text("t", text, [])


# ---- what it must catch ------------------------------------------------------


def _j(*parts: str) -> str:
    """Join fragments into a fixture at run time.

    The fixtures have to contain the exact phrases the screen matches, and this
    file has to be screenable like every other — those pull in opposite
    directions, and muting the file is the wrong way to resolve it. Assembling
    the phrase from pieces satisfies both: the regex sees the whole string, and
    the source contains no line that matches anything.
    """
    return "".join(parts)


@pytest.mark.parametrize(
    "line,rule",
    [
        (_j("the marginal ", "cost of a widget is unremarkable"), "unit-economics"),
        (_j("wombats are cheap ", "to serve"), "unit-economics"),
        (_j("\u20ac", "11 / month, or \u20ac", "110 billed annually"), "money"),
        (_j("about $9", ".9999/month per widget"), "money"),
        (_j("costs us 11 ", "cents in postage"), "money"),
        (_j("the land ", "grab beats the revenue ", "foregone"), "strategy"),
        (_j("the badger is the thing ", "being sold"), "strategy"),
        (_j("our compet", "itors sell badgers too"), "strategy"),
        (_j("the first ", "customer asked about badgers"), "estate"),
        (_j("no stag", "ing, one environment"), "estate"),
        (_j("runs on a single ", "instance in a shed"), "estate"),
        (_j("Keep this file for planning; do not repub", "lish it"), "self-advertising-redaction"),
        (_j("| 5 GB | (with", "held) |"), "self-advertising-redaction"),
        (_j("kept in a private ", "archive repository"), "self-advertising-redaction"),
    ],
)
def test_it_catches_the_categories_it_claims_to(line, rule):
    hits = _scan(line)
    assert hits, f"{line!r} was not caught at all"
    assert any(f"[{rule}]" in h for h in hits), f"{line!r} caught, but not as {rule}"


def test_an_identifying_value_is_matched_by_value_not_by_pattern():
    """The strongest check here, and the one that cannot false-positive: the
    real values are read from the gitignored file that holds them."""
    secrets = [("CRA_BACKUP_BUCKET", "cra-backups-000000000000")]
    hits = screen._scan_text("t", "aws s3 cp x s3://cra-backups-000000000000/", secrets)
    assert hits and "identifying-value" in hits[0]
    assert "CRA_BACKUP_BUCKET" in hits[0]


# ---- what it must not catch --------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'cd "$(dirname "$0")/.."',            # shell positional, not an amount
        "run scripts/dev_up.sh $1 --serve",   # ditto
        "Article 64 sets fines reaching 2.5% of turnover",
        "the support period is five years",
        "CONFORMITY is the only paid feature",   # a decision, which may be recorded
    ],
)
def test_it_leaves_ordinary_text_alone(line):
    """A screen that cries wolf is one people learn to push past, so the false
    positives matter as much as the misses."""
    assert not _scan(line), f"{line!r} should not have tripped anything"


# ---- allowances --------------------------------------------------------------


def test_a_line_can_be_allowed_with_a_reason():
    assert _scan(_j("the marginal ", "cost of a widget is x"))
    assert not _scan(_j("the marginal ", "cost of a widget is x  # screen: allow: a fixture"))


def test_a_file_allowance_is_scoped_to_one_named_rule():
    """A blanket file-level mute would turn the first inconvenient hit into
    permanent silence, so the directive has to name the rule it silences."""
    text = _j("screen: allow-file money: invented amounts\n",
              "\u20ac", "11 / month\n", "the marginal ", "cost of a widget\n")
    hits = _scan(text)
    assert not any("[money]" in h for h in hits)
    assert any("[unit-economics]" in h for h in hits), "an unrelated rule was silenced too"


# ---- the failure that actually happened --------------------------------------


def test_commit_messages_are_screened_not_just_files(tmp_path):
    """A file-only screen passes a clean tree whose log restores it."""
    repo = tmp_path / "r"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True,
                                    capture_output=True, text=True)
    run("init", "-q")
    run("config", "user.email", "t@example.test")
    run("config", "user.name", "t")
    (repo / "a.txt").write_text("nothing interesting here\n")
    run("add", "-A")
    run("commit", "-q", "-m",
        _j("Tidy the badger module\n\nIt said the land ",
           "grab beats the revenue ", "foregone."))

    # `screen.py` resolves its own repository root, so the message is scanned
    # directly rather than by running it with a different cwd.
    body = subprocess.run(["git", "-C", str(repo), "log", "--format=%B", "-1"],
                          capture_output=True, text=True).stdout
    hits = _scan(body)
    assert any("[strategy]" in h for h in hits), (
        "a commit message describing what it removed was not caught"
    )


def test_the_clean_message_says_it_is_not_a_clearance(capsys):
    """Same discipline as `not_a_clean_bill` and `open_obligations: null`: an
    absence of findings must not read as a finding of absence."""
    src = SCREEN.read_text()
    assert "does not mean it is safe to publish" in src


def test_a_range_it_cannot_read_fails_rather_than_passing():
    """Found by running the hook on a deliberately bad commit and watching it
    report the file and miss the message.

    With no upstream the hook fell back to `<root>^..HEAD`. The root commit has
    no parent, so `git log` errored, and the screen read a non-zero exit as
    "no messages to look at" and passed. A check that cannot see its input must
    say so — the same rule as `scan_incomplete`, where a feed that could not be
    reached and a clean result are the same zero.
    """
    out = subprocess.run(
        [sys.executable, str(SCREEN), "--range", "no-such-ref..HEAD"],
        capture_output=True, text=True,
    )
    assert out.returncode != 0
    assert "could not read commit messages" in out.stderr


def test_a_range_resolving_to_no_commits_is_not_a_clean_result():
    """The CI job screened `<root>..HEAD`, which excludes the root commit. On a
    freshly squashed history that is every commit there is, so the check ran,
    found nothing to read, and reported green on the one push it existed for.

    Pinned as a property of the range rather than of the shell: a range that
    resolves to zero commits has told you nothing, and nothing is not clean.
    """
    root = subprocess.run(["git", "-C", str(ROOT), "rev-list", "--max-parents=0", "HEAD"],
                          capture_output=True, text=True).stdout.split()[-1]
    empty = subprocess.run(["git", "-C", str(ROOT), "log", "--oneline", f"{root}..{root}"],
                           capture_output=True, text=True).stdout.strip()
    assert empty == "", "fixture assumption wrong: that range should be empty"
    assert subprocess.run(
        ["git", "-C", str(ROOT), "log", "--oneline", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip(), "`HEAD` must include the root commit, which is why the hook uses it"


def test_a_line_allowance_does_not_mute_an_identifying_value():
    """A phrase can be fine in context. A bucket name never is, so one marker
    must not cover both."""
    secrets = [("CRA_BACKUP_BUCKET", "cra-backups-000000000000")]
    line = "s3://cra-backups-000000000000/db  # screen: allow: the marginal cost of a widget"
    hits = screen._scan_text("t", line, secrets)
    assert any("identifying-value" in h for h in hits)
    assert not any("[unit-economics]" in h for h in hits)
