"""The audit trail may not assert a human did something the server cannot see.

Issue #46, found by an adversarial end-to-end run: twelve advisory dismissals
made by an agent over MCP were recorded as `actor_kind: human`, while the
requirement edits in the same session were recorded as `agent`. Triage found
eleven handlers doing it, and they were the wrong eleven — `decide_risk`,
`confirm_risk_assessment`, `sign_off`, `place_on_market`, `dismiss_advisory`,
`record_report_submission` and friends. The acts that decide, freeze and sign.

Every one of them arrives over the MCP wire. There is no path by which the
server observes a person: the console is read-only, and a connector token
identifies an account, not who is holding the keyboard. So `human` was an
assertion about the world made on no evidence, inside the one record an
authority may read.

`propose_risks` is the exception and shows what honest looks like:
`actor_kind="model" if model else "agent"`, with `actor_model` recorded beside
it — because the caller *tells* it which model wrote the text.
"""

from __future__ import annotations

import inspect
import pathlib

from cra.agents import dispatch

_SRC = pathlib.Path(inspect.getfile(dispatch)).parent.parent / "server"


def test_no_handler_claims_a_human_performed_the_action():
    """Swept over the source rather than the dispatch tables.

    A handler can pass `actor_kind` through a variable, so reading the files is
    what catches the literal. It is also the form the mistake actually took:
    eleven copies of the same keyword argument, added one at a time.
    """
    offenders = []
    for path in sorted(_SRC.glob("*.py")):
        # `audit.py` defines the parameter and its docstring quotes the literal
        # while explaining why nothing should pass it. Excluding the definition
        # site is not a hole: it has no `record(...)` call of its own to make.
        if path.name == "audit.py":
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if 'actor_kind="human"' in line or "actor_kind='human'" in line:
                offenders.append(f"{path.name}:{i}")

    assert not offenders, (
        "these record an audit row asserting a person performed the action, "
        f"which the server cannot know over MCP: {offenders}. Leave "
        "`actor_kind` unset — it defaults to `agent`. If a genuinely "
        "human-originated write path now exists, say so in audit.record's "
        "docstring and in this test before setting it."
    )


def test_the_default_is_agent():
    """The whole fix rests on this. If the default were `human`, removing the
    eleven keyword arguments would have changed nothing."""
    sig = inspect.signature(__import__("cra.server.audit", fromlist=["record"]).record)
    assert sig.parameters["actor_kind"].default == "agent"


def test_the_sweep_is_reading_real_files():
    """A guard on the guard: a wrong `_SRC` makes the sweep above pass on an
    empty directory, which is the failure mode of every source-level check."""
    names = {p.name for p in _SRC.glob("*.py")}
    for expected in ("risk.py", "advisories.py", "conformity.py", "releases.py"):
        assert expected in names, f"{expected} not found under {_SRC}"


def test_an_authored_risk_still_records_which_model_wrote_it():
    """The other direction. Removing the false `human` claims must not remove
    the one true attribution the codebase has: `propose_risks` takes the model
    name from the caller, so it can say what wrote the text.
    """
    src = (_SRC / "risk.py").read_text()
    assert 'actor_kind="model" if model else "agent"' in src
    assert "actor_model=model" in src
