"""Can a caller find out what it is talking to?

Both of these exist because of a real incident: a session opened before a
deploy kept offering the old tool list while the server answered with new code,
and the agent concluded the server was broken and invented a workaround. The
server cannot ask a client whether its cache is stale. It can only hand over
the truth in a place the client does not cache — a tool result.
"""

from __future__ import annotations

import types

import cra
import cra.buildinfo as buildinfo
from cra.agents import dispatch as dispatcher


def _fake_build() -> types.SimpleNamespace:
    """Stand in for the module `deploy.sh` generates.

    Patched as an attribute of the `cra` package, not just in `sys.modules`:
    `from cra import _build` resolves the attribute first, so a `sys.modules`
    entry is shadowed whenever a real `_build.py` is present — which it is on
    any machine that has run a deploy.
    """
    return types.SimpleNamespace(
        COMMIT="abc1234", BRANCH="main", BUILT_AT="2026-08-06T00:00:00Z"
    )


def test_a_dev_tree_says_dev_rather_than_inventing_a_commit():
    """`_build` is generated at deploy time. Without it the honest answer is
    "unknown" — a wrong hash is worse than no hash, because it is actionable."""
    info = buildinfo.build_info()
    assert info["source"] in ("dev", "env", "build")
    if info["source"] == "dev":
        assert info["commit"] is None
        assert info["release"] is None


def test_release_falls_back_to_the_env_var(monkeypatch):
    monkeypatch.setenv("CRA_RELEASE", "v-from-env")
    info = buildinfo.build_info()
    assert info["release"] == "v-from-env"
    assert info["source"] in ("env", "build")


def test_the_version_is_always_reported():
    assert buildinfo.build_info()["version"]


def test_the_tool_list_comes_from_the_dispatcher_not_a_hand_written_list():
    """A hand-maintained list drifts from what is callable, which is exactly
    the failure this is supposed to detect."""
    dispatcher._ensure_handlers_loaded()
    assert set(buildinfo.tool_names()) == {*dispatcher._READ, *dispatcher._MUTATING}


def test_the_risk_assessment_tools_are_in_the_authoritative_list():
    names = set(buildinfo.tool_names())
    assert {
        "start_risk_assessment",
        "propose_risks",
        "decide_risk",
        "confirm_risk_assessment",
        "get_risk_assessment",
    } <= names


def test_server_identity_carries_the_list_and_says_what_to_do_with_it():
    ident = buildinfo.server_identity()
    assert ident["tool_count"] == len(ident["tools"])
    assert "start_risk_assessment" in ident["tools"]
    hint = ident["if_your_tool_list_differs"]
    assert "reconnect" in hint
    # The instruction that matters: a stale menu must not become a workaround.
    assert "workaround" in hint


def test_overview_hands_the_authoritative_list_to_every_new_session():
    """`cra_overview` is the orientation call, so it is where a client with a
    cached tool list finds out its menu is out of date."""
    out = dispatcher.dispatch("cra_overview", "", "u1", {})
    assert out["ok"] is True
    assert out["server"]["tool_count"] >= 31
    assert "start_risk_assessment" in out["server"]["tools"]


def test_a_stale_release_env_var_is_flagged_not_silently_preferred(monkeypatch):
    """CRA_RELEASE is hand-set and rots. It is also what Sentry tags every
    error with, so a stale one files today's crashes under an old build."""
    fake = _fake_build()
    monkeypatch.setattr(cra, "_build", fake, raising=False)
    monkeypatch.setenv("CRA_RELEASE", "something-old")

    info = buildinfo.build_info()
    assert info["commit"] == "abc1234"
    assert info["release"] == "something-old"
    assert info["release_stale"] is True


def test_release_defaults_to_the_deployed_commit(monkeypatch):
    fake = _fake_build()
    monkeypatch.setattr(cra, "_build", fake, raising=False)
    monkeypatch.delenv("CRA_RELEASE", raising=False)

    info = buildinfo.build_info()
    assert info["release"] == "abc1234"
    assert "release_stale" not in info
    assert buildinfo.release() == "abc1234"
