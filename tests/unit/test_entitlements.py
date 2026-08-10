"""What a plan covers, and what a refusal is allowed to say.

Two things here are load-bearing beyond "the gate works":

**The table sweep.** Every registered tool must be classified free or gated.
The one membership hole this codebase ever had got in through a handler written
without the check its neighbours had, and the fix was a test that sweeps rather
than spot-checks. Same shape, same reason.

**The wording of a refusal.** This service exists to stop an absence of
knowledge reading as knowledge of absence. A paywall is the easiest place in
the whole product to break that: "not included in your plan" must never land as
"nothing to report". Those assertions are not style checks.
"""

from __future__ import annotations

import pytest

from cra.agents import dispatch
from cra.server import entitlements


@pytest.fixture(autouse=True)
def _enforced(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "1")


@pytest.fixture
def free(monkeypatch):
    monkeypatch.setattr(entitlements, "plan_for", lambda _uid: entitlements.FREE)
    return entitlements.FREE


# ---- the sweep ---------------------------------------------------------------


def test_every_tool_is_classified_free_or_gated():
    """A new tool cannot ship without someone deciding which side it is on."""
    dispatch._ensure_handlers_loaded()
    registered = set(dispatch._READ) | set(dispatch._MUTATING)
    unclassified = registered - set(dispatch._REQUIRES) - dispatch._FREE
    assert not unclassified, (
        f"add these to _REQUIRES or _FREE in dispatch.py: {sorted(unclassified)}"
    )


def test_nothing_is_classified_twice():
    assert not (set(dispatch._REQUIRES) & dispatch._FREE)


def test_the_tables_name_only_real_tools():
    """A rename that misses one of these tables must fail loudly, not silently
    stop gating the tool it used to name."""
    dispatch._ensure_handlers_loaded()
    registered = set(dispatch._READ) | set(dispatch._MUTATING)
    phantom = (set(dispatch._REQUIRES) | dispatch._FREE) - registered
    assert not phantom, f"these are gated but not registered: {sorted(phantom)}"


def test_every_required_feature_exists():
    assert set(dispatch._REQUIRES.values()) <= entitlements.ALL_FEATURES


def test_the_free_pass_reaches_a_confirmed_assessment_and_a_gap_report():
    """The free tier's whole promise: find out what the CRA asks of this
    product and where it stands. If any of these were gated, there would be
    nothing to be free."""
    for name in (
        "classify_product",
        "start_risk_assessment",
        "propose_risks",
        "decide_risk",
        "confirm_risk_assessment",
        "list_requirements",
        "assemble_technical_file",
        "record_sbom",
    ):
        assert name in dispatch._FREE


# ---- plans -------------------------------------------------------------------


def test_free_covers_everything_except_the_legal_act():
    """The line, in one assertion.

    Free is the work — assessment, evidence, scanning, the Article 14 clocks.
    Paid is placing a product on the market: freezing the file, the
    declaration, sign-off, releases. `CONFORMITY` is the only paid feature.
    """
    assert entitlements.FREE.features == entitlements.ALL_FEATURES - {
        entitlements.CONFORMITY
    }
    assert not entitlements.FREE.covers(entitlements.CONFORMITY)
    for feature in (
        entitlements.EVIDENCE,
        entitlements.REASSESSMENT,
        entitlements.REPORTING,
        entitlements.ADVISORIES,
    ):
        assert entitlements.FREE.covers(feature)


def test_free_cannot_reach_the_ten_year_archive():
    """The one line with a hard technical reason behind it.

    `statutory_exports` is Object Lock, ten years, unreclaimable. Every tool
    that can write one must sit behind CONFORMITY, so a free account can never
    commit this service to a decade. Swept rather than spot-checked: a new tool
    that freezes something and forgets this fails here.
    """
    # Found by reading the handlers, not by listing them here. A hand-kept list
    # is exactly what this invariant cannot rely on: the tool that breaks it
    # will be one nobody thought to add. `record_build` was added to the module
    # that contains an archive writer and this is what proves it does not reach
    # one.
    import inspect

    # Registration is an import side-effect, so a sweep that does not ask for
    # the handlers iterates an empty dict and passes. Two tests in this file
    # already called this; the ones that did not were quietly vacuous when
    # the file was run on its own.
    dispatch._ensure_handlers_loaded()

    writers = set()
    for name, fn in {**dispatch._READ, **dispatch._MUTATING}.items():
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):  # pragma: no cover — builtins, partials
            continue
        if "statutory_export.record(" in src:
            writers.add(name)

    assert writers, "found no archive writers at all — has the sweep stopped working?"

    # `assemble_technical_file` is in _FREE because the gap report is free; its
    # freeze path checks CONFORMITY inside the handler instead.
    for tool in writers - {"assemble_technical_file"}:
        assert dispatch._REQUIRES.get(tool) == entitlements.CONFORMITY, (
            f"{tool} can write a ten-year archive entry but does not require "
            "CONFORMITY"
        )
    assert not entitlements.FREE.covers(entitlements.CONFORMITY)


def test_recording_a_build_is_free_and_placing_on_the_market_is_not():
    """Issue #44's real subject, and the plan boundary said in the domain model.

    "Free until you place it on the market" was a billing rule the model could
    not express: `record_release` welded recording that a version exists to
    declaring it placed on the market, so a free account could not name a build
    at all, and anyone who wanted to had to make a legal claim to do it.

    Splitting the acts puts the paid line exactly where the sentence says it is.
    """
    dispatch._ensure_handlers_loaded()
    assert "record_build" in dispatch._FREE
    assert dispatch._REQUIRES.get("place_on_market") == entitlements.CONFORMITY
    assert entitlements.FREE.covers(entitlements.EVIDENCE), (
        "recording a build is only worth having free if evidence can hang off it"
    )


def test_paid_plans_differ_only_in_limits():
    """The ladder sells capacity, not capability. Someone paying the smallest
    amount still gets every feature — the alternative is a compliance tool that
    withholds part of a legal obligation over the difference between two
    tiers."""
    table = entitlements.plans()
    for name in ("solo", "team", "portfolio", "founding", "internal"):
        assert table[name].features == entitlements.ALL_FEATURES


def test_limits_are_env_overridable(monkeypatch):
    monkeypatch.setenv("CRA_PLAN_TEAM_MAX_PRODUCTS", "7")
    assert entitlements.plans()["team"].max_products == 7


def test_a_nonsense_limit_is_ignored_not_obeyed(monkeypatch):
    monkeypatch.setenv("CRA_PLAN_TEAM_MAX_PRODUCTS", "lots")
    assert entitlements.plans()["team"].max_products == 3


def test_enforcement_is_off_by_default(monkeypatch):
    monkeypatch.delenv("CRA_ENTITLEMENTS_ENFORCED", raising=False)
    assert entitlements.enforced() is False


def test_shadow_mode_allows_everything(monkeypatch, free):
    """Blocking someone out of compliance work is not a thing to discover from
    a support email, so the gates ship logging rather than refusing."""
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "0")
    entitlements.require("u-1", entitlements.REPORTING, what="x")
    entitlements.require_room_for_member("u-1", current=99)


# ---- refusals ----------------------------------------------------------------


def test_a_refusal_denies_being_a_compliance_conclusion(free):
    with pytest.raises(entitlements.UpgradeRequired) as e:
        entitlements.require(
            "u-1", entitlements.CONFORMITY, what="sign_off would have run."
        )
    said = str(e.value).lower()
    assert "nothing about your product's compliance is implied" in said
    # And it says how to get out of it, because a dead end reads as a bug.
    assert "cra@skarp.app" in said


def test_a_refusal_carries_a_code_an_agent_can_branch_on():
    assert entitlements.UpgradeRequired.code == "upgrade_required"
    # It travels the same path as every other domain refusal.
    from cra.server.errors import TransitionError

    assert issubclass(entitlements.UpgradeRequired, TransitionError)


def test_nobody_is_charged_for_a_second_person(free):
    """Seats stopped being metered on 2026-08-09.

    An Article 14 clock runs for 24 hours, so a plan permitting exactly one
    login makes that person a single point of failure on a statutory deadline.
    Metering seats also put the boundary on hiring rather than on anything to
    do with compliance.
    """
    for plan in entitlements.plans().values():
        assert plan.max_members >= entitlements.UNLIMITED, plan.name
    entitlements.require_room_for_member("u-1", current=99)


def test_the_member_refusal_still_argues_for_attribution_if_a_cap_returns(monkeypatch):
    """`require_room_for_member` is dormant, not deleted. If a seat cap ever
    comes back the refusal has to keep arguing against sharing a token, because
    the wrong name in the audit trail defeats the product."""
    monkeypatch.setenv("CRA_PLAN_FREE_MAX_MEMBERS", "1")
    monkeypatch.setattr(entitlements, "plan_for", lambda _uid: entitlements.plans()["free"])
    with pytest.raises(entitlements.UpgradeRequired) as e:
        entitlements.require_room_for_member("u-1", current=1)
    assert "own name" in str(e.value)


def test_describe_names_the_ceiling_and_qualifies_it(free):
    out = entitlements.describe("u-1")
    assert out["name"] == "free"
    assert set(out["not_included"]) == {entitlements.CONFORMITY}
    assert "says nothing about whether your product meets" in out["note"]


def test_describe_reports_unlimited_as_null(monkeypatch):
    monkeypatch.setattr(
        entitlements, "plan_for", lambda _uid: entitlements.plans()["internal"]
    )
    out = entitlements.describe("u-1")
    # None, not a large number a client would render as a real limit.
    assert out["max_products"] is None
    assert out["not_included"] == []


# ---- failing open ------------------------------------------------------------


def test_an_unreadable_tier_allows_rather_than_refuses(monkeypatch):
    """If the tier cannot be read we do not know what plan this is — and "we
    could not check" must not resolve to "free". Refusing would lock somebody
    out of compliance work because a billing lookup failed, which is a far
    worse outcome than an unbilled call. Do not "fix" this to fail closed."""
    def boom():
        raise RuntimeError("DATABASE_URL is not set")

    monkeypatch.setattr(entitlements, "session_scope", boom)
    plan = entitlements.plan_for("u-1")
    assert plan.features == entitlements.ALL_FEATURES
    # And no gate raises on the way through.
    entitlements.require("u-1", entitlements.REPORTING, what="x")
    entitlements.require_room_for_product("u-1")


def test_a_missing_account_is_free_not_unlimited():
    """Distinct from the case above: the database answered, and the answer was
    that there is no such account."""
    class _Empty:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def get(self, *a):
            return None

    import contextlib

    with pytest.MonkeyPatch.context() as m:
        m.setattr(entitlements, "session_scope", lambda: _Empty())
        assert entitlements.plan_for("nobody").name == "free"


def test_granted_plans_never_lapse():
    """`GRANTS` is consulted here and in `billing.expire_stale_tier`, and the
    two used to be separate literals that disagreed — `founding` was missing
    from this one, so a grandfathered account with a stale `tier_until` read as
    free. One set, both callers."""
    from cra.server import billing

    assert entitlements.GRANTS == frozenset({"free", "founding", "internal"})
    assert billing.entitlements.GRANTS is entitlements.GRANTS
