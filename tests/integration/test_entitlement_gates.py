"""The gates, against a real database and the real dispatcher.

The unit tests pin what a plan *is*. These pin what happens to somebody on one,
and the properties that matter are less about refusing than about refusing
cleanly:

  * a refused reassessment must leave the confirmed version untouched — a
    half-opened draft would make a frozen assessment look superseded by
    something that does not exist;
  * a free account must still reach a confirmed assessment and a gap report,
    or there is nothing to be free;
  * the gap report must say that its gaps mean "not tracked here". This service
    exists so an absence of knowledge never reads as knowledge of absence, and
    a paywall is the easiest place in the product to break that.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import Product, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import entitlements, store_pg  # noqa: E402

UTC = timezone.utc


@pytest.fixture(autouse=True)
def _enforced(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "1")


def _call(tool, product_id, actor_id, **args):
    # `tool`, not `name` — create_product takes a `name` argument of its own.
    return dispatcher.dispatch(tool, product_id, actor_id, args)


def _user(tier="free", until=None) -> str:
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test", tier=tier, tier_until=until))
    return uid


def _product(owner: str, name="Acme Gateway") -> str:
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name=name,
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    _call(
        "classify_product", pid, owner,
        product_class="default", in_scope=True,
        rationale="Ordinary product with digital elements.",
    )
    return pid


REQ = "annex_i.i.2.a"


def _confirm_assessment(pid: str, uid: str) -> dict:
    """One pass through the assessment, in the domain's own order."""
    _call(
        "start_risk_assessment", pid, uid,
        method="STRIDE",
        intended_purpose="An API gateway fronting internal services",
        foreseeable_misuse="Deployed on the public internet with no WAF",
        conditions_of_use="Customer-operated Kubernetes cluster",
        support_duration_note="Five years from GA",
        part_i_1_approach="Threat modelling each release against the accepted risks.",
        part_ii_approach="SBOM per build, daily scanning, CVD policy, Article 14 clocks here.",
    )
    _call(
        "propose_risks", pid, uid,
        basis="repository at HEAD plus the deployment topology",
        model="claude-opus-5",
        risks=[{
            "title": "Unauthenticated access to the admin API",
            "asset": "administrative control plane",
            "threat": "an unauthenticated caller reconfigures routing",
            "attack_vector": "admin listener bound to 0.0.0.0",
            "impact": "full traffic interception",
            "affects_requirements": [REQ],
        }],
    )
    _call(
        "decide_risk", pid, uid,
        risk_id="risk-001", decision="accept", treatment="mitigate",
        rationale="Real for our topology; mitigated by mTLS on the admin listener.",
    )
    return _call(
        "confirm_risk_assessment", pid, uid,
        rationale="Reviewed with the maintainers against the shipped topology.",
    )


def _assessment(pid: str, uid: str) -> dict:
    return _call("get_risk_assessment", pid, uid)["assessment"]


# ---- what an unpaid account reaches ------------------------------------------


def test_a_free_account_reaches_a_confirmed_assessment_and_a_gap_report():
    uid = _user()
    pid = _product(uid)

    assert _confirm_assessment(pid, uid)["ok"] is True
    assert _call("list_requirements", pid, uid)["ok"] is True

    report = _call("assemble_technical_file", pid, uid)
    assert report["ok"] is True
    assert report["missing_slots"]  # it is a gap report; that is the product


def test_the_gap_report_says_it_is_a_working_view_not_an_attested_one():
    """The note had to change when evidence moved onto the free plan.

    It used to say the gaps meant "not recorded here" rather than "not done",
    because a free account could not record evidence at all. That premise is
    now false and the sentence would have excused real gaps. What is still true
    on a plan without CONFORMITY is narrower: this is a working view, nobody
    has attested to it, and the gaps are real.
    """
    uid = _user()
    pid = _product(uid)
    _confirm_assessment(pid, uid)

    note = _call("assemble_technical_file", pid, uid)["coverage_note"]
    assert "freezing or signing" in note
    assert "real gaps" in note
    assert "compliance conclusion" in note
    assert "not tracking" not in note


def test_a_paid_account_gets_no_such_note():
    uid = _user(tier="solo")
    pid = _product(uid)
    _confirm_assessment(pid, uid)
    assert "coverage_note" not in _call("assemble_technical_file", pid, uid)


# ---- reassessment ------------------------------------------------------------


def test_a_free_account_may_reassess_as_the_product_changes():
    """Reassessment moved onto the free plan.

    Article 13(3) requires the assessment kept current across the support
    period, so charging for revision was charging for compliance maintenance on
    a product that may not even be on the market yet.
    """
    uid = _user()
    pid = _product(uid)
    _confirm_assessment(pid, uid)
    assert _assessment(pid, uid)["version"] == 1

    out = _call(
        "propose_risks", pid, uid,
        basis="a dependency bump noticed after the confirm",
        model="claude-opus-5",
        risks=[{"title": "Second thoughts", "affects_requirements": [REQ]}],
    )
    assert out["ok"] is True, out
    assert _assessment(pid, uid)["version"] == 2


def test_a_paid_account_may_reassess():
    uid = _user(tier="solo")
    pid = _product(uid)
    _confirm_assessment(pid, uid)
    out = _call(
        "propose_risks", pid, uid,
        basis="a new TLS library shipped this release",
        model="claude-opus-5",
        risks=[{"title": "New dependency added", "affects_requirements": [REQ]}],
    )
    assert out["ok"] is True
    assert _assessment(pid, uid)["version"] == 2


# ---- freezing ----------------------------------------------------------------


def test_freezing_the_technical_file_is_refused_on_free():
    uid = _user()
    pid = _product(uid)
    _confirm_assessment(pid, uid)
    out = _call("assemble_technical_file", pid, uid, finalize=True)
    assert out["ok"] is False
    assert out["code"] == "upgrade_required"


# ---- the gated modules -------------------------------------------------------


@pytest.mark.parametrize(
    "tool,args",
    [
        ("get_reporting_deadlines", {}),
        ("record_vulnerability", {"title": "x", "description": "y"}),
        ("check_reporting_readiness", {}),
        ("scan_advisories", {}),
        ("list_advisory_candidates", {}),
        ("update_requirement", {"req_id": REQ, "status": "met"}),
    ],
)
def test_the_work_is_free(tool, args):
    """All six of these refused on free until 2026-08-09.

    Evidence, scanning and the Article 14 clocks are the work of getting a
    product ready. The gate belongs at the legal act, not part-way through
    the preparation for it.
    """
    uid = _user()
    pid = _product(uid)
    out = _call(tool, pid, uid, **args)
    # `.get` — a successful envelope carries no `code` at all.
    assert out.get("code") != "upgrade_required", out


@pytest.mark.parametrize(
    "tool,args",
    [
        ("record_release", {"version": "1.0.0"}),
        ("set_support_period", {"end": "2036-01-01T00:00:00+00:00", "rationale": "x"}),
        ("generate_declaration_of_conformity", {}),
        ("generate_simplified_declaration", {"url": "https://example.com/doc"}),
        ("sign_off", {"signer_name": "A", "signer_role": "CTO", "statement": "x"}),
    ],
)
def test_the_legal_act_is_paid_and_says_so_branchably(tool, args):
    """The other half of the line. Every one of these can write a ten-year
    Object Lock entry, which is the only cost here that cannot be reclaimed."""
    uid = _user()
    pid = _product(uid)
    out = _call(tool, pid, uid, **args)
    assert out["ok"] is False
    assert out["code"] == "upgrade_required"
    assert out["plan"] == "free"
    assert out["feature"] == entitlements.CONFORMITY


def test_the_same_tools_work_on_a_paid_plan():
    uid = _user(tier="team")
    pid = _product(uid)
    assert _call("get_reporting_deadlines", pid, uid)["ok"] is True
    assert _call("list_advisory_candidates", pid, uid)["ok"] is True


# ---- caps --------------------------------------------------------------------


def test_the_product_cap_refuses_at_the_limit_not_past_it():
    uid = _user()  # free: one product
    _product(uid)
    out = _call("create_product", "", uid, name="Second thing")
    assert out["ok"] is False
    assert out["code"] == "upgrade_required"

    with session_scope() as s:
        owned = list(s.query(Product).filter(Product.owner_user_id == uid))
    assert len(owned) == 1


def test_a_team_plan_has_room_for_three():
    uid = _user(tier="team")
    for n in range(3):
        assert _call("create_product", "", uid, name=f"Thing {n}")["ok"] is True
    assert _call("create_product", "", uid, name="Fourth")["ok"] is False


def test_no_plan_charges_for_a_second_person():
    """Seats stopped being metered on 2026-08-09 — including on `solo`, which
    used to refuse here. A plan permitting one login makes that person a single
    point of failure on a 24-hour statutory clock."""
    for tier in ("free", "solo"):
        uid = _user(tier=tier)
        pid = _product(uid)
        other = _user()
        out = _call("add_member", pid, uid, email=f"m-{other[:8]}@example.test")
        assert out.get("code") != "upgrade_required", (tier, out)


def test_a_team_plan_may_add_members():
    uid = _user(tier="team")
    pid = _product(uid)
    assert _call("add_member", pid, uid, user_id=_user())["ok"] is True


# ---- expiry ------------------------------------------------------------------


def test_a_lapsed_paid_tier_reads_as_free():
    """Nothing has to run for a subscription to end. `tier_until` is the
    paid-through date and the plan is derived from it, the same way obligation
    state is derived rather than stored."""
    lapsed = _user(tier="team", until=datetime.now(UTC) - timedelta(days=1))
    assert entitlements.plan_for(lapsed).name == "free"

    live = _user(tier="team", until=datetime.now(UTC) + timedelta(days=1))
    assert entitlements.plan_for(live).name == "team"


def test_an_unknown_tier_reads_as_free_rather_than_crashing():
    weird = _user(tier="enterprise-plus-ultra")
    assert entitlements.plan_for(weird).name == "free"


def test_grandfathered_accounts_keep_everything():
    uid = _user(tier="founding")
    pid = _product(uid)
    _confirm_assessment(pid, uid)
    assert _call("assemble_technical_file", pid, uid, finalize=False)["ok"] is True
    assert _call("get_reporting_deadlines", pid, uid)["ok"] is True


# ---- shadow mode -------------------------------------------------------------


def test_shadow_mode_gates_nothing(monkeypatch):
    monkeypatch.setenv("CRA_ENTITLEMENTS_ENFORCED", "0")
    uid = _user()
    pid = _product(uid)
    assert _call("get_reporting_deadlines", pid, uid)["ok"] is True
    assert _call("create_product", "", uid, name="Second thing")["ok"] is True


# ---- the overview ------------------------------------------------------------


def test_the_overview_names_the_plan_before_a_wall_is_hit():
    uid = _user()
    plan = _call("cra_overview", "", uid)["plan"]
    assert plan["name"] == "free"
    assert plan["max_products"] == 1
    assert sorted(plan["not_included"]) == [entitlements.CONFORMITY]
    assert plan["enforced"] is True


# ---- the sweeper -------------------------------------------------------------


def test_the_daily_sweep_now_covers_free_products_too(monkeypatch):
    """Scanning moved onto the free plan, so the sweep no longer skips anyone.

    That was a deliberate decision rather than an oversight — sweeping every
    product was measured and found affordable. The skip machinery stays because
    the sweep must still report what it left out if a future plan ever excludes
    scanning — a sweep claiming to have covered everything while ignoring most
    of it is the reading this codebase exists to prevent.
    """
    from cra.server import advisory_sweeper

    free_owner = _user()
    _product(free_owner, name="Unpaid thing")
    paid_owner = _user(tier="team")
    _product(paid_owner, name="Paid thing")

    monkeypatch.setattr(advisory_sweeper.advisories, "scanning_enabled", lambda: True)
    seen: list[str] = []

    def fake_scan(pid):
        seen.append(pid)
        return {"scanned": False}

    monkeypatch.setattr(advisory_sweeper.advisories, "scan_product", fake_scan)

    out = advisory_sweeper.sweep_once(dry_run=True)
    assert out["skipped_unentitled"] == 0
    with session_scope() as s:
        free_products = [
            p.id for p in s.query(Product).filter(Product.owner_user_id == free_owner)
        ]
    assert set(free_products) <= set(seen), "a free product was skipped"
