"""Drafting an SRP report from recorded facts.

The property under test throughout is that **a draft always comes out**. The
24-hour clock is the whole reason this tool exists, and a drafter that refuses
to emit because a field is empty has failed exactly when it was needed.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import Evidence, ReportingObligation, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc


def _now():
    return datetime.now(UTC)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def product(owner):
    pid = str(uuid.uuid4())
    now = _now()
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Acme Gateway",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    return pid


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def incident(product, owner):
    return _call(
        "report_incident",
        product,
        owner,
        kind="severe_incident",
        description="Unauthorised access via the update channel",
    )["incident_id"]


# ---- the guarantee -----------------------------------------------------------


def test_a_draft_is_produced_even_with_nothing_on_file(product, owner, incident):
    """Bare product, bare incident, no submitter profile — still a draft.

    ENISA's posture on the early warning is "send what you know, then follow
    up"; this reproduces the worst case a user can be in at hour 1.
    """
    r = _call("draft_report", product, owner, incident_id=incident)
    assert r["ok"] is True
    assert r["markdown"].startswith("# CRA report — 24h")
    # Gaps are reported *alongside* the draft, never instead of it.
    assert {g["field_id"] for g in r["missing_required"]} == {"7"}
    assert "Name of manufacturer" in r["missing_required"][0]["label"]


def test_what_we_already_know_is_filled_in(product, owner, incident):
    r = _call("draft_report", product, owner, incident_id=incident)
    f = r["fields"]
    assert f["1"] == "Incident"
    assert f["2"] == "24h"
    assert f["8"] == "Acme Gateway"
    assert f["12"] == "Unauthorised access via the update channel"
    assert f["i13"] == "yes"


def test_platform_automated_fields_are_never_drafted(product, owner, incident):
    """`A` fields are computed by the SRP. Emitting our own value invites the
    user to reconcile two numbers and trust the wrong one."""
    r = _call("draft_report", product, owner, incident_id=incident)
    assert not (set(r["fields"]) & {"3", "4", "5", "6"})
    assert "Reporter" not in r["markdown"]


def test_required_gaps_are_visible_in_the_markdown_not_silently_dropped(
    product, owner, incident
):
    r = _call("draft_report", product, owner, incident_id=incident)
    assert "⚠️ REQUIRED — not yet supplied" in r["markdown"]


def test_the_draft_says_it_is_not_submitted(product, owner, incident):
    r = _call("draft_report", product, owner, incident_id=incident)
    assert "Not submitted" in r["markdown"]
    assert "does not submit" in r["next"]
    assert r["template_provisional"] is True
    assert "provisional" in r["note"]


# ---- supplying narrative -----------------------------------------------------


def test_caller_supplied_values_land_in_the_draft(product, owner, incident):
    r = _call(
        "draft_report",
        product,
        owner,
        incident_id=incident,
        stage="notification",
        values={"i17": "Credential stuffing against the signing service."},
    )
    assert r["fields"]["i17"] == "Credential stuffing against the signing service."
    assert "Credential stuffing" in r["markdown"]


def test_a_caller_supplied_value_beats_the_recorded_one(product, owner, incident):
    """The human who just lived through the incident knows more than the row."""
    r = _call(
        "draft_report",
        product,
        owner,
        incident_id=incident,
        values={"12": "Signing key compromise — update channel"},
    )
    assert r["fields"]["12"] == "Signing key compromise — update channel"


# ---- carry-forward, the reason the 72h clock is survivable -------------------


def test_narrative_typed_at_one_stage_survives_into_the_next(product, owner, incident):
    """The point of carry-forward: prose the record cannot hold.

    Fields we can re-derive (product name, title, submitter) are re-derived
    rather than carried — that is ENISA's "copied by default, *or updated*",
    and the record is the authority. What genuinely needs carrying is what a
    human typed once and must not have to type again at hour 70.
    """
    _call("set_submitter_profile", product, owner, legal_name="Acme Oy")
    typed = "Credential stuffing against the signing service."
    _call(
        "draft_report",
        product,
        owner,
        incident_id=incident,
        stage="notification",
        values={"i17": typed, "i14": "Update channel served a malicious build."},
    )

    final = _call("draft_report", product, owner, incident_id=incident, stage="final")
    assert set(final["carried_forward"]) >= {"i14", "i17"}
    assert final["fields"]["i17"] == typed
    assert "_(carried forward)_" in final["markdown"]


def test_every_carry_forward_field_is_populated_at_the_next_stage(
    product, owner, incident
):
    """What the user cares about is that nothing is blank second time round —
    whether it got there by carrying or by re-derivation is our business."""
    _call("set_submitter_profile", product, owner, legal_name="Acme Oy")
    first = _call("draft_report", product, owner, incident_id=incident)
    assert first["missing_required"] == []

    second = _call(
        "draft_report", product, owner, incident_id=incident, stage="notification"
    )
    for field_id in ("1", "7", "8", "12", "i13"):
        assert second["fields"][field_id] == first["fields"][field_id]


def test_carry_forward_skips_a_stage_that_was_never_drafted(product, owner, incident):
    """Missing the 24h draft makes you late, not stuck — the final report must
    still prefill from whatever exists."""
    _call("set_submitter_profile", product, owner, legal_name="Acme Oy")
    _call("draft_report", product, owner, incident_id=incident)  # 24h only

    final = _call("draft_report", product, owner, incident_id=incident, stage="final")
    assert final["ok"] is True
    assert final["fields"]["7"] == "Acme Oy"


def test_a_later_fact_overrides_a_carried_value(product, owner, incident):
    _call("set_submitter_profile", product, owner, legal_name="Acme Oy")
    _call("draft_report", product, owner, incident_id=incident)
    _call("set_submitter_profile", product, owner, legal_name="Acme Group Oyj")

    second = _call(
        "draft_report", product, owner, incident_id=incident, stage="notification"
    )
    assert second["fields"]["7"] == "Acme Group Oyj"
    assert "7" not in second["carried_forward"]


# ---- the vulnerability stream ------------------------------------------------


def test_an_exploited_vulnerability_drafts_on_the_vulnerability_fields(product, owner):
    vid = _call(
        "record_vulnerability",
        product,
        owner,
        summary="RCE in the config parser",
        identifier="CVE-2026-1234",
        actively_exploited=True,
        severity="9.8",
    )
    inc = vid["incident_id"]

    r = _call("draft_report", product, owner, incident_id=inc, stage="final")
    assert r["fields"]["1"] == "Vulnerability"
    assert r["fields"]["v13"] == "CVE-2026-1234"   # CVE id, not EUVD
    assert "v14" not in r["fields"]
    assert r["fields"]["v23"] == "9.8"
    # Incident-stream fields must not leak into a vulnerability report.
    assert not (set(r["fields"]) & {"i13", "i14"})


def test_the_corrective_measure_date_reaches_the_final_report(product, owner):
    v = _call(
        "record_vulnerability",
        product,
        owner,
        summary="rce",
        actively_exploited=True,
    )
    fix = datetime(2026, 10, 2, 16, 30, tzinfo=UTC)
    _call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        corrective_measure_available_at=fix.isoformat(),
        remediation_ref="https://acme.example/advisory/2026-01",
    )
    r = _call("draft_report", product, owner, incident_id=v["incident_id"], stage="final")
    assert r["fields"]["v21"].startswith("2026-10-02")
    assert r["fields"]["v26"] == "https://acme.example/advisory/2026-01"
    assert "v21" not in {g["field_id"] for g in r["missing_required"]}


def test_the_severity_definition_is_rendered_as_guidance_not_a_field(
    product, owner, incident
):
    r = _call("draft_report", product, owner, incident_id=incident, stage="final")
    assert "> 1) it negatively affects" in r["markdown"]
    assert "i22" not in r["fields"]


# ---- persistence -------------------------------------------------------------


def test_the_draft_is_stored_as_hashed_evidence_and_linked_to_its_obligation(
    product, owner, incident
):
    """Ten-year retention means "what did we actually tell the CSIRT" has to be
    answerable later, byte for byte."""
    r = _call("draft_report", product, owner, incident_id=incident)

    with session_scope() as s:
        ev = s.get(Evidence, r["evidence_id"])
        assert ev.kind == "report_draft"
        assert ev.sha256 and ev.size_bytes == len(ev.inline_body.encode())
        assert json.loads(ev.inline_body)["fields"]["8"] == "Acme Gateway"
        assert ev.added_by_user_id == owner

        ob = (
            s.query(ReportingObligation)
            .filter(
                ReportingObligation.incident_id == incident,
                ReportingObligation.stage == "early_warning",
            )
            .one()
        )
        assert ob.draft_evidence_id == r["evidence_id"]


def test_drafting_leaves_an_audit_row_naming_the_gaps(product, owner, incident):
    _call("draft_report", product, owner, incident_id=incident)
    with session_scope() as s:
        from cra.db import AuditEvent

        row = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "draft_report")
            .one()
        )
    assert row.accountable_user_id == owner
    assert row.payload["missing_required"] == ["7"]
    assert row.payload["template_version"] == "v1"


def test_an_unknown_template_version_is_refused(product, owner, incident):
    r = _call(
        "draft_report", product, owner, incident_id=incident, template_version="v99"
    )
    assert r["ok"] is False


def test_an_unknown_stage_lists_the_valid_ones(product, owner, incident):
    r = _call("draft_report", product, owner, incident_id=incident, stage="asap")
    assert r["ok"] is False
    assert "early_warning" in r["error"]


def test_another_users_incident_cannot_be_drafted(product, incident):
    stranger = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=stranger, email=f"{stranger}@example.test"))
    r = _call("draft_report", product, stranger, incident_id=incident)
    assert r["ok"] is False
    assert r["code"] == "not_found"


# ---- readiness ---------------------------------------------------------------


def test_readiness_names_the_things_that_cannot_be_done_in_24_hours(product, owner):
    r = _call("check_reporting_readiness", product, owner)
    assert r["ready"] is False
    items = {b["item"] for b in r["blockers"]}
    assert {"legal_name", "eu_login", "srp_registration", "member_states"} <= items
    # Every blocker has to say what to do about it, not just what's wrong.
    assert all(b["fix"] for b in r["blockers"])


def test_readiness_clears_once_the_profile_is_complete(product, owner):
    _call(
        "set_submitter_profile",
        product,
        owner,
        legal_name="Acme Oy",
        member_states_available=["FI", "SE"],
        eu_login_registered=True,
        srp_registered=True,
        security_contact="security@acme.example",
    )
    r = _call("check_reporting_readiness", product, owner)
    assert r["ready"] is True
    assert r["blockers"] == []
    assert r["summary"] == "Ready to file."


def test_the_profile_reaches_the_draft(product, owner, incident):
    _call(
        "set_submitter_profile",
        product,
        owner,
        legal_name="Acme Oy",
        member_states_available=["FI", "SE"],
    )
    r = _call("draft_report", product, owner, incident_id=incident)
    assert r["fields"]["7"] == "Acme Oy"
    assert r["fields"]["11"] == "FI, SE"
    assert r["missing_required"] == []


def test_setting_one_profile_field_leaves_the_others_alone(product, owner):
    _call("set_submitter_profile", product, owner, legal_name="Acme Oy")
    r = _call("set_submitter_profile", product, owner, security_contact="s@acme.example")
    assert r["submitter"]["legal_name"] == "Acme Oy"
    assert r["submitter"]["security_contact"] == "s@acme.example"
