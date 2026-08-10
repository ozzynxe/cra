"""The release gate, and evidence going stale behind it.

Annex I Pt I(2)(a) bars *making available on the market* a product with known
exploitable vulnerabilities. That is a claim about an instant, and this is the
instant: `record_release` weighs the advisory picture, freezes the answer as
evidence tied to that version, and makes it the release everything else is
measured against.

Two things are being guarded here and they pull in opposite directions.

The gate has to **refuse** when the record cannot support the claim — otherwise
it launders an absence of knowledge into a determination. And it has to have a
**way through**, because shipping with something outstanding is a decision a
manufacturer is entitled to make. What it must never do is let that decision be
made silently, which is why every override is kept on the determination and in
the audit trail.
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

from cra.advisories.feeds import KevCatalogue, OsvResult  # noqa: E402
from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import AdvisoryScan, AuditEvent, Evidence, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.schemas.enums import Lifecycle  # noqa: E402
from cra.server import advisories, store_pg  # noqa: E402

UTC = timezone.utc
SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"}],
    }
)
I2A = "annex_i.i.2.a"


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def product(owner, make_releasable):
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Acme Gateway",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    _call(
        "classify_product",
        pid,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Ordinary product with digital elements.",
    )
    _call("record_sbom", pid, owner, sbom=SBOM, source_ref="git:abc1234")
    make_releasable(_call, pid, owner)
    return pid


@pytest.fixture
def clean_scan(monkeypatch):
    """Feeds that match nothing: a genuinely clean product."""
    kev = KevCatalogue(ok=True)
    monkeypatch.setattr(
        advisories, "osv_query", lambda comps: OsvResult(ok=True, queried=len(list(comps)))
    )
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: kev)
    monkeypatch.setattr(advisories, "osv_advisory", lambda i: {})
    monkeypatch.setattr(
        advisories, "epss_catalogue", lambda **kw: type("C", (), {"ok": False, "model_version": None, "score_date": None})()
    )
    monkeypatch.setattr(advisories, "epss_scores", lambda ids: {})
    return kev


@pytest.fixture
def dirty_scan(monkeypatch, clean_scan):
    """One unresolved candidate, not exploited — the Annex I half, no clock."""

    def fake_osv(components):
        res = OsvResult(ok=True, queried=1)
        for c in components:
            res.by_component[c.key()] = ["GHSA-open"]
        return res

    monkeypatch.setattr(advisories, "osv_query", fake_osv)
    monkeypatch.setattr(
        advisories,
        "osv_advisory",
        lambda i: {"summary": "Prototype pollution", "aliases": ["CVE-2020-8203"]},
    )
    return clean_scan


def _release(product, owner, version="1.0.0", **kw):
    return _call("record_release", product, owner, version=version, **kw)


def _evidence(product, subject=f"requirement:{I2A}"):
    with session_scope() as s:
        return list(
            s.query(Evidence)
            .filter(Evidence.product_id == product, Evidence.subject_ref == subject)
            .all()
        )


# ---- the gate refuses ----------------------------------------------------------


def test_a_release_needs_a_scan_to_have_happened(product, owner):
    """'No open candidates' means nothing without 'and we looked'. Before this
    work a clean scan left no trace at all, so there was no way to tell an
    unscanned product from a clean one."""
    out = _release(product, owner)
    assert out["ok"] is False and out["code"] == "release_gate_blocked"
    assert [b["blocker"] for b in out["blockers"]] == ["never_scanned"]


def test_a_refusal_is_not_a_finding_about_the_product(product, owner):
    """The same discipline as `UpgradeRequired` and `not_a_clean_bill`: being
    unable to make a statement is not the opposite statement."""
    out = _release(product, owner)
    assert "does not currently support" in out["what_this_means"] or (
        "cannot currently support" in out["what_this_means"]
    )
    assert "Nothing here says your product has one" in out["what_this_means"]


def test_open_candidates_block_a_release(product, owner, dirty_scan):
    _call("scan_advisories", product, owner)
    out = _release(product, owner)
    assert out["ok"] is False
    blockers = {b["blocker"] for b in out["blockers"]}
    assert "open_candidates" in blockers
    assert "exploitability determination" in "".join(b["detail"] for b in out["blockers"])


def test_a_scan_that_could_not_reach_its_feeds_blocks(product, owner, clean_scan, monkeypatch):
    """A failed fetch and a clean product are the same zero and opposite
    meanings — the reason `sources_ok` is a column at all."""
    monkeypatch.setattr(
        advisories, "osv_query", lambda comps: OsvResult(ok=False, queried=0)
    )
    _call("scan_advisories", product, owner)
    out = _release(product, owner)
    assert out["ok"] is False
    assert "scan_incomplete" in {b["blocker"] for b in out["blockers"]}


def test_a_stale_scan_blocks(product, owner, clean_scan):
    _call("scan_advisories", product, owner)
    with session_scope() as s:
        row = s.query(AdvisoryScan).filter(AdvisoryScan.product_id == product).one()
        row.ran_at = datetime.now(UTC) - timedelta(days=30)

    out = _release(product, owner)
    assert out["ok"] is False
    assert "scan_too_old" in {b["blocker"] for b in out["blockers"]}


def test_every_blocker_is_reported_at_once(product, owner, dirty_scan, monkeypatch):
    """Being told about the candidates, fixing them, and only then hearing the
    scan is also too old is what teaches people to reach straight for the
    override."""
    monkeypatch.setattr(
        advisories, "osv_query", lambda comps: OsvResult(ok=False, queried=0)
    )
    _call("scan_advisories", product, owner)
    with session_scope() as s:
        s.query(AdvisoryScan).filter(AdvisoryScan.product_id == product).one().ran_at = (
            datetime.now(UTC) - timedelta(days=30)
        )
    out = _release(product, owner)
    assert len({b["blocker"] for b in out["blockers"]}) >= 2


# ---- and lets you through, loudly ----------------------------------------------


def test_a_clean_scan_lets_a_release_through(product, owner, clean_scan):
    _call("scan_advisories", product, owner)
    out = _release(product, owner, version="1.0.0")
    assert out["ok"] is True
    assert out["version"] == "1.0.0"
    assert out["lifecycle"] == Lifecycle.PLACED_ON_MARKET.value
    assert "accepted_despite" not in out


def test_one_rationale_waives_every_blocker(product, owner, dirty_scan):
    """One escape hatch rather than one per condition: four flags would let
    someone silence the checks individually until nothing was asserted."""
    _call("scan_advisories", product, owner)
    out = _release(
        product,
        owner,
        accepted_rationale="Not reachable in our build; fix ships in 1.0.1.",
    )
    assert out["ok"] is True
    assert "open_candidates" in out["accepted_despite"]
    assert "after an incident" in out["care"]


def test_the_override_is_written_into_the_determination_and_the_trail(
    product, owner, dirty_scan
):
    _call("scan_advisories", product, owner)
    reason = "Not reachable in our build; fix ships in 1.0.1."
    _release(product, owner, accepted_rationale=reason)

    body = json.loads(_evidence(product)[0].inline_body)
    assert body["accepted_rationale"] == reason
    assert body["open_candidates"] == 1
    assert [b["blocker"] for b in body["blockers_accepted"]] == ["open_candidates"]

    with session_scope() as s:
        ev = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "record_release")
            .one()
        )
        assert ev.payload["blockers_accepted"] == ["open_candidates"]
        assert ev.rationale == reason


def test_the_determination_is_tied_to_the_version_and_hashed(product, owner, clean_scan):
    _call("scan_advisories", product, owner)
    out = _release(product, owner, version="2.4.0")
    rows = _evidence(product)
    assert len(rows) == 1
    assert rows[0].applies_to_version == "2.4.0"
    assert rows[0].sha256 == out["determination_sha256"]


def test_the_determination_disclaims_what_it_is_not(product, owner, clean_scan):
    """A clean feed result is not a finding that the product has no exploitable
    vulnerabilities — only that these feeds knew of none."""
    _call("scan_advisories", product, owner)
    _release(product, owner)
    body = json.loads(_evidence(product)[0].inline_body)
    assert "not a statement that the product has no exploitable" in body["caveat"]


def test_it_says_a_shipped_release_does_not_become_non_conformant_later(
    product, owner, clean_scan
):
    """I(2)(a) is about the moment of placing on the market. What comes after
    is Art 13(8) and Annex I Pt II(2), and conflating them would have the tool
    imply an obligation the regulation does not create."""
    _call("scan_advisories", product, owner)
    out = _release(product, owner)
    assert "do not make this release" in out["not_retroactive"]


# ---- releases as the anchor -----------------------------------------------------


def test_a_version_cannot_be_recorded_twice(product, owner, clean_scan):
    _call("scan_advisories", product, owner)
    _release(product, owner, version="1.0.0")
    again = _release(product, owner, version="1.0.0")
    assert again["ok"] is False
    assert "already recorded" in again["error"]


def test_reaching_the_market_does_not_stale_the_risk_assessment(
    product, owner, clean_scan
):
    """The exemption, end to end. Recording a first release moves the lifecycle,
    and without the carve-out that would immediately demand a re-assessment at
    the moment of shipping.

    The assessment comes from the `product` fixture, which has to confirm one
    for the release gate to pass at all. Building a second one here would open
    version 2 with an undecided risk in it and fail to confirm — which is
    correct behaviour, and not what this test is about.
    """
    _call("scan_advisories", product, owner)
    assert _release(product, owner)["ok"] is True

    view = _call("get_risk_assessment", product, owner)["assessment"]
    assert view["stale"] is False, view.get("stale_reasons")


def test_list_releases_reports_the_position_at_each(product, owner, dirty_scan):
    _call("scan_advisories", product, owner)
    _release(product, owner, version="1.0.0", accepted_rationale="Shipping anyway.")

    out = _call("list_releases", product, owner)
    assert out["count"] == 1 and out["current"] == "1.0.0"
    entry = out["releases"][0]
    assert entry["i2a"]["open_candidates_at_release"] == 1
    assert entry["i2a"]["accepted_rationale"] == "Shipping anyway."


def test_no_releases_says_what_that_means_for_evidence(product, owner):
    out = _call("list_releases", product, owner)
    assert out["count"] == 0
    assert "unversioned rather than stale" in out["note"]


# ---- issue #30: confirming an exploited advisory used to clear the gate -------


def _exploited_candidate(product, owner, monkeypatch):
    """One CISA-KEV candidate, the shape journey 5 hit with log4j."""
    from cra.db import AdvisoryCandidate, session_scope as _scope

    with _scope() as db:
        row = AdvisoryCandidate(
            product_id=product,
            advisory_id="GHSA-jfh8-c2jp-5v3q",
            cve_ids=["CVE-2021-44228"],
            component_name="org.apache.logging.log4j/log4j-core",
            component_version="2.14.1",
            component_ecosystem="Maven",
            component_purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            summary="Remote code execution in log4j-core",
            exploited=True,
            kev_cve_id="CVE-2021-44228",
            status="open",
        )
        db.add(row)
        db.flush()
        return row.id


def test_confirming_an_exploited_advisory_does_not_clear_the_release_gate(
    product, owner, clean_scan, monkeypatch
):
    """The end-to-end run's finding, reproduced.

    Confirming a candidate closes it — correctly, the candidate queue is a queue
    of questions and confirming answers one. But the gate counted only
    candidates, so the way to clear an exploited advisory out of the gate was to
    agree that the product was affected. The run shipped a product with a
    confirmed, actively exploited log4j while an unfiled 24-hour Article 14
    clock ran, and the frozen determination recorded `exploited_open: 0`.
    """
    candidate_id = _exploited_candidate(product, owner, monkeypatch)
    _call("scan_advisories", product, owner)

    confirmed = _call(
        "confirm_advisory", product, owner,
        candidate_id=candidate_id,
        rationale="Checked the shipped build: the vulnerable class is on the classpath.",
    )
    assert confirmed["ok"] is True, confirmed

    out = _release(product, owner, version="1.0.0")
    assert out["ok"] is False, "a confirmed exploited vulnerability did not block the release"
    codes = {b["blocker"] for b in out["blockers"]}
    assert "exploited_vulnerability_unremediated" in codes, out["blockers"]


def test_recording_a_remedy_lets_the_release_through(product, owner, clean_scan, monkeypatch):
    """Unremediated means nothing recorded, not nothing done — the release that
    carries the fix is exactly the one that must not be blocked."""
    candidate_id = _exploited_candidate(product, owner, monkeypatch)
    _call("scan_advisories", product, owner)
    _call("confirm_advisory", product, owner, candidate_id=candidate_id,
          rationale="Vulnerable class is on the classpath in the shipped build.")

    vulns = _call("get_reporting_deadlines", product, owner)
    vid = None
    from cra.db import Vulnerability, session_scope as _scope
    with _scope() as db:
        vid = db.query(Vulnerability).filter(Vulnerability.product_id == product).first().id

    fixed = _call("update_vulnerability", product, owner, vulnerability_id=vid,
                  remediation_ref="git:9f2c1ab — bumped log4j-core to 2.17.1")
    assert fixed["ok"] is True, fixed

    out = _release(product, owner, version="1.0.0")
    codes = {b["blocker"] for b in out.get("blockers", [])}
    assert "exploited_vulnerability_unremediated" not in codes, out


def test_the_frozen_position_records_the_exploited_vulnerabilities(
    product, owner, clean_scan, monkeypatch
):
    """The half that made the original finding worse than a missing block.

    `list_releases` reported `exploited_open: 0` for a release made with a
    confirmed exploited vulnerability outstanding. That artefact is what an
    auditor reads, and it said the opposite of what was true.
    """
    candidate_id = _exploited_candidate(product, owner, monkeypatch)
    _call("scan_advisories", product, owner)
    _call("confirm_advisory", product, owner, candidate_id=candidate_id,
          rationale="Vulnerable class is on the classpath in the shipped build.")

    out = _release(product, owner, version="1.0.0",
                   accepted_rationale="Shipping: mitigations in place at the edge.")
    assert out["ok"] is True, out

    i2a = _call("list_releases", product, owner)["releases"][-1]["i2a"]
    assert i2a["exploited_vulnerabilities_at_release"] == 1, i2a
    assert i2a["exploited_vulnerability_ids"], i2a
    assert i2a["accepted_rationale"], "the override must be on the record"


# ---- an override is not a clean release, and must not read like one -------------
#
# Every field these assert on except `blockers_accepted` already existed, and an
# end-to-end run still shipped past three blockers on the word "fine" and
# reported it "exactly as I would a clean release". The qualification was
# present and *placed* where a summarising agent drops it: three keys below a
# `note` announcing the I(2)(a) position had been frozen as evidence.
#
# So these pin the headline rather than the presence of a warning somewhere in
# the payload. A response is read top-down and relayed from its summary.


def test_the_note_itself_says_the_release_was_an_override(product, owner, dirty_scan):
    """The one field a relaying agent always carries."""
    _call("scan_advisories", product, owner)
    out = _release(product, owner, accepted_rationale="fine")
    note = out["note"]
    assert "over 1 unresolved blocker" in note
    assert "open_candidates" in note
    assert "'fine'" in note


def test_the_note_does_not_describe_a_determination_that_was_not_made(
    product, owner, dirty_scan
):
    """The exact sentence the run relayed. What is frozen when blockers are
    waived is the waiver, and the note has to say which of the two it is."""
    _call("scan_advisories", product, owner)
    clean_phrasing = "with the Annex I Pt I(2)(a) position frozen as evidence against it"
    out = _release(product, owner, accepted_rationale="fine")
    assert clean_phrasing not in out["note"]
    assert "not a determination that the product ships without known" in out["note"]


def test_a_clean_release_still_reads_as_one(product, owner, clean_scan):
    """The other half: a gate that hedged a clean pass would be crying wolf,
    and the next override would read the same as this."""
    _call("scan_advisories", product, owner)
    out = _release(product, owner)
    assert "frozen as evidence against it" in out["note"]
    assert "unresolved blocker" not in out["note"]
    assert "accepted_despite" not in out and "blockers_accepted" not in out


def test_nothing_the_refusal_said_is_dropped_when_it_goes_through(
    product, owner, dirty_scan
):
    """`accepted_despite` carried codes only, so `requirements_unsettled` went
    across without the 22. The full objects the refusal returned come too."""
    _call("scan_advisories", product, owner)
    refused = _release(product, owner, version="1.0.0")
    out = _release(product, owner, version="1.0.1", accepted_rationale="fine")
    assert [b["blocker"] for b in out["blockers_accepted"]] == [
        b["blocker"] for b in refused["blockers"]
    ]
    assert all(b.get("detail") for b in out["blockers_accepted"])


def test_the_care_note_quotes_the_reason_back(product, owner, dirty_scan):
    """Surfaced, never judged — the same line as `thin_justifications` and the
    13(3) echo. Nothing measures the reason; it is shown to the person who has
    to stand behind it, at the moment it becomes permanent."""
    _call("scan_advisories", product, owner)
    out = _release(product, owner, accepted_rationale="fine")
    assert "'fine'" in out["care"]


def test_not_retroactive_does_not_excuse_what_is_outstanding_today(
    product, owner, dirty_scan
):
    """It is about what turns up *later*. Sitting unqualified above an accepted
    blocker it reads as cover for the blocker, which inverts Art 13(8)."""
    _call("scan_advisories", product, owner)
    out = _release(product, owner, accepted_rationale="fine")
    assert "does not soften the blocker" in out["not_retroactive"]


# ---- never looked is not none found ---------------------------------------------


def test_an_unscanned_release_reports_null_candidates_not_zero(product, owner):
    """`open_candidates: 0` beside `last_scan: null` is the single most
    quotable number in the response, and it reads as good news. The product has
    never been scanned: nought is true and reporting it is not.

    Same rule as EPSS, where a missing score is unscored and never low.
    """
    out = _release(product, owner, accepted_rationale="shipping regardless")
    assert out["ok"] is True
    assert out["open_candidates"] is None
    assert "never looked" in out["open_candidates_note"]


def test_the_frozen_determination_says_null_too(product, owner):
    """The response is read once; this is the artefact an authority reads in
    ten years."""
    _release(product, owner, accepted_rationale="shipping regardless")
    body = json.loads(_evidence(product)[0].inline_body)
    assert body["open_candidates"] is None
    assert body["scan"] is None


def test_a_scanned_release_still_reports_its_count(product, owner, dirty_scan):
    """Null must mean *never looked*, so a real zero and a real count both have
    to survive — otherwise the distinction the previous two tests draw is lost."""
    _call("scan_advisories", product, owner)
    out = _release(product, owner, accepted_rationale="fine")
    assert out["open_candidates"] == 1
    assert "open_candidates_note" not in out
