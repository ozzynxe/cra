"""From a feed match to a statutory clock.

This is the only path in the system where the *tool* creates awareness rather
than recording it, and awareness is what Article 14's deadlines run from. So the
tests here are mostly about restraint: what detection is not allowed to do on
its own, and where the clock is anchored when a person finally agrees.

The feeds are stubbed. What matters is the state machine around them, not
whether OSV was up.
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
from cra.db import AdvisoryCandidate, AuditEvent, Incident, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import advisories, store_pg  # noqa: E402

UTC = timezone.utc
SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "requests", "purl": "pkg:pypi/requests@2.31.0"},
            {"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"},
        ],
    }
)


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def product(owner):
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
    return pid


@pytest.fixture
def feeds(monkeypatch):
    """Stub OSV and KEV. `requests` is exploited, `lodash` merely vulnerable."""

    def fake_osv(components):
        res = OsvResult(ok=True, queried=len(list(components)))
        for c in components:
            if c.name == "requests":
                res.by_component[c.key()] = ["GHSA-exploited"]
            elif c.name == "lodash":
                res.by_component[c.key()] = ["GHSA-quiet"]
        return res

    details = {
        "GHSA-exploited": {"summary": "RCE in the parser", "aliases": ["CVE-2026-1111"]},
        "GHSA-quiet": {"summary": "Prototype pollution", "aliases": ["CVE-2026-2222"]},
    }
    kev = KevCatalogue(ok=True)
    kev.entries["CVE-2026-1111"] = {
        "cve_id": "CVE-2026-1111",
        "date_added": "2026-08-01",
        "ransomware": "Known",
    }

    monkeypatch.setattr(advisories, "osv_query", fake_osv)
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: kev)
    monkeypatch.setattr(advisories, "osv_advisory", lambda i: details.get(i))
    return kev


def _candidates(product, owner, **kw):
    return _call("list_advisory_candidates", product, owner, **kw)["candidates"]


# ---- detection ---------------------------------------------------------------


def test_a_scan_raises_candidates_not_vulnerabilities(product, owner, feeds):
    """The central restraint. Detection must not create a record that starts a
    clock, because a version match is not a finding of fact."""
    r = _call("scan_advisories", product, owner)
    assert r["ok"] is True and r["scanned"] is True
    assert r["findings"] == 2 and r["exploited"] == 1

    # No vulnerability, and above all no incident.
    assert _call("get_reporting_deadlines", product, owner)["counts"]["open"] == 0
    with session_scope() as s:
        assert s.query(Incident).filter(Incident.product_id == product).count() == 0


def test_the_exploited_candidate_carries_its_kev_provenance(product, owner, feeds):
    _call("scan_advisories", product, owner)
    exploited = _candidates(product, owner, filter="exploited")
    assert len(exploited) == 1
    c = exploited[0]
    assert c["component"] == "requests@2.31.0"
    assert c["kev_cve_id"] == "CVE-2026-1111"
    assert c["kev_date_added"] == "2026-08-01"


def test_rescanning_does_not_duplicate(product, owner, feeds):
    first = _call("scan_advisories", product, owner)
    second = _call("scan_advisories", product, owner)
    assert first["new_candidates"] == 2
    assert second["new_candidates"] == 0
    assert len(_candidates(product, owner, filter="all")) == 2


def test_a_product_with_no_sbom_says_so_rather_than_reporting_clean(product, owner, feeds):
    pid = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="No SBOM",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    r = _call("scan_advisories", pid, owner)
    assert r["scanned"] is False
    assert "No SBOM recorded" in r["why"]


def test_an_unreachable_feed_is_not_a_clean_scan(product, owner, monkeypatch):
    monkeypatch.setattr(
        advisories, "osv_query", lambda comps: OsvResult(ok=False)
    )
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: KevCatalogue(ok=True))
    r = _call("scan_advisories", product, owner)
    assert r["sources_ok"] is False
    assert "not a clean result" in r["summary"]


def test_an_empty_result_never_reads_as_a_clean_bill_of_health(product, owner, feeds):
    out = _call("list_advisory_candidates", product, owner, filter="confirmed")
    assert out["count"] == 0
    # "exploitable", not "exploited" — deliberately the broader word. Art 3(41)
    # is what Annex I Pt I(2)(a) bars shipping; Art 3(42) is what Article 14
    # reports on. Claiming no *exploited* vulnerabilities would be the narrower
    # and easier statement, and not the one that matters at release.
    assert "no exploitable vulnerabilities" in out["not_a_clean_bill"]


def test_the_candidate_list_spells_out_both_duties(product, owner, feeds):
    """`actively_exploited` is not the line between important and unimportant.
    It separates the Article 14 reporting duty from the Annex I Pt I(2)(a)
    placing-on-the-market bar, and the second one covers the larger set."""
    _call("scan_advisories", product, owner)
    out = _call("list_advisory_candidates", product, owner)
    duties = out["two_duties"]
    assert "3(42)" in duties and "24-hour" in duties
    assert "3(41)" in duties and "I(2)(a)" in duties
    assert "drops the other" in duties


# ---- confirming --------------------------------------------------------------


def _exploited_id(product, owner):
    _call("scan_advisories", product, owner)
    return _candidates(product, owner, filter="exploited")[0]["candidate_id"]


def test_confirming_without_saying_what_you_checked_is_refused(product, owner, feeds):
    cid = _exploited_id(product, owner)
    r = _call("confirm_advisory", product, owner, candidate_id=cid, rationale="")
    assert r["ok"] is False and "rationale is required" in r["error"]


def test_confirming_an_exploited_candidate_starts_the_clocks(product, owner, feeds):
    cid = _exploited_id(product, owner)
    r = _call(
        "confirm_advisory",
        product,
        owner,
        candidate_id=cid,
        rationale="Checked the shipped wheel; the affected parser is reachable.",
    )
    assert r["ok"] is True
    assert r["actively_exploited"] is True
    assert {d["stage"] for d in r["deadlines"]} == {"early_warning", "notification"}

    with session_scope() as s:
        assert s.query(Incident).filter(Incident.product_id == product).count() == 1


def test_awareness_is_anchored_on_when_the_tool_told_you(product, owner, feeds):
    """Not on when the user got round to confirming. The notification is the
    earliest defensible answer to "when did you know", and anchoring later
    understates how long the clock has been running."""
    cid = _exploited_id(product, owner)
    told_at = datetime.now(UTC) - timedelta(hours=20)
    with session_scope() as s:
        s.get(AdvisoryCandidate, cid).notified_at = told_at

    r = _call(
        "confirm_advisory",
        product,
        owner,
        candidate_id=cid,
        rationale="Confirmed against the shipped artifact.",
    )
    early = next(d for d in r["deadlines"] if d["stage"] == "early_warning")
    # 24h from being told, 20h ago — about four hours left, not a fresh 24.
    assert 3.0 < early["hours_remaining"] < 5.0
    assert "when this service notified you" in r["awareness_note"]


def test_a_confirmed_candidate_links_to_its_vulnerability(product, owner, feeds):
    cid = _exploited_id(product, owner)
    r = _call(
        "confirm_advisory", product, owner, candidate_id=cid, rationale="Affected."
    )
    with session_scope() as s:
        row = s.get(AdvisoryCandidate, cid)
    assert row.status == "confirmed"
    assert row.vulnerability_id == r["vulnerability_id"]


def test_confirming_twice_is_idempotent(product, owner, feeds):
    cid = _exploited_id(product, owner)
    _call("confirm_advisory", product, owner, candidate_id=cid, rationale="Affected.")
    again = _call(
        "confirm_advisory", product, owner, candidate_id=cid, rationale="Affected."
    )
    assert again["already_confirmed"] is True


# ---- dismissing --------------------------------------------------------------


def test_a_dismissal_needs_a_standard_justification_and_a_reason(product, owner, feeds):
    cid = _exploited_id(product, owner)
    bad = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="because",
        note="x",
    )
    assert bad["ok"] is False and "VEX" in bad["error"]

    no_note = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="component_not_present",
        note="  ",
    )
    assert no_note["ok"] is False and "note is required" in no_note["error"]


def test_a_dismissal_is_recorded_as_evidence_not_as_an_absence(product, owner, feeds):
    cid = _exploited_id(product, owner)
    r = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="vulnerable_code_not_in_execute_path",
        note="We ship the library but never call the affected parser.",
    )
    assert r["ok"] is True
    assert "Annex I Pt II(2)" in r["evidence_note"]
    # Dismissing something CISA lists as exploited gets an extra word.
    assert "care" in r

    with session_scope() as s:
        audit = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "dismiss_advisory")
            .one()
        )
    # #46: `agent`. Dismissing a KEV-listed advisory is the sharpest place
    # the trail must not overstate what it saw.
    assert audit.actor_kind == "agent"
    assert audit.payload["justification"] == "vulnerable_code_not_in_execute_path"
    assert audit.payload["was_actively_exploited"] is True


def test_a_dismissal_survives_the_next_scan(product, owner, feeds):
    """Re-raising what someone already ruled out trains them to ignore the
    alerts, which is worse than not alerting at all."""
    cid = _exploited_id(product, owner)
    _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="component_not_present",
        note="Not in the artifact we ship.",
    )
    _call("scan_advisories", product, owner)
    assert _candidates(product, owner, filter="exploited") == []
    assert len(_candidates(product, owner, filter="dismissed")) == 1


def test_newly_exploited_reopens_a_dismissed_candidate(product, owner, feeds, monkeypatch):
    """A dismissal is a judgement made on what was known. CISA subsequently
    listing the advisory as exploited is new information, not noise."""
    _call("scan_advisories", product, owner)
    quiet = next(
        c for c in _candidates(product, owner) if c["component"].startswith("lodash")
    )
    _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=quiet["candidate_id"],
        justification="vulnerable_code_not_in_execute_path",
        note="Not reachable today.",
    )

    feeds.entries["CVE-2026-2222"] = {
        "cve_id": "CVE-2026-2222",
        "date_added": "2026-08-06",
        "ransomware": "Unknown",
    }
    r = _call("scan_advisories", product, owner)
    assert r["reopened_or_updated"] >= 1

    with session_scope() as s:
        row = s.get(AdvisoryCandidate, quiet["candidate_id"])
    assert row.status == "open"
    assert row.exploited is True
    assert row.notified_at is None  # so the sweeper tells someone
    assert "re-opened" in row.disposition_note


def test_a_confirmed_candidate_cannot_then_be_dismissed(product, owner, feeds):
    cid = _exploited_id(product, owner)
    _call("confirm_advisory", product, owner, candidate_id=cid, rationale="Affected.")
    r = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="false_positive",
        note="Changed my mind.",
    )
    assert r["ok"] is False and "already confirmed" in r["error"]


def test_a_non_member_sees_nothing(product, owner, feeds):
    _call("scan_advisories", product, owner)
    stranger = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=stranger, email=f"{stranger}@example.test"))
    r = _call("list_advisory_candidates", product, stranger)
    assert r["ok"] is False


# ---- values from the real world, not convenient ones -------------------------


def test_a_cvss_vector_fits_in_severity(product, owner, monkeypatch):
    """OSV puts a CVSS *vector* in `severity.score`, not a number. The first
    production scan against a real SBOM failed inserting one: the column was
    String(32) and a v3.1 vector is 44 characters, a v4.0 vector 63."""
    V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

    def fake_osv(components):
        res = OsvResult(ok=True, queried=len(list(components)))
        for c in components:
            if c.name == "requests":
                res.by_component[c.key()] = ["GHSA-vector"]
        return res

    monkeypatch.setattr(advisories, "osv_query", fake_osv)
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: KevCatalogue(ok=True))
    monkeypatch.setattr(
        advisories,
        "osv_advisory",
        lambda i: {"summary": "x", "severity": [{"type": "CVSS_V4", "score": V4}]},
    )

    r = _call("scan_advisories", product, owner)
    assert r["ok"] is True and r["new_candidates"] == 1
    assert _candidates(product, owner)[0]["severity"] == V4


@pytest.mark.parametrize("justification", sorted(advisories.VEX_JUSTIFICATIONS))
def test_every_vex_justification_can_actually_be_stored(
    product, owner, feeds, justification
):
    """Parametrised over the whole vocabulary rather than a convenient member.

    `vulnerable_code_cannot_be_controlled_by_adversary` is 49 characters and the
    column was String(48) — a closed vocabulary defined in this repo that did
    not fit a column defined in this repo. The earlier tests all used shorter
    justifications, so nothing failed until real use.
    """
    cid = _exploited_id(product, owner)
    r = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification=justification,
        note="Checked against the shipped artifact.",
    )
    assert r["ok"] is True, r.get("error")
    assert r["candidate"]["disposition"] == justification


# ---- the one door between a candidate and a record -----------------------------


def test_confirming_says_what_was_asserted_and_on_what(product, owner, feeds):
    """An end-to-end run was refused for an empty rationale, answered "the
    scanner found it", and was accepted.

    The refusal one call earlier states the rule in so many words — a feed match
    is not the check — and then the sentence saying the check *was* a feed match
    went through. What ended on the record was a human determination that the
    product is affected, an open incident and a 24-hour clock, with nothing in
    the response marking it apart from a determination somebody made.

    Not refused. No mechanical test reads a sentence, and a length rule would
    teach padding — the line already taken for Annex I justifications and the
    Article 13(3) statements. What changes is that the assertion and what it
    rests on arrive together, at the moment it becomes a legal deadline.
    """
    cid = _exploited_id(product, owner)
    out = _call("confirm_advisory", product, owner,
                candidate_id=cid, rationale="the scanner found it")
    assert out["ok"] is True
    said = out["recorded_determination"]
    assert "'the scanner found it'" in said
    assert "human determination" in said
    assert "A feed match is not that determination" in said
    assert "review_this_reason" in out


def test_a_reason_of_substance_is_not_flagged(product, owner, feeds):
    """The surfacing has to be quiet when there is something to read, or it is
    noise and gets ignored."""
    cid = _exploited_id(product, owner)
    out = _call(
        "confirm_advisory", product, owner, candidate_id=cid,
        rationale=(
            "We ship 2.14.1 in the gateway image and the JNDI lookup path is "
            "reachable from the request logger, confirmed against the running "
            "container."
        ),
    )
    assert out["ok"] is True
    assert "review_this_reason" not in out
    assert "recorded_determination" in out
