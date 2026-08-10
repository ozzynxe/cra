"""EPSS where it touches stored decisions.

`test_epss.py` covers the feed and the pure ordering. This covers the part with
consequences: a score written next to somebody's judgement, and the one case
where the model is allowed to disturb a judgement that was already made.

The rule the whole file exists to hold: **re-opening asks a question, it never
answers one.** A rise in predicted likelihood puts a dismissed candidate back in
front of a person. It does not mark anything exploitable, does not undo the VEX
justification, and does not write a determination. The worst outcome of getting
the threshold wrong is a prompt nobody needed.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.advisories.feeds import EpssScore, KevCatalogue, OsvResult  # noqa: E402
from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import AdvisoryCandidate, AuditEvent, session_scope  # noqa: E402
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
        from cra.db import User

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


class _Cat:
    ok = True
    model_version = "v2026.06.15"
    score_date = "2026-08-07T12:03:11Z"


@pytest.fixture
def feeds(monkeypatch):
    """Two components. Neither is on KEV, so nothing here has a clock — which
    is the point: this is the Annex I I(2)(a) half, not the Article 14 half.

    `scores` is mutable so a test can move the model between scans.
    """

    def fake_osv(components):
        res = OsvResult(ok=True, queried=len(list(components)))
        for c in components:
            if c.name == "requests":
                res.by_component[c.key()] = ["GHSA-scored"]
            elif c.name == "lodash":
                res.by_component[c.key()] = ["GHSA-unscored"]
        return res

    details = {
        "GHSA-scored": {"summary": "Parser flaw", "aliases": ["CVE-2020-8203"]},
        "GHSA-unscored": {"summary": "Prototype pollution", "aliases": ["CVE-2026-9999999"]},
    }
    kev = KevCatalogue(ok=True)
    scores = {"CVE-2020-8203": EpssScore("CVE-2020-8203", 0.05213, 0.91707)}
    cat = _Cat()

    monkeypatch.setattr(advisories, "osv_query", fake_osv)
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: kev)
    monkeypatch.setattr(advisories, "osv_advisory", lambda i: details.get(i))
    monkeypatch.setattr(advisories, "epss_catalogue", lambda **kw: cat)
    monkeypatch.setattr(advisories, "epss_scores", lambda ids: dict(scores))
    return {"scores": scores, "kev": kev, "cat": cat}


def _row(product, advisory_id="GHSA-scored"):
    with session_scope() as s:
        return (
            s.query(AdvisoryCandidate)
            .filter(
                AdvisoryCandidate.product_id == product,
                AdvisoryCandidate.advisory_id == advisory_id,
            )
            .one()
        )


def _candidates(product, owner, **kw):
    return _call("list_advisory_candidates", product, owner, **kw)["candidates"]


def _dismiss(product, owner, candidate_id, note="Not in the execute path in our build."):
    return _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=candidate_id,
        justification="vulnerable_code_not_in_execute_path",
        note=note,
    )


# ---- the score gets stored, with its provenance --------------------------------


def test_a_scan_stores_both_numbers_and_the_model_that_produced_them(product, owner, feeds):
    """Constraint 4. A score without `model_version` and `score_date` cannot be
    reproduced, and this one informed a compliance judgement."""
    out = _call("scan_advisories", product, owner)
    assert out["epss_ok"] is True
    assert out["epss_scored"] == 1 and out["epss_unscored"] == 1

    row = _row(product)
    assert row.epss_probability == pytest.approx(0.05213)
    assert row.epss_percentile == pytest.approx(0.91707)
    assert row.epss_model_version == "v2026.06.15"
    assert row.epss_score_date == "2026-08-07T12:03:11Z"


def test_an_unscored_candidate_says_unknown_rather_than_showing_a_number(
    product, owner, feeds
):
    """Constraint 2 as the agent sees it. `epss` is absent rather than zeroed,
    so a consumer that forgets to check cannot render '0%'."""
    _call("scan_advisories", product, owner)
    unscored = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-unscored")
    assert unscored["epss"] is None
    assert "not a low score" in unscored["epss_unscored_reason"]


def test_the_reading_shows_percentile_alongside_probability(product, owner, feeds):
    """The CVE-2020-8203 case: 5.2% reads as negligible on its own and is the
    92nd percentile. Both numbers, or the presentation misleads."""
    _call("scan_advisories", product, owner)
    scored = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")
    assert scored["epss"]["probability"] == pytest.approx(0.05213)
    assert scored["epss"]["percentile"] == pytest.approx(0.91707)
    assert "91.7%" in scored["epss"]["reading"]


def test_there_is_no_threshold_in_the_listing(product, owner, feeds):
    """Constraint 1. Every candidate is listed whatever it scores — a cutoff
    would be a compliance policy wearing a filter's clothes."""
    _call("scan_advisories", product, owner)
    out = _call("list_advisory_candidates", product, owner)
    assert out["count"] == 2
    assert "no threshold and no cutoff" in out["on_epss"]


def test_the_queue_puts_scored_above_unscored(product, owner, feeds):
    """NULLS LAST at the SQL layer, for the same reason as the pure sort."""
    _call("scan_advisories", product, owner)
    ids = [c["advisory_id"] for c in _candidates(product, owner)]
    assert ids == ["GHSA-scored", "GHSA-unscored"]


# ---- dismissal pins the judgement to a moment ----------------------------------


def test_dismissing_records_the_score_it_was_judged_against(product, owner, feeds):
    _call("scan_advisories", product, owner)
    cid = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")[
        "candidate_id"
    ]
    out = _dismiss(product, owner, cid)

    row = _row(product)
    assert row.epss_probability_at_decision == pytest.approx(0.05213)
    assert row.epss_percentile_at_decision == pytest.approx(0.91707)
    assert "5.2%" in out["epss_watch"] and "0.917" in out["epss_watch"]

    with session_scope() as s:
        ev = (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "dismiss_advisory")
            .one()
        )
        assert ev.payload["epss_probability_at_decision"] == pytest.approx(0.05213)
        assert ev.payload["epss_percentile_at_decision"] == pytest.approx(0.91707)


def test_constraint_3_epss_cannot_stand_in_for_a_justification(product, owner, feeds):
    """A dismissal needs a VEX category *and* a note about this product. A
    likelihood score is a statement about a CVE in general and can satisfy
    neither — structurally, because both remain required fields."""
    _call("scan_advisories", product, owner)
    cid = _candidates(product, owner)[0]["candidate_id"]

    no_note = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="vulnerable_code_not_in_execute_path",
        note="",
    )
    assert no_note["ok"] is False

    bad_category = _call(
        "dismiss_advisory",
        product,
        owner,
        candidate_id=cid,
        justification="epss_is_low",
        note="EPSS is only 0.05.",
    )
    assert bad_category["ok"] is False


# ---- the re-open --------------------------------------------------------------


def test_a_material_rise_reopens_and_explains_itself(product, owner, feeds):
    _call("scan_advisories", product, owner)
    cid = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")[
        "candidate_id"
    ]
    _dismiss(product, owner, cid)
    assert _row(product).status == "dismissed"

    feeds["scores"]["CVE-2020-8203"] = EpssScore("CVE-2020-8203", 0.71, 0.99)
    out = _call("scan_advisories", product, owner)
    assert out["reopened_on_epss_rise"] == 1

    row = _row(product)
    assert row.status == "open"
    # Re-notify: the sweeper's unnotified index is how a human hears about it.
    assert row.notified_at is None
    # The VEX determination is preserved, not erased — this is a question, not
    # a reversal.
    assert row.disposition == "vulnerable_code_not_in_execute_path"
    assert "71.0%" in row.disposition_note and "5.2%" in row.disposition_note
    assert "0.917" in row.disposition_note and "0.990" in row.disposition_note
    assert "not a finding that the product is affected" in row.disposition_note


def test_a_small_rise_leaves_a_settled_dismissal_alone(product, owner, feeds):
    """Re-raising something a person already ruled out trains them to ignore
    the alerts, which is the outcome that makes this feature worse than not
    having it."""
    _call("scan_advisories", product, owner)
    cid = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")[
        "candidate_id"
    ]
    _dismiss(product, owner, cid)

    feeds["scores"]["CVE-2020-8203"] = EpssScore("CVE-2020-8203", 0.06, 0.93)
    out = _call("scan_advisories", product, owner)
    assert out["reopened_on_epss_rise"] == 0
    assert _row(product).status == "dismissed"


def test_a_fall_never_reopens(product, owner, feeds):
    _call("scan_advisories", product, owner)
    cid = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")[
        "candidate_id"
    ]
    _dismiss(product, owner, cid)

    feeds["scores"]["CVE-2020-8203"] = EpssScore("CVE-2020-8203", 0.001, 0.10)
    assert _call("scan_advisories", product, owner)["reopened_on_epss_rise"] == 0
    assert _row(product).status == "dismissed"


def test_the_behaviour_can_be_switched_off_without_a_deploy(
    product, owner, feeds, monkeypatch
):
    """No probability can multiply by 999, so this disables re-opening."""
    monkeypatch.setenv("CRA_EPSS_REOPEN_FACTOR", "999")
    _call("scan_advisories", product, owner)
    cid = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")[
        "candidate_id"
    ]
    _dismiss(product, owner, cid)

    feeds["scores"]["CVE-2020-8203"] = EpssScore("CVE-2020-8203", 0.99, 1.0)
    assert _call("scan_advisories", product, owner)["reopened_on_epss_rise"] == 0
    assert _row(product).status == "dismissed"


def test_a_kev_listing_still_reopens_regardless_of_epss(product, owner, feeds):
    """The pre-existing path, unchanged. Observed exploitation is a stronger
    reason to look again than any prediction, and it must not have been
    displaced by the new one."""
    _call("scan_advisories", product, owner)
    cid = next(c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-scored")[
        "candidate_id"
    ]
    _dismiss(product, owner, cid)

    feeds["kev"].entries["CVE-2020-8203"] = {
        "cve_id": "CVE-2020-8203",
        "date_added": "2026-08-08",
    }
    out = _call("scan_advisories", product, owner)
    row = _row(product)
    assert row.status == "open" and row.exploited is True
    # Counted as a KEV re-open, not an EPSS one — they are different reasons
    # and the note has to say the right one.
    assert out["reopened_on_epss_rise"] == 0
    assert "CISA subsequently listed this as exploited" in row.disposition_note


def test_an_unscored_candidate_is_never_reopened_by_scoring(product, owner, feeds):
    """A CVE with no score has no rise to measure, and `None` must not be
    treated as 0.0 climbing to something."""
    _call("scan_advisories", product, owner)
    cid = next(
        c for c in _candidates(product, owner) if c["advisory_id"] == "GHSA-unscored"
    )["candidate_id"]
    _dismiss(product, owner, cid)

    out = _call("scan_advisories", product, owner)
    assert out["reopened_on_epss_rise"] == 0
    assert _row(product, "GHSA-unscored").status == "dismissed"


def test_a_scoring_outage_does_not_blank_a_stored_score(product, owner, feeds, monkeypatch):
    """A stale number beside a live decision is bad; erasing one because the
    feed was down is worse, because it looks like the CVE was never scored."""
    _call("scan_advisories", product, owner)
    assert _row(product).epss_percentile is not None

    monkeypatch.setattr(advisories, "epss_scores", lambda ids: {})
    monkeypatch.setattr(
        advisories, "epss_catalogue", lambda **kw: type("D", (), {"ok": False, "model_version": None, "score_date": None})()
    )
    out = _call("scan_advisories", product, owner)

    assert out["epss_ok"] is False
    # The finding is still here and still right, only unranked this round.
    assert out["findings"] == 2
    assert _row(product).epss_percentile == pytest.approx(0.91707)
