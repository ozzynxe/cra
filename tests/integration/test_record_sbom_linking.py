"""`record_sbom` and the requirement it is supposed to satisfy — issue #20.

Recording an SBOM is the one thing Annex I Pt II(1) asks for by name, and doing
it successfully used to leave the requirement still reading as a gap. The
evidence row was written, and `_slot_view` found it through `by_subject`, but
the id was never linked into the blob — so `_is_gap`, which tests
`item.evidence_ids`, kept saying no. `list_requirements` and
`assemble_technical_file` disagreed about the same requirement, and only one of
them was right.

Underneath that was a transaction boundary: the insert and its audit row went
through a bare `session_scope` with no state write at all. Nothing was lost
only because there was nothing to lose. The moment the blob link was added,
those two writes had to become one transaction — which is what `mutate` is for
and what the last test here proves against a real Postgres.
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

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import AuditEvent, Evidence, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import advisories, store_pg  # noqa: E402

UTC = timezone.utc
REQ = "annex_i.ii.1"
SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"}],
    }
)


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


def _place(product, owner, version="1.0.0", **kw):
    """`record_build` then `place_on_market` — the two acts the one call did.

    Split on 2026-08-10. Recording that a build exists and declaring it placed
    on the market assert different things, and only the second is a legal
    claim; tests that mean "this version shipped" have to say both.
    """
    build_kw = {
        k: kw.pop(k) for k in ("source_ref", "notes", "built_at") if k in kw
    }
    built = _call("record_build", product, owner, version=version, **build_kw)
    assert built["ok"] is True, built
    return _call("place_on_market", product, owner, version=version, **kw)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"{uid}@example.test"))
    return uid


@pytest.fixture
def bare_product(owner):
    """Classified nowhere — so there is no Annex I checklist yet."""
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
    return pid


@pytest.fixture
def product(bare_product, owner, make_releasable):
    _call(
        "classify_product",
        bare_product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="Ordinary product with digital elements.",
    )
    make_releasable(_call, bare_product, owner)
    return bare_product


def _requirement(product, owner, req=REQ):
    out = _call("list_requirements", product, owner, verbose=True)
    return next(r for r in out["requirements"] if r["req_id"] == req), out


def _slot_coverage(product, owner):
    tf = _call("assemble_technical_file", product, owner)
    return next(
        s["requirement_coverage"] for s in tf["slots"] if "requirement_coverage" in s
    )


# ---- the bug ---------------------------------------------------------------------


def test_recording_an_sbom_links_it_to_the_requirement(product, owner):
    # A delta, not an absolute. `make_releasable` now settles the
    # unconditional requirements with evidence — Annex I Pt II(1) among
    # them — so "starts at zero" stopped being true for a reason that has
    # nothing to do with what this test is about.
    before, _ = _requirement(product, owner)

    out = _call("record_sbom", product, owner, sbom=SBOM, source_ref="git:abc1234")
    assert out["ok"] is True

    row, _ = _requirement(product, owner)
    assert row["evidence_count"] == before["evidence_count"] + 1
    assert out["evidence_id"] in row["evidence_ids"]


def test_the_requirement_stops_reading_as_a_gap(product, owner):
    """Issue #20's 'Done when'. Before the fix this stayed in `gaps` forever,
    which meant the one requirement the tool can genuinely satisfy end to end
    reported as unmet."""
    _call("record_sbom", product, owner, sbom=SBOM, source_ref="git:abc1234")
    _call(
        "update_requirement",
        product,
        owner,
        req_id=REQ,
        applicability="applicable",
        status="verified",
        implementation_note="SBOM recorded and scanned.",
    )
    _, listing = _requirement(product, owner)
    assert REQ not in [
        r["req_id"] for r in _call("list_requirements", product, owner, filter="gaps")["requirements"]
    ]


def test_the_checklist_and_the_technical_file_now_agree(product, owner):
    """They read the same evidence by different routes — `_is_gap` off the blob,
    `_slot_view` off `by_subject`. Disagreeing about one requirement is how a
    gap report and a checklist tell a user two different things."""
    _call("record_sbom", product, owner, sbom=SBOM, source_ref="git:abc1234")
    _call(
        "update_requirement",
        product,
        owner,
        req_id=REQ,
        applicability="applicable",
        status="verified",
    )
    gaps_from_listing = {
        r["req_id"]
        for r in _call("list_requirements", product, owner, filter="gaps")["requirements"]
    }
    assert (REQ in gaps_from_listing) == (REQ in _slot_coverage(product, owner)["gaps"])
    assert REQ not in gaps_from_listing


def test_re_recording_does_not_duplicate_the_link(product, owner):
    """SBOMs are re-recorded whenever the dependency set changes, which the
    tool's own note tells people to do."""
    before, _ = _requirement(product, owner)
    first = _call("record_sbom", product, owner, sbom=SBOM, source_ref="git:aaa")
    second = _call("record_sbom", product, owner, sbom=SBOM + " ", source_ref="git:bbb")

    row, _ = _requirement(product, owner)
    assert row["evidence_count"] == before["evidence_count"] + 2
    assert len(set(row["evidence_ids"])) == before["evidence_count"] + 2
    # A subset: the fixture settles this requirement with its own evidence, so
    # the link list is not only the two SBOMs. Both are present, both distinct,
    # and the counts above are what prove nothing was duplicated.
    assert {first["evidence_id"], second["evidence_id"]} <= set(row["evidence_ids"])
    assert first["evidence_id"] != second["evidence_id"]


# ---- the version it describes ------------------------------------------------------


@pytest.fixture
def shipped(product, owner, monkeypatch):
    """A product on 1.0.0, with feeds that match nothing."""
    from cra.advisories.feeds import KevCatalogue, OsvResult

    monkeypatch.setattr(
        advisories, "osv_query", lambda comps: OsvResult(ok=True, queried=len(list(comps)))
    )
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: KevCatalogue(ok=True))
    monkeypatch.setattr(advisories, "osv_advisory", lambda i: {})
    monkeypatch.setattr(
        advisories,
        "epss_catalogue",
        lambda **kw: type("C", (), {"ok": False, "model_version": None, "score_date": None})(),
    )
    monkeypatch.setattr(advisories, "epss_scores", lambda ids: {})
    _call("record_sbom", product, owner, sbom=SBOM, source_ref="git:seed")
    _call("scan_advisories", product, owner)
    assert _place( product, owner, version="1.0.0")["ok"] is True
    return product


def test_an_sbom_ties_to_the_current_release_by_default(shipped, owner):
    out = _call("record_sbom", shipped, owner, sbom=SBOM, source_ref="git:ccc")
    assert out["applies_to_version"] == "1.0.0"


def test_a_version_naming_a_real_release_wins_over_the_default(shipped, owner):
    _call("scan_advisories", shipped, owner)
    _place( shipped, owner, version="2.0.0")
    out = _call(
        "record_sbom", shipped, owner, sbom=SBOM, source_ref="git:ddd", version="1.0.0"
    )
    assert out["applies_to_version"] == "1.0.0", "an explicit real release must win"


def test_a_version_that_is_not_yet_a_release_is_kept_as_given(shipped, owner):
    """An unreleased label is taken at face value, and this test used to assert
    the opposite while its own docstring argued for this.

    It said that tagging an SBOM built for 2.0.0 as evidence for 1.0.0 "would be
    a false claim about which build it describes" — and then asserted exactly
    that, because an unknown version fell back to the latest existing release.

    Recording the bill of materials for the build you are about to ship, before
    it is a release, is the ordinary order of work. The fallback also made the
    Annex I Pt I(2)(a) gate unclearable: releasing 2.0.0 was refused because the
    scan covered 1.0.0, and re-recording the SBOM as 2.0.0 filed it as 1.0.0
    again. `record_build` stores versions verbatim and never parses them, so
    there is nothing to validate a label against in any case.
    """
    out = _call(
        "record_sbom",
        shipped,
        owner,
        sbom=SBOM,
        source_ref="git:eee",
        version="2.0.0-rc1",
    )
    assert out["applies_to_version"] == "2.0.0-rc1"
    with session_scope() as s:
        row = s.query(Evidence).filter(Evidence.id == out["evidence_id"]).one()
        assert "2.0.0-rc1" in row.title


# ---- no checklist, and no crash ------------------------------------------------------


def test_an_sbom_with_no_checklist_is_stored_and_says_so(bare_product, owner):
    """`record_sbom` does not require classification, so a product can
    legitimately have nowhere to link. Refusing a valid upload over a
    bookkeeping detail would be the wrong trade."""
    out = _call("record_sbom", bare_product, owner, sbom=SBOM, source_ref="git:abc")
    assert out["ok"] is True
    assert "classify_product(in_scope=true)" in out["not_linked"]

    with session_scope() as s:
        assert (
            s.query(Evidence).filter(Evidence.product_id == bare_product).count() == 1
        )


# ---- one transaction ------------------------------------------------------------------


def test_the_evidence_and_its_audit_row_commit_together(product, owner, monkeypatch):
    """The boundary, now that it spans three writes instead of two.

    Honest about what this does and does not prove: the old bare
    `session_scope` already made the evidence row and its audit row atomic, so
    this test passes against the code before the fix too. What changed is that
    the blob link joined them, and `mutate` is what keeps all three together.

    It is here as a regression guard on the widened boundary rather than as
    proof of the fix — under the CRA the trail is the deliverable, and a state
    change that cannot be evidenced must not survive. The eight tests above are
    the ones that fail without the fix.
    """
    from cra.server import audit as audit_mod

    def boom(*a, **kw):
        raise RuntimeError("audit is down")

    # A baseline rather than zero: the fixture confirms a risk assessment,
    # which freezes it into `evidence`, so an absolute count would be asserting
    # something about the fixture instead of about the rollback.
    with session_scope() as s:
        before = s.query(Evidence).filter(Evidence.product_id == product).count()
    before_link, _ = _requirement(product, owner)

    monkeypatch.setattr(audit_mod, "record", boom)

    out = _call("record_sbom", product, owner, sbom=SBOM, source_ref="git:abc1234")
    assert out["ok"] is False

    with session_scope() as s:
        assert s.query(Evidence).filter(Evidence.product_id == product).count() == before
        assert (
            s.query(AuditEvent)
            .filter(AuditEvent.product_id == product, AuditEvent.op == "record_sbom")
            .count()
            == 0
        )
    row, _ = _requirement(product, owner)
    # The blob link is unchanged too — a baseline for the same reason the
    # evidence count is one: the fixture settles this requirement.
    assert row["evidence_count"] == before_link["evidence_count"]
