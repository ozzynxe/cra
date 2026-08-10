"""Evidence going stale when the product moves past it — #14, end to end.

The failure this closes: a technical file that is complete, frozen, signed, and
describes a release from two years ago. Every piece of that file looked settled
because nothing in the system knew which build a test report was about.

The "Done when" from the issue, which is the first test below: *shipping a new
version makes requirements evidenced only against the old one visibly stale,
and `assemble_technical_file` will not report them settled.*

The other half is restraint. Evidence with no version attached must **not**
read as stale, or deploying this would have turned every existing requirement
in every account into a gap overnight on the strength of something nobody
checked.
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

from cra.advisories.feeds import KevCatalogue, OsvResult  # noqa: E402
from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import Evidence, User, session_scope  # noqa: E402
from cra.regulation import requirements as catalogue  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import advisories, annex, store_pg  # noqa: E402

UTC = timezone.utc
SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"}],
    }
)
REQ = "annex_i.i.2.e"  # confidentiality — an evidence-only requirement


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


@pytest.fixture(autouse=True)
def clean_feeds(monkeypatch):
    """Nothing matches, so the release gate is never the thing under test."""
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


def _ship(product, owner, version):
    _call("scan_advisories", product, owner)
    out = _place( product, owner, version=version)
    assert out["ok"] is True, out
    return out


def _evidence_for(product, owner, req=REQ, **kw):
    return _call(
        "attach_evidence",
        product,
        owner,
        subject_ref=f"requirement:{req}",
        title="Encryption at rest test report",
        body="AES-256-GCM verified over the storage layer; 42 cases, 0 failures.",
        source_ref="ci:run/8891",
        **kw,
    )


def _verified(product, owner, req=REQ):
    _call(
        "update_requirement",
        product,
        owner,
        req_id=req,
        applicability="applicable",
        status="verified",
        implementation_note="Encrypted at rest and in transit.",
    )


def _currency(product, owner, req=REQ):
    out = _call("list_requirements", product, owner, verbose=True)
    row = next(r for r in out["requirements"] if r["req_id"] == req)
    return out, row.get("evidence_currency")


# ---- the Done when --------------------------------------------------------------


def test_shipping_a_new_version_makes_old_evidence_stale(product, owner):
    _ship(product, owner, "1.0.0")
    _evidence_for(product, owner)
    _verified(product, owner)

    out, currency = _currency(product, owner)
    assert currency["state"] == annex.CURRENT
    assert REQ not in out["evidence_stale"]

    _ship(product, owner, "2.0.0")

    out, currency = _currency(product, owner)
    assert currency["state"] == annex.STALE
    assert currency["evidenced_against"] == ["1.0.0"]
    assert REQ in out["evidence_stale"]
    assert "re-evidencing against the current release" in currency["detail"]


def test_stale_evidence_stops_the_file_reporting_it_settled(product, owner):
    _ship(product, owner, "1.0.0")
    _evidence_for(product, owner)
    _verified(product, owner)
    _ship(product, owner, "2.0.0")

    tf = _call("assemble_technical_file", product, owner)
    coverage = next(
        s["requirement_coverage"] for s in tf["slots"] if "requirement_coverage" in s
    )
    assert REQ in coverage["gaps"]
    assert REQ in coverage["evidenced_against_earlier_release"]


def test_re_evidencing_against_the_new_release_settles_it_again(product, owner):
    _ship(product, owner, "1.0.0")
    _evidence_for(product, owner)
    _verified(product, owner)
    _ship(product, owner, "2.0.0")
    assert _currency(product, owner)[1]["state"] == annex.STALE

    _evidence_for(product, owner)  # defaults to the current release

    out, currency = _currency(product, owner)
    assert currency["state"] == annex.CURRENT
    assert REQ not in out["evidence_stale"]


# ---- the restraint ---------------------------------------------------------------


def test_evidence_attached_before_any_release_is_unversioned_not_stale(product, owner):
    """The migration case, and the reason this is not a flag day. Every row
    written before `applies_to_version` existed is NULL."""
    _evidence_for(product, owner)
    _verified(product, owner)
    _ship(product, owner, "1.0.0")

    out, currency = _currency(product, owner)
    assert currency["state"] == annex.UNVERSIONED
    assert REQ in out["evidence_unversioned"]
    assert REQ not in out["evidence_stale"]


def test_unversioned_evidence_does_not_block_the_technical_file(product, owner):
    _evidence_for(product, owner)
    _verified(product, owner)
    _ship(product, owner, "1.0.0")

    tf = _call("assemble_technical_file", product, owner)
    coverage = next(
        s["requirement_coverage"] for s in tf["slots"] if "requirement_coverage" in s
    )
    assert REQ not in coverage["gaps"]
    assert REQ in coverage["evidence_without_a_release"]


def test_a_product_with_no_releases_behaves_exactly_as_before(product, owner):
    """Zero verdicts and no extra keys, so nothing changes for anyone who has
    not started recording releases."""
    _evidence_for(product, owner)
    _verified(product, owner)

    out, currency = _currency(product, owner)
    assert currency is None
    assert "current_release" not in out
    assert "evidence_stale" not in out


# ---- how a version gets onto a piece of evidence ----------------------------------


def test_attaching_defaults_to_the_current_release_and_says_so(product, owner):
    _ship(product, owner, "3.1.4")
    out = _evidence_for(product, owner)
    assert out["applies_to_version"] == "3.1.4"
    assert "Tied to release 3.1.4" in out["version_note"]


def test_an_explicit_version_back_fills_an_earlier_release(product, owner):
    _ship(product, owner, "1.0.0")
    _ship(product, owner, "2.0.0")
    out = _evidence_for(product, owner, applies_to_version="1.0.0")
    assert out["applies_to_version"] == "1.0.0"
    assert "version_note" not in out

    with session_scope() as s:
        row = s.query(Evidence).filter(Evidence.id == out["evidence_id"]).one()
        assert row.applies_to_version == "1.0.0"


def test_a_version_that_was_never_released_is_refused(product, owner):
    """Evidence pointing at a release that does not exist would look versioned
    and be unverifiable — worse than leaving it untagged."""
    _ship(product, owner, "1.0.0")
    out = _evidence_for(product, owner, applies_to_version="9.9.9")
    assert out["ok"] is False
    assert "no release '9.9.9'" in out["error"]


def test_before_any_release_the_reply_explains_why_it_is_unversioned(product, owner):
    out = _evidence_for(product, owner)
    assert out["applies_to_version"] is None
    assert "unversioned rather than stale" in out["version_note"]


def test_the_version_reaches_the_audit_trail(product, owner):
    from cra.db import AuditEvent

    _ship(product, owner, "1.0.0")
    out = _evidence_for(product, owner)
    with session_scope() as s:
        ev = (
            s.query(AuditEvent)
            .filter(
                AuditEvent.product_id == product,
                AuditEvent.subject_id == out["evidence_id"],
            )
            .one()
        )
        assert ev.payload["applies_to_version"] == "1.0.0"


# ---- the release gate writes its own versioned evidence ----------------------------


def test_the_i2a_determination_lands_on_the_requirement_it_is_about(product, owner):
    """`place_on_market` is itself an evidence writer, and its artefact has to
    play by the same rules as any other."""
    _ship(product, owner, "1.0.0")
    listed = _call("list_evidence", product, owner, subject_ref="requirement:annex_i.i.2.a")
    assert listed["count"] == 1

    out = _call("list_requirements", product, owner, verbose=True)
    row = next(r for r in out["requirements"] if r["req_id"] == "annex_i.i.2.a")
    assert row["evidence_count"] == 1
    assert (row.get("evidence_currency") or {}).get("state") == annex.CURRENT


# ---- the adjacent fix ---------------------------------------------------------------


def test_the_content_hash_is_stable_when_nothing_changed(product, owner):
    """`assembled_at` used to sit inside the hashed payload, so the digest moved
    on every call and every prior attestation read as stale after any
    re-freeze. Staleness has to mean the file changed."""
    first = _call("assemble_technical_file", product, owner)
    second = _call("assemble_technical_file", product, owner)
    assert first["content_hash"] == second["content_hash"]
    assert first["assembled_at"] != second["assembled_at"]


def test_the_file_records_which_release_it_describes(product, owner):
    _ship(product, owner, "1.0.0")
    tf = _call("assemble_technical_file", product, owner)
    assert tf["release"] == "1.0.0"

    before = tf["content_hash"]
    _ship(product, owner, "2.0.0")
    after = _call("assemble_technical_file", product, owner)["content_hash"]
    assert before != after, "a new release changes what the file documents"


def test_every_catalogue_requirement_can_carry_a_currency_verdict(product, owner):
    """Guards the join key: currency is keyed on `req_id`, and a catalogue
    renumbering that broke it would silently report every requirement as having
    no verdict rather than failing."""
    _ship(product, owner, "1.0.0")
    ids = {r.id for r in catalogue()}
    out = _call("list_requirements", product, owner)
    assert {r["req_id"] for r in out["requirements"]} == ids


def test_a_file_with_no_release_says_nothing_is_tied_to_a_build(product, owner):
    """`evidence_currency` returns nothing when there are no releases — there is
    no build for evidence to be current *against* — so `evidence_without_a_
    release`, the field that exists to say evidence is untied, is empty in
    exactly the case where none of it is tied to anything.

    A run froze, declared and signed a technical file in which no claim was tied
    to any build, and nothing in the file said so. Reported at the file level
    rather than per requirement: the per-item verdict would be noise on every
    product that has not shipped yet, and the fact worth stating is about the
    file.
    """
    tf = _call("assemble_technical_file", product, owner)
    assert tf["release"] is None
    assert "nothing in this file is tied to a build" in tf["describes_no_release"]
    assert "record_build()" in tf["describes_no_release"]


def test_once_a_release_exists_that_statement_is_gone(product, owner):
    _ship(product, owner, "1.0.0")
    tf = _call("assemble_technical_file", product, owner)
    assert tf["describes_no_release"] is None
