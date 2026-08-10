"""Freezing an artefact and registering it for export are one transaction.

That is the whole guarantee, and it is why the export row lives in Postgres
rather than being an S3 call at the end of the handler. S3 cannot commit
atomically with the database, so the *intent* is made durable where atomicity
is available and the upload is reconciled afterwards.

What this buys, since the nightly dump now expires after 90 days: there is no
path that produces a signed declaration whose durable copy was silently never
made. The remaining failure is `pending`, which is a real state with a row
behind it — visible, countable, alertable — rather than an absence.

Tested against a database because the atomicity claim is meaningless without
one.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

_NEEDS_DB = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import StatutoryExport, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import statutory_export, store_pg  # noqa: E402

pytestmark = _NEEDS_DB

SBOM = (
    '{"bomFormat":"CycloneDX","components":['
    '{"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}'
)


def _call(name, product_id, actor_id, **args):
    return dispatcher.dispatch(name, product_id, actor_id, args)


@pytest.fixture
def owner():
    uid = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=uid, email=f"exp-{uid[:8]}@example.test"))
    return uid


@pytest.fixture
def product(owner, make_releasable, clean_scan):
    pid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    store_pg.save_state(
        ComplianceState(
            product_id=pid,
            name="Acme Gateway",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    _call("classify_product", pid, owner, product_class="default", in_scope=True,
          rationale="Ordinary product with digital elements.")
    _call("record_sbom", pid, owner, sbom=SBOM, source_ref="git:abc1234")
    make_releasable(_call, pid, owner)
    return pid


def _exports(pid, kind=None):
    with session_scope() as s:
        rows = s.query(StatutoryExport).filter(StatutoryExport.product_id == pid).all()
        return [r for r in rows if kind is None or r.kind == kind]


def test_a_product_with_nothing_frozen_exports_nothing():
    """The bucket is the expensive one. Only real artefacts go in it."""
    assert _exports(str(uuid.uuid4())) == []


def test_recording_a_release_registers_it(product, owner):
    _call("scan_advisories", product, owner)
    out = _call("record_release", product, owner, version="1.0.0")
    assert out["ok"] is True, out
    rows = _exports(product, statutory_export.RELEASE)
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert rows[0].payload["artefact"]["version"] == "1.0.0"


def test_freezing_the_technical_file_registers_it(product, owner, make_file_freezable):
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")
    make_file_freezable(_call, product, owner)
    out = _call("assemble_technical_file", product, owner, finalize=True)
    assert out["ok"] is True, out
    rows = _exports(product, statutory_export.TECHNICAL_FILE)
    assert len(rows) == 1
    assert rows[0].payload["artefact"]["content_hash"] == out["content_hash"]


def test_re_freezing_unchanged_content_does_not_duplicate(product, owner, make_file_freezable):
    """Keyed by content hash. A retry, or a re-freeze that changed nothing,
    must not fan out into a second immutable object."""
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")
    make_file_freezable(_call, product, owner)
    _call("assemble_technical_file", product, owner, finalize=True)
    _call("assemble_technical_file", product, owner, finalize=True)
    assert len(_exports(product, statutory_export.TECHNICAL_FILE)) == 1


def test_the_export_carries_its_own_retention_date(product, owner):
    """Per object, from Article 13(13), rather than a blanket 3,660 days."""
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")
    rows = _exports(product, statutory_export.RELEASE)
    assert rows[0].retain_until.year >= datetime.now(timezone.utc).year + 9


def test_an_artefact_and_its_export_row_commit_together(product, owner, make_file_freezable, monkeypatch):
    """The guarantee. If registering the export fails, the freeze fails too —
    a frozen file with no durable copy is the state this exists to prevent."""
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")
    make_file_freezable(_call, product, owner)

    def boom(*a, **kw):
        raise RuntimeError("export registry is down")

    monkeypatch.setattr(statutory_export, "record", boom)
    out = _call("assemble_technical_file", product, owner, finalize=True)
    assert out["ok"] is False

    with session_scope() as s:
        frozen = [
            e
            for e in s.query(StatutoryExport)
            .filter(StatutoryExport.product_id == product)
            .all()
            if e.kind == statutory_export.TECHNICAL_FILE
        ]
    assert frozen == [], "an export row survived a rolled-back freeze"


def test_without_a_bucket_the_intent_is_still_recorded(product, owner, monkeypatch):
    """A deployment with no bucket must accumulate a backlog it can upload
    later, not discover it never had one."""
    monkeypatch.delenv("CRA_STATUTORY_BUCKET", raising=False)
    assert statutory_export.enabled() is False
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")
    assert len(_exports(product, statutory_export.RELEASE)) == 1
    assert statutory_export.flush_pending() == {
        "enabled": False,
        "pending": statutory_export.pending_count(),
        "exported": 0,
    }


def test_flush_uploads_pending_rows_and_marks_them(product, owner, monkeypatch):
    monkeypatch.setenv("CRA_STATUTORY_BUCKET", "test-bucket")
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")

    put = []

    class _Client:
        def put_object(self, **kw):
            put.append(kw)

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _Client())
    result = statutory_export.flush_pending()
    assert result["exported"] >= 1
    # flush_pending drains the whole backlog, and other tests leave rows in it,
    # so find this product's object rather than assuming it is first.
    mine = [k for k in put if k["Key"].startswith(f"product/{product}/")]
    assert mine, f"nothing uploaded for {product}"
    assert mine[0]["Bucket"] == "test-bucket"
    assert mine[0]["ObjectLockMode"] == "GOVERNANCE"

    rows = _exports(product, statutory_export.RELEASE)
    assert rows[0].status == "exported"
    assert rows[0].storage_key == mine[0]["Key"]


def test_an_upload_failure_is_recorded_rather_than_swallowed(product, owner, monkeypatch):
    """A durability failure that leaves no trace is indistinguishable from
    success — the one outcome this product refuses everywhere."""
    monkeypatch.setenv("CRA_STATUTORY_BUCKET", "test-bucket")
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")

    class _Client:
        def put_object(self, **kw):
            raise RuntimeError("bucket unreachable")

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _Client())
    result = statutory_export.flush_pending()
    assert result["failed"] >= 1

    rows = _exports(product, statutory_export.RELEASE)
    assert rows[0].status == "failed"
    assert "bucket unreachable" in rows[0].error_text
    assert rows[0].attempts == 1


def test_a_failed_export_is_retried_on_the_next_flush(product, owner, monkeypatch):
    monkeypatch.setenv("CRA_STATUTORY_BUCKET", "test-bucket")
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")

    state = {"fail": True}

    class _Client:
        def put_object(self, **kw):
            if state["fail"]:
                raise RuntimeError("down")

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _Client())
    statutory_export.flush_pending()
    state["fail"] = False
    statutory_export.flush_pending()

    rows = _exports(product, statutory_export.RELEASE)
    assert rows[0].status == "exported"
    assert rows[0].attempts == 2
    assert rows[0].error_text is None


def test_a_flush_can_be_scoped_to_one_product(product, owner, monkeypatch):
    """Unscoped, `flush_pending` drains everything — right for the sweeper, and
    a footgun for a smoke test pointed at the real archive from a development
    database: the artefacts land under a ten-year lock and undoing that needs a
    governance bypass."""
    monkeypatch.setenv("CRA_STATUTORY_BUCKET", "test-bucket")
    _call("scan_advisories", product, owner)
    _call("record_release", product, owner, version="1.0.0")

    put = []

    class _Client:
        def put_object(self, **kw):
            put.append(kw)

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _Client())
    statutory_export.flush_pending(product_id=product)

    assert put, "nothing uploaded"
    stray = [k for k in put if not k["Key"].startswith(f"product/{product}/")]
    assert stray == [], f"a scoped flush uploaded {len(stray)} other product(s)"
