"""Postgres state backend against a real database.

Skipped without DATABASE_URL, following the repo's `_NEEDS_DB` pattern.

The test that earns its keep is `test_audit_write_failure_rolls_back_state`.
Coauthor wrote activity rows best-effort and swallowed failures; here the audit
trail is the deliverable, so a failed audit write must take the state change
with it. That is a claim about transaction boundaries, and the only way to
believe it is to make a write fail against a real Postgres and look.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.db import AuditEvent, User, session_scope  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402


def _now():
    return datetime.now(timezone.utc)


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


def _audit_count(product_id: str) -> int:
    with session_scope() as s:
        return (
            s.query(AuditEvent).filter(AuditEvent.product_id == product_id).count()
        )


def test_save_and_load_roundtrip(product):
    state = store_pg.load_state(product)
    assert state.name == "Acme Gateway"
    assert state.classification.product_class == "unknown"


def test_load_missing_raises():
    with pytest.raises(FileNotFoundError):
        store_pg.load_state(str(uuid.uuid4()))


def test_refuses_product_with_no_owner():
    """A product nobody is accountable for is not a compliance artifact."""
    now = _now()
    with pytest.raises(ValueError, match="no owner"):
        store_pg.save_state(
            ComplianceState(
                product_id=str(uuid.uuid4()), name="Orphan", created_at=now, updated_at=now
            )
        )


def test_with_lock_commits_state_and_audit_together(product, owner):
    def fn(state, db):
        state.name = "Renamed"
        db.add(
            AuditEvent(
                product_id=product,
                subject_type="product",
                op="rename",
                accountable_user_id=owner,
                actor_kind="agent",
                rationale="test",
            )
        )
        return state, {"ok": True}

    assert store_pg.with_lock(product, fn) == {"ok": True}
    assert store_pg.load_state(product).name == "Renamed"
    assert _audit_count(product) == 1


def test_audit_write_failure_rolls_back_state(product, owner):
    """The inversion this whole backend exists for.

    A state change that cannot be evidenced must not survive. Here the audit
    row violates a NOT NULL constraint, so the flush fails — and the rename
    must go with it.
    """
    before = store_pg.load_state(product).name

    def fn(state, db):
        state.name = "ShouldNotPersist"
        db.add(
            AuditEvent(
                product_id=product,
                subject_type="product",
                op=None,  # NOT NULL — the write will fail
                accountable_user_id=owner,
            )
        )
        return state, {"ok": True}

    with pytest.raises(Exception):
        store_pg.with_lock(product, fn)

    assert store_pg.load_state(product).name == before
    assert _audit_count(product) == 0


def test_state_version_increments_on_each_write(product):
    v0 = store_pg.load_state(product).state_version

    def bump(state, _db):
        state.description = state.description + "."
        return state, None

    store_pg.with_lock(product, bump)
    store_pg.with_lock(product, bump)
    assert store_pg.load_state(product).state_version == v0 + 2


def test_expected_version_mismatch_raises(product):
    from cra.server.errors import VersionConflict

    state = store_pg.load_state(product)
    stale_version = state.state_version - 1
    with pytest.raises(VersionConflict):
        store_pg.save_state(state, expected_version=stale_version)


def test_denormalised_columns_mirror_the_blob(product):
    """Listing must not have to deserialise every product."""
    from cra.db import Product

    def classify(state, _db):
        state.classification.product_class = "important_class_i"
        state.lifecycle = "placed_on_market"
        return state, None

    store_pg.with_lock(product, classify)
    with session_scope() as s:
        row = s.get(Product, product)
        assert row.product_class == "important_class_i"
        assert row.lifecycle == "placed_on_market"


def test_delete_archives_rather_than_removing(product):
    """Hard delete would orphan the audit rows that describe the product."""
    from cra.db import Product

    store_pg.delete_session(product)
    with session_scope() as s:
        row = s.get(Product, product)
        assert row is not None
        assert row.archived_at is not None
    assert product not in store_pg.list_sessions()
