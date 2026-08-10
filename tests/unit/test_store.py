from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cra.schemas import ComplianceState, MemberInfo, Role
from cra.server import store


def _make_state(product_id="t", now=None) -> ComplianceState:
    now = now or datetime.now(timezone.utc)
    return ComplianceState(
        product_id=product_id,
        name="T",
        members={"u1": MemberInfo(role=Role.OWNER, user_id="u1", joined_at=now)},
        created_at=now,
        updated_at=now,
    )


def test_save_and_load_roundtrip(isolate_state):
    store.save_state(_make_state())
    rt = store.load_state("t")
    assert rt.product_id == "t"
    assert rt.members["u1"].role == "owner"


def test_load_missing_raises(isolate_state):
    with pytest.raises(FileNotFoundError):
        store.load_state("nope")


def test_with_lock_persists(isolate_state):
    store.save_state(_make_state())

    def fn(s, _db):
        s.name = "Changed"
        return s, {"ok": True}

    assert store.with_lock("t", fn) == {"ok": True}
    assert store.load_state("t").name == "Changed"


def test_session_exists(isolate_state):
    assert not store.session_exists("nope")
    store.save_state(_make_state("yes"))
    assert store.session_exists("yes")


def test_unknown_fields_are_rejected(isolate_state):
    """`extra="forbid"` is the boundary guard: an unexpected field in a stored
    blob should fail loudly rather than be silently dropped, because silently
    dropped data here is missing compliance evidence.
    """
    (isolate_state / "bad.json").write_text(
        '{"product_id":"bad","name":"B",'
        '"created_at":"2026-08-01T00:00:00Z",'
        '"updated_at":"2026-08-01T00:00:00Z",'
        '"not_a_real_field":1}',
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        store.load_state("bad")
