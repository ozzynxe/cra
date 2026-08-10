"""Postgres state backend — the one that makes the audit trail trustworthy.

The state blob lives in `products.state` (JSONB) rather than a file or a
DynamoDB item, for one reason: **the state write and the audit write must land
in the same transaction.**

**The CRA asks for no audit trail.** Keeping one is a design choice — it
answers "who decided this, and when" about a file an authority may read, and it
is evidence of the Annex I Pt II(2) vulnerability handling. Nothing here should
describe it as a statutory requirement. Parts of it do become statutory once a
product is placed on the market, which is when working state turns into the
record an authority may ask for.

Chosen or not, it is a deliverable, so a state change nobody can evidence is
worse than no state change at all. The upstream this forked from wrote activity
rows best-effort and swallowed failures — correct for a social feed, where a
lost row costs nothing. Here `with_lock` hands the caller
the live SQLAlchemy session: anything it writes commits atomically with the
state, and any failure rolls the whole thing back.

Concurrency is `SELECT … FOR UPDATE` on the product row. Several developers'
agents work one product at once, but writes are keyed and mostly independent
(different requirements, different vulnerabilities), so the critical section is
short and contention is rare. `state_version` is carried for optimistic checks
by callers that read before writing.

Interface matches `store.py` so `store_backend.get_backend()`
can swap between them, with one deliberate difference: `with_lock`'s callback
receives `(state, db)` rather than `(state,)`.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Callable, Optional, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from cra.db import Product, ProductMember, session_scope
from cra.schemas import ComplianceState

log = logging.getLogger(__name__)

T = TypeVar("T")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_jsonb(state: ComplianceState) -> dict:
    """Pydantic → plain dict for JSONB.

    Round-tripping through `model_dump_json` rather than `model_dump` so
    datetimes and enums serialise exactly as they do everywhere else — a
    stored blob that only *nearly* matches the wire format is a debugging tax
    nobody should pay twice.
    """
    return json.loads(state.model_dump_json())


def _mirror_columns(row: Product, state: ComplianceState) -> None:
    """Denormalise the few fields queried across products.

    Everything else stays in the blob. These exist so listing and filtering
    don't have to deserialise every product.
    """
    row.name = state.name
    row.economic_operator_role = state.economic_operator_role
    row.product_class = state.classification.product_class
    row.lifecycle = state.lifecycle
    row.support_period_end = state.support_period.end


def _mirror_members(s: Session, state: ComplianceState) -> None:
    """Project blob membership into `product_members`, in the same transaction.

    The blob stays the source of truth; this table is the queryable index onto
    it. It has to exist because the question "what is due across everything
    this user is on" is asked without a product id, and answering it by
    deserialising every blob in the database is exactly what putting
    obligations in rows was meant to avoid.

    Sync rather than append: a member removed from the state must lose access
    on the next write, not linger with a stale grant.
    """
    existing = {
        m.user_id: m
        for m in s.execute(
            select(ProductMember).where(ProductMember.product_id == state.product_id)
        ).scalars()
    }
    for user_id, info in state.members.items():
        row = existing.pop(user_id, None)
        if row is None:
            s.add(
                ProductMember(
                    product_id=state.product_id,
                    user_id=user_id,
                    role=str(info.role),
                    added_at=info.joined_at or _now(),
                )
            )
        elif row.role != str(info.role):
            row.role = str(info.role)
    for stale in existing.values():
        s.delete(stale)


def load_state(product_id: str) -> ComplianceState:
    with session_scope() as s:
        row = s.get(Product, product_id)
        if row is None:
            raise FileNotFoundError(f"no product {product_id!r}")
        return ComplianceState.model_validate(row.state)


def save_state(state: ComplianceState, *, expected_version: Optional[int] = None) -> None:
    """Upsert the product row.

    `expected_version` enables an optimistic check for callers that read, then
    wrote, outside a `with_lock` block. Inside `with_lock` the row is already
    locked and this is unnecessary.
    """
    from cra.server.errors import VersionConflict

    with session_scope() as s:
        row = s.get(Product, state.product_id, with_for_update=True)
        now = _now()
        if row is None:
            state.state_version = 0
            state.updated_at = now
            owner = next(
                (uid for uid, m in state.members.items() if m.role == "owner"),
                None,
            )
            if owner is None:
                raise ValueError(
                    f"product {state.product_id!r} has no owner member; refusing to "
                    "create a product nobody is accountable for"
                )
            row = Product(
                id=state.product_id,
                slug=state.product_id,
                owner_user_id=owner,
                state=_to_jsonb(state),
                state_version=0,
                created_at=now,
                updated_at=now,
            )
            _mirror_columns(row, state)
            s.add(row)
            s.flush()  # the membership rows need the product to exist
            _mirror_members(s, state)
            return

        if expected_version is not None and row.state_version != expected_version:
            raise VersionConflict(
                f"product {state.product_id} is at version {row.state_version}, "
                f"expected {expected_version} — reload and reapply"
            )
        state.state_version = row.state_version + 1
        state.updated_at = now
        row.state = _to_jsonb(state)
        row.state_version = state.state_version
        row.updated_at = now
        _mirror_columns(row, state)
        _mirror_members(s, state)


def with_lock(
    product_id: str,
    fn: Callable[[ComplianceState, object], tuple[ComplianceState, T]],
) -> T:
    """Lock the product row, apply `fn`, persist, and commit as one transaction.

    `fn` receives `(state, db)`. Write audit rows through `db` — they commit
    with the state or not at all. Raising from `fn` rolls back everything,
    which is the intended behaviour when an audit write fails.
    """
    with session_scope() as s:
        row = s.get(Product, product_id, with_for_update=True)
        if row is None:
            raise FileNotFoundError(f"no product {product_id!r}")

        state = ComplianceState.model_validate(row.state)
        new_state, result = fn(state, s)

        new_state.state_version = row.state_version + 1
        new_state.updated_at = _now()
        row.state = _to_jsonb(new_state)
        row.state_version = new_state.state_version
        row.updated_at = new_state.updated_at
        _mirror_columns(row, new_state)
        _mirror_members(s, new_state)
        return result


def session_exists(product_id: str) -> bool:
    with session_scope() as s:
        return s.get(Product, product_id) is not None


def list_sessions() -> list[str]:
    with session_scope() as s:
        return [
            r[0]
            for r in s.execute(
                select(Product.id).where(Product.archived_at.is_(None)).order_by(Product.created_at)
            ).all()
        ]


def delete_session(product_id: str) -> None:
    """Archive, never hard-delete.

    `audit_events` and `attestations` carry no foreign key to `products`
    precisely so the record survives — but removing the product row would still
    orphan the thing those rows describe. Archiving keeps the story readable.
    """
    with session_scope() as s:
        row = s.get(Product, product_id, with_for_update=True)
        if row is not None:
            row.archived_at = _now()
