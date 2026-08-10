"""Audit-trail writes.

One rule, and it is the inversion this codebase exists around: **an audit write
that fails must fail the operation.** Coauthor's equivalent ended with

    except Exception:  # noqa: BLE001 — never block the originating action

which is right when the audit row is a social feed and wrong when it is the
deliverable. Under the CRA the trail is retained ten years and is what an
auditor actually reads; a state change nobody can evidence is worse than no
state change.

So there is no try/except here. `record()` flushes immediately rather than
leaving the insert to commit-time, so a constraint violation surfaces at the
call site — inside the caller's transaction, where it still rolls back the
change it was describing.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from cra.db import AuditEvent


def record(
    db: Session,
    *,
    product_id: str,
    subject_type: str,
    op: str,
    accountable_user_id: Optional[str],
    actor_kind: str = "agent",
    subject_id: Optional[str] = None,
    rationale: str = "",
    payload: Optional[dict] = None,
    actor_model: Optional[str] = None,
    before_hash: Optional[str] = None,
    after_hash: Optional[str] = None,
) -> AuditEvent:
    """Append one audit event to the caller's open transaction.

    `accountable_user_id` is the human answerable for the action, separate from
    `actor_kind`, which records whether a person, an agent, or a model performed
    it. Both are needed: "an agent attached this evidence" does not answer an
    auditor's question, and neither does a bare user id when the work was done
    autonomously.

    **`actor_kind` defaults to `agent`, and nothing should override it to
    `human` today.** Eleven handlers used to pass `actor_kind="human"` —
    `decide_risk`, `confirm_risk_assessment`, `sign_off`, `place_on_market`,
    `dismiss_advisory` among them — while ordinary edits like
    `update_requirement` passed nothing and were recorded honestly. That is
    exactly backwards: every one of those calls arrives over the MCP wire, which
    means an agent made it, and the server has no way to know a person was in
    the room. It labelled the acts that decide, freeze and sign as human, on no
    evidence.

    That is the failure this codebase is built against, turned inward. An
    unverifiable claim is reported as unverified everywhere else —
    `open_candidates: null` where nothing was scanned, `unversioned` rather than
    stale, `incomparable` rather than superseded. The audit trail is the
    deliverable; it does not get to assert what the rest of the product refuses
    to.

    The parameter stays because a genuinely human-originated write may exist one
    day — the console is read-only, so there is none now. A test sweeps for it
    (`tests/unit/test_actor_kind.py`); a new `human` needs a reason that survives
    reading this.
    """
    event = AuditEvent(
        product_id=product_id,
        subject_type=subject_type,
        subject_id=subject_id,
        op=op,
        accountable_user_id=accountable_user_id,
        actor_kind=actor_kind,
        actor_model=actor_model,
        rationale=rationale,
        payload=payload,
        before_hash=before_hash,
        after_hash=after_hash,
    )
    db.add(event)
    # Surface constraint failures here, not at commit — the caller is still
    # inside the transaction that made the change this row describes.
    db.flush()
    return event
