"""Inviting a colleague to a product by email.

`add_member` took a `user_id` and nothing in the service could look one up, so
adding a teammate meant reading their UUID out of the database. This is the
part that makes it work for a person: an address, an email, and membership
applied when they verify.

## Enumeration

`add_member` answers the same whether the address already has an account. The
owner learns that the person was invited, never whether they were already a
customer — the same line `request_access` holds, and for the same reason: who
has an account here is not a fact an invitation form should hand out.

## Why the row outlives acceptance

Who was invited to a product, by whom, and when they joined is part of the
record of who could have touched a technical file kept for ten years. Deleting
the invitation on acceptance would leave only the membership, which says who is
there now and not how they got there.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from cra.db import ProductInvitation, User, session_scope
from cra.server import mailer, signup

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalise(email: str) -> str:
    """Same rules as everywhere else an address is accepted here."""
    return signup.normalise_email(email)


def user_id_for(email: str) -> Optional[str]:
    with session_scope() as db:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        return user.id if user else None


def invite(
    *,
    product_id: str,
    email: str,
    role: str,
    invited_by: Optional[str],
    product_name: str = "",
) -> None:
    """Record a pending invitation and mail it. Never raises on mail failure.

    The row is what matters — it is what makes them a member when they sign up.
    A mail problem should not lose the invitation, so it is written first and
    the send is best-effort. The owner can always resend.
    """
    with session_scope() as db:
        existing = db.execute(
            select(ProductInvitation).where(
                ProductInvitation.product_id == product_id,
                ProductInvitation.email == email,
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.role = role
            existing.revoked_at = None
            existing.invited_by = invited_by or existing.invited_by
        else:
            db.add(
                ProductInvitation(
                    product_id=product_id,
                    email=email,
                    role=role,
                    invited_by=invited_by,
                )
            )

    origin = (mailer.app_origin() or "").rstrip("/")
    where = f"{origin}/access" if origin else "the sign-up page"
    name = product_name or "a product"
    try:
        mailer.send(
            to_email=email,
            subject=f"You have been added to {name} on Skarp CRA",
            plain=(
                f"Someone added this address to {name} on Skarp CRA, as "
                f"{role}.\n\n"
                f"You do not have an account here yet. Create one at {where} "
                "and you will join automatically — there is nothing to accept.\n\n"
                "Skarp CRA tracks EU Cyber Resilience Act obligations for "
                "software products. If this means nothing to you, ignore this "
                "email; nothing happens until you sign up.\n\n"
                "Questions: cra@skarp.app"
            ),
            html=(
                f"<p>Someone added this address to <b>{signup._esc(name)}</b> on "
                f"Skarp CRA, as <b>{signup._esc(role)}</b>.</p>"
                f'<p>You do not have an account here yet. <a href="{where}">Create '
                "one</a> and you will join automatically — there is nothing to "
                "accept.</p>"
                "<p>Skarp CRA tracks EU Cyber Resilience Act obligations for "
                "software products. If this means nothing to you, ignore this "
                "email; nothing happens until you sign up.</p>"
                '<p>Questions: <a href="mailto:cra@skarp.app">cra@skarp.app</a></p>'
            ),
            hint="Set it, or invited colleagues are never told they were invited.",
        )
    except Exception:  # noqa: BLE001 — the row is the invitation, not the email
        log.exception("could not mail the invitation for %s to %s", product_id, email)


def apply_pending(email: str, user_id: str) -> list[str]:
    """Join every product this address was invited to. Returns product ids.

    Called from `signup._claim_account`, which is the one place an address
    becomes an account — so an invitation lands whichever way they arrive:
    magic link, OAuth code, billing, or console login.

    Membership is written through the state blob rather than the mirror table,
    because the blob is the source of truth and `save_state` is what keeps the
    two in step.
    """
    with session_scope() as db:
        pending = list(
            db.execute(
                select(ProductInvitation).where(
                    ProductInvitation.email == email,
                    ProductInvitation.accepted_at.is_(None),
                    ProductInvitation.revoked_at.is_(None),
                )
            ).scalars()
        )
        rows = [(p.id, p.product_id, p.role) for p in pending]

    joined: list[str] = []
    for invite_id, product_id, role in rows:
        try:
            _join(product_id, user_id, role)
        except Exception:  # noqa: BLE001 — one bad invitation must not block signup
            log.exception("could not apply invitation %s", invite_id)
            continue
        with session_scope() as db:
            row = db.get(ProductInvitation, invite_id)
            if row is not None:
                row.accepted_at = _now()
        joined.append(product_id)

    if joined:
        log.info("applied %d invitation(s) for %s", len(joined), email)
    return joined


def _join(product_id: str, user_id: str, role: str) -> None:
    from cra.schemas import MemberInfo, Role
    from cra.server import audit, store_backend

    backend = store_backend.get_backend()
    state = backend.load_state(product_id)
    if user_id in state.members:
        return
    state.members[user_id] = MemberInfo(
        role=Role(role), user_id=user_id, joined_at=_now()
    )
    backend.save_state(state)

    with session_scope() as db:
        audit.record(
            db,
            product_id=product_id,
            subject_type="membership",
            subject_id=user_id,
            op="accept_invitation",
            accountable_user_id=user_id,
            payload={"user_id": user_id, "role": role},
        )
