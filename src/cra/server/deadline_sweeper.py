"""Deadline alerting — the part that works when nobody is asking.

Forked from Coauthor's `notifications.py`, with four inversions. Each is a
place where behaviour that is right for an activity feed is wrong for a
statutory clock.

**Query the index, not a per-user cursor.** Coauthor walked every user and
asked "what happened since I last mailed you". The question here is "what is
due", which is a property of obligations, not of people — so this sweeps the
partial index on `(due_at) WHERE submitted_at IS NULL` and fans out to the
members of whichever products it finds. A user who joins a product mid-incident
gets the next alert; there is no cursor to backfill.

**No batching window.** Coauthor coalesced activity on a 300-second timer so a
burst of edits became one digest. Coalescing a one-hour-to-deadline alert is
indefensible, so the window is gone entirely.

**The kill switch defaults ON.** Coauthor's shipped dark, which is right for a
feature nobody is depending on and wrong for the alerting half of a compliance
tool: a deploy that silently disables deadline mail is the failure this exists
to prevent. Set `CRA_DEADLINE_ALERTS_ENABLED=0` to turn it off deliberately.

**Misconfiguration is recorded, not swallowed.** If mail is enabled but no
sender is configured, every skipped alert is written as a `suppressed` row
naming the reason. An operator asking "why did nobody get told" gets an answer
from the database rather than from log archaeology.

Delivery is at-least-once on purpose. A row is written before the send and
retried while it is not `sent`, so a crash mid-send costs a duplicate rather
than a miss. For a legal deadline that is the right way round.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from cra.db import (
    NotificationLog,
    Product,
    ProductMember,
    ReportingObligation,
    User,
    session_scope,
)
from cra.deadlines import due_rung, hours_remaining, sweep_lookahead
from cra.server import entitlements, mailer

log = logging.getLogger(__name__)


# ---- config -----------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or not v.strip():
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or not v.strip():
        return default
    try:
        return int(v)
    except ValueError:
        log.warning("invalid int for %s: %r — using default %d", name, v, default)
        return default


def is_enabled() -> bool:
    """Kill switch, **defaulting ON** — see the module docstring."""
    return _env_bool("CRA_DEADLINE_ALERTS_ENABLED", default=True)


def _from_addr() -> str:
    return os.environ.get("CRA_ALERTS_FROM", "")


def _ses_region() -> str:
    return os.environ.get("CRA_ALERTS_SES_REGION", "eu-north-1")


def _sweep_interval_seconds() -> int:
    return _env_int("CRA_SWEEP_INTERVAL_SECONDS", 300)


def _app_origin() -> str:
    return os.environ.get("CRA_APP_ORIGIN", "")


# ---- message ----------------------------------------------------------------

_STAGE_TEXT = {
    "early_warning": "early warning",
    "notification": "full notification",
    "final": "final report",
}


def _subject(*, product_name: str, stage: str, rung: str, remaining: float) -> str:
    stage_text = _STAGE_TEXT.get(stage, stage)
    if rung == "overdue":
        return f"OVERDUE: CRA {stage_text} for {product_name}"
    if remaining < 1:
        mins = max(int(remaining * 60), 0)
        return f"{mins} minutes left: CRA {stage_text} for {product_name}"
    return f"{int(remaining)}h left: CRA {stage_text} for {product_name}"


def _body(
    *, product_name: str, stage: str, rung: str, due_at: datetime, remaining: float
) -> tuple[str, str]:
    stage_text = _STAGE_TEXT.get(stage, stage)
    when = due_at.strftime("%Y-%m-%d %H:%M UTC")
    if rung == "overdue":
        lead = (
            f"The CRA {stage_text} for {product_name} was due at {when} and has "
            "not been recorded as submitted."
        )
    else:
        lead = (
            f"The CRA {stage_text} for {product_name} is due at {when} — "
            f"{remaining:.1f} hours from now."
        )

    plain = "\n".join(
        [
            lead,
            "",
            "Submit it on the CRA Single Reporting Platform under your EU Login, "
            "then record it with record_report_submission() so this stops "
            "chasing you.",
            "",
            "If you have already submitted, recording the reference is what "
            "closes the obligation — this alert reads the record, not the "
            "platform.",
            "",
            _app_origin() or "",
        ]
    ).strip()
    html = "<p>" + "</p><p>".join(plain.split("\n\n")) + "</p>"
    return plain, html


# ---- delivery ---------------------------------------------------------------


# Delivery lives in `server/mailer.py` — three callers now share it. Re-exported
# under the old names so the sweepers and their tests keep reading as they did.
NotConfigured = mailer.NotConfigured


def _send(*, to_email: str, subject: str, plain: str, html: str) -> str:
    """Deliver, naming this feature's own kill switch if delivery is impossible.

    The hint reaches a `notification_log` suppression row, so it has to point at
    the switch that silences deadline alerts specifically.
    """
    return mailer.send(
        to_email=to_email,
        subject=subject,
        plain=plain,
        html=html,
        hint=(
            "Set it, or set CRA_DEADLINE_ALERTS_ENABLED=0 to disable alerting "
            "deliberately."
        ),
    )


# ---- end of support ----------------------------------------------------------

# Article 13(19): the end date has to be clear to buyers, and where technically
# feasible users get told when it arrives. Days, not hours — the Article 14
# ladder counts down a 24-hour clock, this one counts down years, and a rung at
# "6 hours left" on a support period would be absurd.
#
# The last rung is `None`, meaning passed, and it fires once. A product out of
# support does not need a daily reminder; it needs one unmistakable message and
# then a status that says so every time anybody asks.
_EOS_LADDER: tuple[Optional[int], ...] = (180, 90, 30, 7, None)

# Namespaced so a rung label can never collide with an obligation's. Both write
# to `notification_log.kind`, and "T-7d" means one thing on a final report and
# something very different on a support period — dedupe reads this column, so a
# collision would silence a real alert.
_EOS_PREFIX = "eos:"


def eos_kind(rung: Optional[int]) -> str:
    return f"{_EOS_PREFIX}ended" if rung is None else f"{_EOS_PREFIX}T-{rung}d"


def eos_rung(*, end_at: datetime, now: datetime, already_sent: set[str]) -> Optional[str]:
    """The most urgent unsent rung this support period has reached.

    Same shape as `deadlines.due_rung`, and for the same reasons: only the most
    urgent crossed rung, and sending it retires the gentler ones. A sweeper
    that was down for a week should say "30 days left", not replay the ladder.
    """
    days = (end_at - now).total_seconds() / 86400.0
    for rung in reversed(_EOS_LADDER):  # passed first, then most urgent
        crossed = days < 0 if rung is None else 0 <= days <= rung
        if not crossed:
            continue
        kind = eos_kind(rung)
        return None if kind in already_sent else kind
    return None


def _eos_already_sent(db: Session, product_id: str) -> set[str]:
    """Support-period rungs already settled for this product.

    Keyed on the product rather than an obligation id, because there is no
    obligation row here — `notification_log.obligation_id` stays NULL, which is
    also why the kind has to be namespaced.
    """
    return {
        kind
        for (kind,) in db.execute(
            select(NotificationLog.kind).where(
                NotificationLog.product_id == product_id,
                NotificationLog.obligation_id.is_(None),
                NotificationLog.kind.startswith(_EOS_PREFIX),
                NotificationLog.status.in_(_SETTLED),
            )
        )
    }


def _eos_message(*, product_name: str, end_at: datetime, days: float, ended: bool):
    when = end_at.strftime("%Y-%m-%d")
    if ended:
        subject = f"Support period ended: {product_name}"
        lead = (
            f"The support period for {product_name} ended on {when}. Under "
            "Article 13(8) the obligation to handle vulnerabilities ran for "
            "that period; from here the duty to keep security updates "
            "available for ten years (Article 13(9)) is what continues."
        )
        action = (
            "Article 13(19) asks you to tell users their product has reached "
            "end of support, where that is technically feasible. If you have "
            "done it, keep what you sent as evidence."
        )
    else:
        subject = f"{int(days)} days left of support: {product_name}"
        lead = (
            f"The support period for {product_name} ends on {when} — "
            f"{int(days)} days from now."
        )
        action = (
            "Decide now whether to extend it. Extending is a determination "
            "with its own reasoning: set_support_period(end=..., "
            "rationale=...). If it is ending, Article 13(19) wants users told, "
            "and buyers to have known the date at the point of purchase."
        )

    plain = "\n".join(
        [
            lead,
            "",
            action,
            "",
            "This reads the support period you recorded, not the product. "
            "Nothing here is a statement that the product is or is not still "
            "supported in fact.",
            "",
            _app_origin() or "",
        ]
    ).strip()
    return subject, plain, "<p>" + "</p><p>".join(plain.split("\n\n")) + "</p>"


def _sweep_support_periods(db: Session, now: datetime, dry_run: bool) -> dict:
    """One pass over products whose recorded support period is near or past.

    Plan-gated the same way the advisory sweeper is, and for the same reason:
    the plan is what says whether a product is meant to be swept, and mail sent
    about a product nobody is tracking is mail nobody asked for.
    """
    considered = sent = suppressed = 0
    planned: list[dict] = []
    horizon = now + timedelta(days=max(_EOS_LADDER[0] or 0, 1))

    rows = list(
        db.execute(
            select(Product).where(
                Product.support_period_end.is_not(None),
                Product.support_period_end <= horizon,
            )
        ).scalars()
    )

    for product in rows:
        if entitlements.enforced() and not entitlements.plan_for(
            product.owner_user_id
        ).covers(entitlements.CONFORMITY):
            continue

        end_at = product.support_period_end
        if end_at.tzinfo is None:
            end_at = end_at.replace(tzinfo=timezone.utc)
        kind = eos_rung(
            end_at=end_at, now=now, already_sent=_eos_already_sent(db, product.id)
        )
        if kind is None:
            continue
        considered += 1

        days = (end_at - now).total_seconds() / 86400.0
        ended = kind == eos_kind(None)
        recipients = _recipients(db, product.id)

        if dry_run:
            planned.append(
                {
                    "product": product.name,
                    "kind": kind,
                    "ends_at": end_at.isoformat(),
                    "days_remaining": round(days, 1),
                    "recipients": [u.email for u in recipients],
                }
            )
            continue

        subject, plain, html = _eos_message(
            product_name=product.name, end_at=end_at, days=days, ended=ended
        )
        for user in recipients:
            row = NotificationLog(
                recipient_user_id=user.id,
                product_id=product.id,
                obligation_id=None,
                kind=kind,
                status="pending",
            )
            db.add(row)
            db.flush()
            try:
                row.ses_message_id = _send(
                    to_email=user.email, subject=subject, plain=plain, html=html
                )
                row.status = "sent"
                row.sent_at = now
                sent += 1
            except NotConfigured as e:
                row.status = "suppressed"
                row.error_text = str(e)[:500]
                suppressed += 1
            except Exception as e:  # noqa: BLE001 — one bad address must not
                # stop the rest of the pass.
                log.exception("end-of-support alert failed for %s", user.id)
                row.status = "failed"
                row.error_text = str(e)[:500]

    return {
        "considered": considered,
        "sent": sent,
        "suppressed": suppressed,
        "planned": planned,
    }


# ---- the sweep --------------------------------------------------------------


def _recipients(db: Session, product_id: str) -> list[User]:
    """Everyone on the product, not just its owner.

    Fan-out is the point: a deadline is the team's problem, and the person who
    happens to own the billing relationship is frequently not the one who can
    file the report.
    """
    rows = db.execute(
        select(User)
        .join(ProductMember, ProductMember.user_id == User.id)
        .where(ProductMember.product_id == product_id)
    ).scalars()
    return [u for u in rows if u.notifications_enabled and u.email and "@" in u.email]


# Statuses that settle a rung. `sent` is the happy path; `suppressed` means we
# deliberately did not send and recorded why, which needs an operator, not a
# retry — without it here, a deployment missing its sender writes a fresh
# suppression row every sweep interval, for every open obligation, forever.
#
# `pending` and `failed` are deliberately absent: the first may be a send that
# died in flight and the second plainly did, so both stay eligible. That makes
# delivery at-least-once, which is the right way round for a legal deadline.
_SETTLED = ("sent", "suppressed")


def _already_sent(db: Session, obligation_id: str) -> set[str]:
    """Rung labels that no longer need attempting for this obligation."""
    return {
        kind
        for (kind,) in db.execute(
            select(NotificationLog.kind).where(
                NotificationLog.obligation_id == obligation_id,
                NotificationLog.status.in_(_SETTLED),
            )
        )
    }


def _open_obligations(db: Session, now: datetime) -> Iterable[ReportingObligation]:
    """Unsubmitted obligations inside the lookahead, plus everything overdue.

    This is the query the partial index exists for. Overdue rows have no lower
    bound: an obligation that blew its deadline last week is still open and
    still needs its one overdue alert if it never got one.
    """
    horizon = now + sweep_lookahead()
    return db.execute(
        select(ReportingObligation)
        .where(
            ReportingObligation.submitted_at.is_(None),
            ReportingObligation.waived_reason.is_(None),
            ReportingObligation.due_at <= horizon,
        )
        .order_by(ReportingObligation.due_at)
    ).scalars()


def sweep_once(*, now: Optional[datetime] = None, dry_run: bool = False) -> dict:
    """One pass. Returns a summary; never raises for a single bad recipient.

    `dry_run` resolves and records nothing — it answers "what would go out",
    which is what you want when tuning the ladder against real data.
    """
    if not is_enabled():
        log.debug("deadline sweeper: disabled by kill switch")
        return {"enabled": False, "sent": 0, "suppressed": 0, "considered": 0}

    now = now or datetime.now(timezone.utc)
    sent = suppressed = considered = 0
    planned: list[dict] = []

    with session_scope() as db:
        for ob in list(_open_obligations(db, now)):
            rung = due_rung(
                stage=ob.stage,
                due_at=ob.due_at,
                now=now,
                already_sent=_already_sent(db, ob.id),
            )
            if rung is None:
                continue
            considered += 1

            product = db.get(Product, ob.product_id)
            if product is None:  # pragma: no cover — FK makes this unreachable
                continue
            remaining = hours_remaining(ob.due_at, now)

            if dry_run:
                planned.append(
                    {
                        "obligation_id": ob.id,
                        "product": product.name,
                        "stage": ob.stage,
                        "rung": rung,
                        "hours_remaining": remaining,
                        "recipients": [u.email for u in _recipients(db, ob.product_id)],
                    }
                )
                continue

            subject = _subject(
                product_name=product.name,
                stage=ob.stage,
                rung=rung,
                remaining=remaining,
            )
            plain, html = _body(
                product_name=product.name,
                stage=ob.stage,
                rung=rung,
                due_at=ob.due_at,
                remaining=remaining,
            )

            for user in _recipients(db, ob.product_id):
                # Write before send: a crash in between costs a duplicate on
                # the next sweep, not a missed statutory deadline.
                row = NotificationLog(
                    recipient_user_id=user.id,
                    product_id=ob.product_id,
                    obligation_id=ob.id,
                    kind=rung,
                    status="pending",
                )
                db.add(row)
                db.flush()
                try:
                    row.ses_message_id = _send(
                        to_email=user.email, subject=subject, plain=plain, html=html
                    )
                    row.status = "sent"
                    row.sent_at = now
                    sent += 1
                except NotConfigured as e:
                    # Not an error to retry — an operator has to act. Record it
                    # so the gap is visible in the data, not only in the logs.
                    row.status = "suppressed"
                    row.error_text = str(e)[:500]
                    suppressed += 1
                except Exception as e:  # noqa: BLE001 — one bad address must
                    # not stop the rest of the sweep.
                    log.exception("deadline alert failed for %s", user.id)
                    row.status = "failed"
                    row.error_text = str(e)[:500]

            # Convenience marker only. Nothing reads it to decide compliance —
            # that is `obligation_state()`, from stored facts.
            ob.escalation_last_notified_at = now

        # Article 13(19), in the same pass. Reported separately because the two
        # answer different questions — "you owe a report in six hours" and
        # "this product leaves support in 90 days" should never be added into
        # one number an operator then has to unpick.
        eos = _sweep_support_periods(db, now, dry_run)

    out = {
        "enabled": True,
        "considered": considered,
        "sent": sent,
        "suppressed": suppressed,
        "support_period": {
            "considered": eos["considered"],
            "sent": eos["sent"],
            "suppressed": eos["suppressed"],
        },
    }
    if dry_run:
        out["planned"] = planned
        out["support_period"]["planned"] = eos["planned"]
    return out


async def _sweeper_loop() -> None:
    interval = _sweep_interval_seconds()
    log.info(
        "deadline sweeper started (enabled=%s, interval=%ss, lookahead=%s)",
        is_enabled(),
        interval,
        sweep_lookahead(),
    )
    while True:
        try:
            result = await asyncio.to_thread(sweep_once)
            if result.get("sent") or result.get("suppressed"):
                log.info("deadline sweeper: %s", result)
        except Exception:  # noqa: BLE001 — the loop outlives any one failure
            log.exception("deadline sweeper iteration raised")
        await asyncio.sleep(interval)


def start_sweeper_task() -> asyncio.Task:
    return asyncio.create_task(_sweeper_loop(), name="cra-deadline-sweeper")
