"""The proactive half: scan every product's SBOM and mail what is exploited.

The deadline sweeper chases obligations that already exist. This one looks for
the event that creates them — an advisory affecting a component you ship, which
CISA lists as actively exploited.

It reuses the deadline sweeper's delivery machinery deliberately: same
`NotificationLog` rows, same SES sender, same fan-out to every product member,
same at-least-once discipline. There is one way this service emails somebody.

Three differences from the deadline sweeper, each because the subject matter is
different:

**It runs daily, not every five minutes.** KEV changes at most daily and OSV is
somebody else's service. Hammering either would be rude and would find nothing.

**It notifies once per candidate, not on an escalating ladder.** A deadline gets
more urgent as it approaches; a candidate does not change until a person acts on
it. Repeating would train people to filter these, and this is the one mail that
must be read.

**A failed scan is silent about findings but loud in the log.** If OSV could not
be reached, the correct number of emails to send is zero — and the correct
number of "all clear" impressions to leave is also zero. The tools report
`sources_ok`; the sweeper simply does not treat an unreachable feed as a result.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from cra.db import AdvisoryCandidate, NotificationLog, Product, session_scope
from cra.server import advisories, entitlements, statutory_export
from cra.server.deadline_sweeper import (
    NotConfigured,
    _app_origin,
    _recipients,
    _send,
)

log = logging.getLogger(__name__)


def is_enabled() -> bool:
    """On by default, like deadline alerting and for the same reason.

    A compliance tool that quietly stops telling you about exploited components
    has failed at the job it was installed for. Turn it off deliberately with
    CRA_ADVISORY_ALERTS_ENABLED=0.
    """
    raw = os.environ.get("CRA_ADVISORY_ALERTS_ENABLED", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _interval_seconds() -> int:
    return int(os.environ.get("CRA_ADVISORY_SWEEP_SECONDS", str(24 * 3600)))


def _subject(product_name: str, n: int) -> str:
    what = "vulnerability" if n == 1 else "vulnerabilities"
    return f"[CRA] {n} actively exploited {what} in {product_name}"


def _body(product_name: str, rows: list[AdvisoryCandidate]) -> tuple[str, str]:
    origin = _app_origin()
    lines = [
        f"{len(rows)} component(s) in {product_name} match advisories that CISA "
        "lists as actively exploited.",
        "",
        "Under Article 14, the 24-hour early-warning clock runs from when the "
        "manufacturer becomes AWARE of an actively exploited vulnerability in "
        "the product. Treat this message as the start of that awareness unless "
        "you establish otherwise.",
        "",
    ]
    for r in rows:
        cve = r.kev_cve_id or r.advisory_id
        lines.append(f"  • {r.component_name}@{r.component_version} — {cve}")
        if r.summary:
            lines.append(f"    {r.summary[:160]}")
        if r.kev_date_added:
            lines.append(f"    on CISA KEV since {r.kev_date_added}")
    lines += [
        "",
        "This is a match between an advisory and a version string in your SBOM,",
        "not a finding that your product is affected. Confirm or dismiss each",
        "one — dismissing with a VEX justification is itself Annex I Pt II(2)",
        "evidence of vulnerability handling.",
        "",
        "In your agent: list_advisory_candidates(filter='exploited')",
    ]
    if origin:
        lines += ["", origin]
    plain = "\n".join(lines)

    items = "".join(
        f"<li><code>{r.component_name}@{r.component_version}</code> — "
        f"<b>{r.kev_cve_id or r.advisory_id}</b>"
        + (f"<br><span style='color:#555'>{r.summary[:160]}</span>" if r.summary else "")
        + "</li>"
        for r in rows
    )
    html = (
        f"<p><b>{len(rows)}</b> component(s) in <b>{product_name}</b> match "
        "advisories CISA lists as <b>actively exploited</b>.</p>"
        "<p>Under Article 14 the 24-hour early-warning clock runs from when the "
        "manufacturer becomes <b>aware</b>. Treat this message as the start of "
        "that awareness unless you establish otherwise.</p>"
        f"<ul>{items}</ul>"
        "<p>This is a match between an advisory and a version string in your "
        "SBOM, not a finding that your product is affected. Confirm or dismiss "
        "each one; a dismissal with a VEX justification is itself Annex I Pt "
        "II(2) evidence.</p>"
        "<p>In your agent: <code>list_advisory_candidates(filter='exploited')</code></p>"
    )
    return plain, html


def sweep_once(*, dry_run: bool = False) -> dict:
    """One pass over every product. Never raises for a single bad recipient."""
    if not is_enabled():
        return {"enabled": False, "scanned": 0, "sent": 0}
    if not advisories.scanning_enabled():
        log.info("advisory sweeper: scanning disabled, nothing to do")
        return {"enabled": True, "scanning": False, "scanned": 0, "sent": 0}

    scanned = sent = suppressed = failed_scans = 0
    planned: list[dict] = []

    # Scoped to owners whose plan covers scanning, rather than to every product
    # in the table. The scope has to come from somewhere, and the plan is the
    # only thing that says whether a product is meant to be swept at all.
    #
    # Skipped products are counted and returned, never silently dropped — a
    # sweep that reports "scanned 4" while ignoring 40 reads as coverage it
    # does not have.
    skipped_unentitled = 0
    with session_scope() as db:
        owned = [(p.id, p.owner_user_id) for p in db.execute(select(Product)).scalars()]

    product_ids = []
    for pid, owner_id in owned:
        if entitlements.enforced() and not entitlements.plan_for(owner_id).covers(
            entitlements.ADVISORIES
        ):
            skipped_unentitled += 1
            continue
        product_ids.append(pid)
    if skipped_unentitled:
        log.info(
            "advisory sweeper: skipping %d product(s) whose plan does not "
            "include scanning",
            skipped_unentitled,
        )

    for pid in product_ids:
        try:
            result = advisories.scan_product(pid)
        except Exception:  # noqa: BLE001 — one bad product must not stop the pass
            log.exception("advisory scan failed for product %s", pid)
            failed_scans += 1
            continue
        if not result.get("scanned"):
            continue
        scanned += 1
        if not result.get("sources_ok"):
            # An unreachable feed is not a clean scan. Say so in the log and
            # send nothing — silence is the only honest output here.
            log.warning(
                "advisory scan for %s ran against incomplete sources "
                "(kev_ok=%s osv_ok=%s); not notifying",
                pid,
                result.get("kev_ok"),
                result.get("osv_ok"),
            )
            continue

        with session_scope() as db:
            rows = list(
                db.execute(
                    select(AdvisoryCandidate).where(
                        AdvisoryCandidate.product_id == pid,
                        AdvisoryCandidate.status == "open",
                        AdvisoryCandidate.exploited.is_(True),
                        AdvisoryCandidate.notified_at.is_(None),
                    )
                ).scalars()
            )
            if not rows:
                continue

            product = db.get(Product, pid)
            recipients = _recipients(db, pid)
            if dry_run:
                planned.append(
                    {
                        "product": product.name,
                        "candidates": [r.advisory_id for r in rows],
                        "recipients": [u.email for u in recipients],
                    }
                )
                continue

            subject = _subject(product.name, len(rows))
            plain, html = _body(product.name, rows)
            now = datetime.now(timezone.utc)

            for user in recipients:
                entry = NotificationLog(
                    recipient_user_id=user.id,
                    product_id=pid,
                    obligation_id=None,
                    kind="advisory-exploited",
                    status="sent",
                )
                db.add(entry)
                db.flush()
                try:
                    entry.ses_message_id = _send(
                        to_email=user.email, subject=subject, plain=plain, html=html
                    )
                    entry.sent_at = now
                    sent += 1
                except NotConfigured as e:
                    entry.status = "suppressed"
                    entry.error_text = str(e)
                    suppressed += 1
                except Exception as e:  # noqa: BLE001
                    entry.status = "failed"
                    entry.error_text = str(e)[:500]
                    log.exception("advisory alert to %s failed", user.email)

            # Stamp awareness once the fan-out is done. This is the timestamp
            # `confirm_advisory` anchors the Article 14 clocks on, so it is
            # written whether delivery succeeded or was suppressed: the
            # manufacturer's own service knew, and a mail-server problem is not
            # a defence.
            for r in rows:
                r.notified_at = now

    out = {
        "enabled": True,
        "scanned": scanned,
        "sent": sent,
        "suppressed": suppressed,
        "failed_scans": failed_scans,
        "skipped_unentitled": skipped_unentitled,
    }
    if dry_run:
        out["planned"] = planned
    return out


async def _sweeper_loop() -> None:
    interval = _interval_seconds()
    log.info(
        "advisory sweeper started (enabled=%s, scanning=%s, interval=%ss)",
        is_enabled(),
        advisories.scanning_enabled(),
        interval,
    )
    while True:
        try:
            result = await asyncio.to_thread(sweep_once)
            if result.get("sent") or result.get("suppressed") or result.get("failed_scans"):
                log.info("advisory sweeper: %s", result)
        except Exception:  # noqa: BLE001 — the loop outlives any one failure
            log.exception("advisory sweeper iteration raised")

        # Reconcile the statutory export backlog on the same beat. Riding this
        # loop rather than starting a third one: it already runs daily, already
        # survives its own failures, and an artefact waiting a few hours for its
        # durable copy is the state the `pending` row exists to make visible.
        #
        # Separately wrapped so an S3 problem cannot take the advisory sweep
        # down with it — they fail for unrelated reasons.
        try:
            out = await asyncio.to_thread(statutory_export.flush_pending)
            if out.get("exported") or out.get("failed") or out.get("pending"):
                log.info("statutory export: %s", out)
        except Exception:  # noqa: BLE001
            log.exception("statutory export flush raised")

        await asyncio.sleep(interval)


def start_sweeper_task() -> asyncio.Task:
    return asyncio.create_task(_sweeper_loop(), name="cra-advisory-sweeper")
