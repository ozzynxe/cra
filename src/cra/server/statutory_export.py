"""The artefacts that have to outlive this database, and getting them out.

Article 13(13) keeps the technical documentation and the EU declaration of
conformity available to market surveillance authorities for **ten years after
the product is placed on the market, or the support period, whichever is
longer**. Article 13(18) says the same for the Annex II information.

That obligation used to be met by accident — a nightly full `pg_dump` into S3
Object Lock at 3,660 days, which kept every abandoned draft immutably for a
decade because a signed technical file had to be. The nightly dump now expires
at 90 days, so the obligation needs somewhere
deliberate to live. Here.

## The two-step, and why it is two steps

`record(...)` writes a `statutory_exports` row **inside the caller's
transaction**. `flush_pending(...)` uploads. They are separate because S3 is a
different system and cannot commit atomically with Postgres — so rather than
pretend, the intent is made durable where atomicity *is* available and the
upload is reconciled afterwards.

What that buys: there is no path producing a signed declaration with no row
here. The failure mode left is `pending` — the artefact exists and its durable
copy does not yet — which is visible, countable and alertable, exactly like a
`suppressed` row in `notification_log`.

The alternative designs both fail. Uploading synchronously and raising would
block someone from signing a declaration because a bucket had a bad minute, and
would still not be atomic. Uploading synchronously and swallowing the error
would make a durability failure indistinguishable from success, which is the
one outcome this product refuses everywhere.

## What an exported object is

Self-describing JSON, not a database row. Ten years is longer than this schema
will live, so an object carries the artefact, its content hash, the product and
enough provenance to be read in 2036 by someone without this codebase — the
regulation version it was assembled against, the anchor it claims, and what the
hash covers.

Keyed `product/{product_id}/{kind}/{sha256}.json`, so re-exporting an unchanged
artefact overwrites itself and a retry storm cannot fan out into duplicates.

## Retention

`retain_until` comes from `conformity.retention_status`, floored at ten years
from export. Two reasons for the floor: a product not yet placed on the market
has no statutory clock but its artefacts should still be durable, and Object
Lock retention can be extended and not shortened, so erring long is the safe
direction.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select

from cra.db import StatutoryExport, session_scope

log = logging.getLogger(__name__)

# What may be exported. A closed set on purpose: this bucket is the expensive,
# immutable one, and "everything that looked important" is how it got expensive
# the first time.
TECHNICAL_FILE = "technical_file"
DECLARATION = "declaration"
SIMPLIFIED_DECLARATION = "simplified_declaration"
SIGN_OFF = "sign_off"
RELEASE = "release"

KINDS = frozenset(
    {TECHNICAL_FILE, DECLARATION, SIMPLIFIED_DECLARATION, SIGN_OFF, RELEASE}
)

_FLOOR_YEARS = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enabled() -> bool:
    """Off without a bucket, and that is not a silent failure.

    `record()` still writes its row when this is false — the intent is the part
    that must not be lost, and a deployment that gains a bucket later uploads
    the backlog rather than discovering it never had one.
    """
    return bool(os.environ.get("CRA_STATUTORY_BUCKET"))


def _bucket() -> Optional[str]:
    return os.environ.get("CRA_STATUTORY_BUCKET") or None


def content_hash(payload: dict) -> str:
    """Stable over the payload, so an unchanged artefact re-exports to itself."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def storage_key(product_id: str, kind: str, digest: str) -> str:
    return f"product/{product_id}/{kind}/{digest}.json"


def _retain_until(retention: Optional[dict]) -> datetime:
    floor = _now().replace(microsecond=0) + timedelta(days=365 * _FLOOR_YEARS + 3)
    until = (retention or {}).get("until")
    if not until:
        return floor
    try:
        statutory = datetime.fromisoformat(str(until))
    except ValueError:
        return floor
    if statutory.tzinfo is None:
        statutory = statutory.replace(tzinfo=timezone.utc)
    return max(floor, statutory)


def record(
    db,
    *,
    product_id: str,
    kind: str,
    payload: dict,
    retention: Optional[dict] = None,
    digest: Optional[str] = None,
) -> Optional[StatutoryExport]:
    """Register an artefact for export. **Call inside the caller's transaction.**

    Returns the row, or None if an identical artefact is already registered —
    which is the normal outcome of re-freezing a technical file that has not
    changed, and must not be an error.

    `digest` is the artefact's **own** content hash where it has one, and
    passing it matters. Hashing this function's wrapper instead makes the
    identity depend on whatever else the wrapper carries — an `evidence_id`
    that is a fresh UUID on every freeze, for instance, which made an unchanged
    technical file export twice under different keys. The tool computing the
    artefact has already decided what its identity covers (see
    `assemble_technical_file`, which deliberately keeps `assembled_at` outside
    the digest for exactly this reason); this should not second-guess it.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown statutory export kind: {kind!r}")

    own_digest = digest is not None
    digest = digest or content_hash(payload)
    existing = db.execute(
        select(StatutoryExport).where(
            StatutoryExport.product_id == product_id,
            StatutoryExport.kind == kind,
            StatutoryExport.content_sha256 == digest,
        )
    ).scalars().first()
    if existing is not None:
        return None

    row = StatutoryExport(
        product_id=product_id,
        kind=kind,
        content_sha256=digest,
        payload={
            "kind": kind,
            "product_id": product_id,
            "content_sha256": digest,
            "recorded_at": _now().isoformat(),
            "retention": retention,
            "artefact": payload,
            "hash_covers": (
                # True in an object that has to be read in 2036 by someone
                # without this codebase, so it must say which of the two it is.
                "the artefact's own content hash, as computed by the tool that "
                "froze it"
                if own_digest
                else "`artefact`, canonicalised as sorted compact JSON"
            ),
            "note": (
                "Exported under Regulation (EU) 2024/2847 Article 13(13) and "
                "13(18) by cra-mcp. `retention.until` is the date this must "
                "remain available; `retain_until` on the object carries the "
                "same date, floored at ten years."
            ),
        },
        retain_until=_retain_until(retention),
    )
    db.add(row)
    return row


def _upload(client, bucket: str, row: StatutoryExport) -> str:
    key = storage_key(row.product_id, row.kind, row.content_sha256)
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(row.payload, sort_keys=True, indent=2, default=str).encode(),
        ContentType="application/json",
        ObjectLockMode="GOVERNANCE",
        ObjectLockRetainUntilDate=row.retain_until,
    )
    return key


def flush_pending(limit: int = 200, *, product_id: Optional[str] = None) -> dict:
    """Upload what has not made it out yet. Safe to call repeatedly.

    Never raises for one bad row: a single artefact that cannot be serialised
    must not stop the rest of the backlog, and its `error_text` is the record of
    why. Same discipline as the two sweepers.

    **Unscoped, this drains the entire backlog** — correct for the sweeper and a
    footgun anywhere else. Pointing `CRA_STATUTORY_BUCKET` at the real archive
    from a development database uploads every test artefact into a bucket they
    cannot be deleted from for ten years, and undoing that needs a governance
    bypass. Assume it will happen to whoever runs this next.

    `product_id` scopes it to one product, which is what a smoke test or a
    manual backfill should use. There is deliberately no environment check:
    `CRA_ENV` defaults to "production" throughout this codebase, so it cannot
    tell a laptop from the real deployment, and a guard that looks like
    protection without being any is worse than none.
    """
    if not enabled():
        with session_scope() as db:
            pending = db.execute(
                select(StatutoryExport).where(StatutoryExport.status == "pending")
            ).scalars().all()
            if pending:
                log.warning(
                    "%d statutory artefact(s) awaiting export and "
                    "CRA_STATUTORY_BUCKET is unset — the record exists only in "
                    "the database, whose backups now expire",
                    len(pending),
                )
            return {"enabled": False, "pending": len(pending), "exported": 0}

    import boto3  # noqa: WPS433 — local, so this module imports without boto3

    client = boto3.client("s3", region_name=os.environ.get("AWS_REGION", "eu-north-1"))
    bucket = _bucket()
    exported = failed = 0

    with session_scope() as db:
        rows = db.execute(
            select(StatutoryExport)
            .where(StatutoryExport.status.in_(("pending", "failed")))
            .where(
                StatutoryExport.product_id == product_id
                if product_id
                else StatutoryExport.product_id.isnot(None)
            )
            .order_by(StatutoryExport.created_at)
            .limit(limit)
        ).scalars().all()

        for row in rows:
            row.attempts = (row.attempts or 0) + 1
            try:
                row.storage_key = _upload(client, bucket, row)
                row.status = "exported"
                row.exported_at = _now()
                row.error_text = None
                exported += 1
            except Exception as e:  # noqa: BLE001 — one bad row must not stop the rest
                row.status = "failed"
                row.error_text = f"{type(e).__name__}: {e}"[:2000]
                failed += 1
                log.exception("statutory export failed for %s", row.id)

    if failed:
        log.warning("statutory export: %d exported, %d failed", exported, failed)
    return {"enabled": True, "exported": exported, "failed": failed}


def pending_count() -> int:
    with session_scope() as db:
        return len(
            db.execute(
                select(StatutoryExport).where(StatutoryExport.status != "exported")
            ).scalars().all()
        )
