"""Everything this service holds about one product, in one document.

There was no way to get data out. For a tool whose whole proposition is
"put your compliance record here and keep it for ten years", that is the wrong
shape twice over: it asks for a commitment it does not reciprocate, and it makes
"what if you disappear" an unanswerable question at exactly the moment someone
is deciding whether to trust it.

**Free, and deliberately so.** A paywall on getting your own data out would make
every other promise in this product conditional on a subscription.

## What it is

A single JSON document: the state blob as stored, plus every row keyed to the
product — evidence, vulnerabilities, incidents, obligations, advisory candidates
and scans, attestations, the audit trail, and the statutory-export ledger. Not a
summary and not a rendering. The technical file is a *derived* view and
`assemble_technical_file` already produces it; this is the material it derives
from, which is what someone rebuilding elsewhere actually needs.

Columns are read from the table rather than listed here. A hand-written field
list silently stops exporting whatever is added next, and an export that quietly
omits a column is worse than no export — the recipient cannot tell.

## Evidence bodies, and why they are optional

Evidence is stored by value: an SBOM, a scan report, a frozen technical file
all live in `inline_body`, bounded at 4 MiB each and 100 MiB per product. Over
MCP a tool result travels through the model's context, so returning a hundred
megabytes of base64 would not be a large response — it would be an incident.

So `include_bodies` defaults to false over the wire, and the response states the
byte count it left out rather than letting a lighter document pass for a
complete one. The console download sets it true and streams the whole thing,
which is what a browser is for.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import select

from cra.agents import dispatch as _dispatch
from cra.db import (
    AdvisoryCandidate,
    AdvisoryScan,
    Attestation,
    AuditEvent,
    Evidence,
    Incident,
    ReportingObligation,
    StatutoryExport,
    Vulnerability,
    session_scope,
)
from cra.server.scoping import _load, _member

# Format identifier and version, in the document. Anyone reading an export in
# five years needs to know what shape they are holding, and a version that
# only exists in a changelog is one they will not find.
FORMAT = "cra-mcp/product-export"
FORMAT_VERSION = 1

# Ordered so a reader meets the product before its history.
_TABLES = (
    ("evidence", Evidence),
    ("vulnerabilities", Vulnerability),
    ("incidents", Incident),
    ("reporting_obligations", ReportingObligation),
    ("advisory_candidates", AdvisoryCandidate),
    ("advisory_scans", AdvisoryScan),
    ("attestations", Attestation),
    ("statutory_exports", StatutoryExport),
    ("audit_events", AuditEvent),
)


def _scalar(v):
    """JSON-safe, without inventing anything.

    Datetimes go out as ISO 8601 with their offset, which is what every other
    surface here emits. Anything already JSON-native — the JSONB payloads — is
    passed through untouched rather than re-encoded.
    """
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, Decimal):
        return float(v)
    return v


def _row(obj, *, skip: tuple[str, ...] = ()) -> dict:
    return {
        c.name: _scalar(getattr(obj, c.name))
        for c in obj.__table__.columns
        if c.name not in skip
    }


def export_product(
    *,
    product_id: str,
    actor_id: str = "",
    include_bodies: bool = False,
) -> dict:
    """Everything held about this product, as one JSON document."""
    state = _load(product_id)
    # Viewer level, matching every other read. Stricter would be theatre:
    # each part of this is already reachable one tool at a time by anyone who
    # can see the product, and a gate that only slows down the convenient
    # version protects nothing.
    _member(state, actor_id)

    out: dict = {
        "ok": True,
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "product_id": product_id,
        # The blob exactly as stored, not a view of it. `mode="json"` is what
        # makes the datetimes and enums serialisable without a second pass.
        "state": state.model_dump(mode="json"),
    }

    omitted_bytes = 0
    counts: dict[str, int] = {}
    with session_scope() as db:
        for key, model in _TABLES:
            rows = list(
                db.execute(
                    select(model).where(model.product_id == product_id)
                ).scalars()
            )
            counts[key] = len(rows)
            if key == "evidence" and not include_bodies:
                omitted_bytes = sum(len(r.inline_body or "") for r in rows)
                out[key] = [_row(r, skip=("inline_body",)) for r in rows]
            else:
                out[key] = [_row(r) for r in rows]

    out["counts"] = counts
    out["note"] = (
        "Everything this service holds about the product: the compliance state "
        "as stored, and every row keyed to it. The Annex VII technical file is "
        "derived from this rather than contained in it — assemble_technical_"
        "file() renders that view."
    )
    if not include_bodies:
        # Stated as a fact with a number, not left for the reader to notice.
        # A partial export that reads as a complete one is the failure this
        # whole document exists to avoid.
        out["bodies_omitted"] = {
            "reason": (
                "Evidence is stored by value and can run to a hundred "
                "megabytes per product, which would not fit in an agent's "
                "context. The hash, size, filename and provenance of every "
                "artefact are included; the bytes are not."
            ),
            "bytes": omitted_bytes,
            "how_to_get_them": (
                "Download the complete archive from the console: "
                "/app/p/<product_id>/export.json — signed in, in a browser, "
                "where a large file is a download rather than a message."
            ),
        }
    return out


_dispatch.register_read("export_product", export_product)
