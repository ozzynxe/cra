"""How large a stored artifact may be, and how much one product may hold.

Extracted rather than left in `annex.py` because `record_sbom` needs it too and
`annex` already imports from `scoping` — the same reason `timestamps.py` exists.

## Why there is a ceiling at all

Evidence is stored **by value**. That is deliberate and it is not negotiable: a
link evidences nothing in ten years, which is how long a technical file is kept.

But storing by value means one tool call writes bytes that are, in practice,
permanent. They go into a Postgres `Text` column, and any of it referenced by a
frozen technical file is copied into an archive under Object Lock, where it
cannot be deleted by ordinary means for at least the ten years Article 13(13)
requires. Nothing in the application expires on its own yet either.

So `attach_evidence` was, until 2026-08-09, the one call in this product where
a single request could commit unbounded storage that nothing could later
reclaim. Not a security problem — a durability one: an irreversible commitment
with no ceiling on it.

## Why these numbers

4 MiB per artifact is far above anything real. A test report, a policy, a scan
output, a signed conclusion are kilobytes; an SBOM for a large product is a few
hundred kilobytes. 100 MiB per product is roughly a thousand honest artifacts.

Both are meant to be invisible. A cap a real user meets is a cap set wrong, so
if either starts firing on genuine work the number is the thing to revisit —
not the discipline of having one.
"""

from __future__ import annotations

import os

from sqlalchemy import func, select

from cra.db import Evidence
from cra.server.errors import InvalidState

_DEFAULT_ARTIFACT = 4 * 1024 * 1024
_DEFAULT_PRODUCT = 100 * 1024 * 1024


def _env_bytes(name: str, default: int) -> int:
    try:
        return max(1024, int(os.environ.get(name, default)))
    except ValueError:
        return default


def max_artifact_bytes() -> int:
    return _env_bytes("CRA_EVIDENCE_MAX_BYTES", _DEFAULT_ARTIFACT)


def max_product_bytes() -> int:
    return _env_bytes("CRA_EVIDENCE_MAX_PRODUCT_BYTES", _DEFAULT_PRODUCT)


def check_artifact_size(size: int, *, what: str = "This artifact") -> None:
    limit = max_artifact_bytes()
    if size > limit:
        raise InvalidState(
            f"{what} is {size / 1048576:.1f} MiB, over the "
            f"{limit / 1048576:.0f} MiB limit for a single stored artifact. "
            "Evidence is stored by value and kept for the statutory period, so "
            "it has to stay a size that can be. Attach the part that actually "
            "evidences the requirement — the findings, the signed conclusion, "
            "the relevant section — with a source_ref pointing at where the "
            "full artifact lives. Splitting it across several attachments works "
            "too; each carries its own hash."
        )


def check_product_total(db, product_id: str, incoming: int) -> None:
    """Call inside the lock.

    A total read before `mutate` takes the row can be stale by the time it is
    acted on, and two concurrent attachments would each see room for one.
    """
    used = (
        db.execute(
            select(func.coalesce(func.sum(Evidence.size_bytes), 0)).where(
                Evidence.product_id == product_id, Evidence.deleted_at.is_(None)
            )
        ).scalar_one()
        or 0
    )
    limit = max_product_bytes()
    if used + incoming > limit:
        raise InvalidState(
            f"this product holds {used / 1048576:.1f} MiB of evidence and this "
            f"artifact would take it past the {limit / 1048576:.0f} MiB limit. "
            "Nothing already stored has been touched. Evidence is kept for the "
            "statutory period, so the total is bounded on purpose — if you are "
            "genuinely near it, that is worth a conversation rather than a "
            "bigger number: cra@skarp.app."
        )
