"""Is the text we cite still in force?

Ported from Coauthor's `good_law.py` (`origin/feature/reference-validation`),
keeping the EU half and dropping the US citator, CourtListener and LLM
machinery entirely. What survives is the part that was always the strongest:
EUR-Lex publishes **ELI structured metadata** in the page head, so in-force
status is an authoritative near-free lookup rather than a judgement call.

Why a compliance tool wants this. The requirement catalogue is anchored to
CELEX identifiers, and the CRA will be amended — delegated acts under Article
7(4) can move products between Annex III classes, and corrigenda happen. A
catalogue frozen at build time goes quietly stale; one that can ask "is
32024R2847 still in force, and has anything I cite been repealed" degrades
loudly instead.

Three properties carried over deliberately:

**Stdlib only.** `urllib` + `re`, no new dependency for a call that runs at
most daily.

**Fails soft to `unknown`.** Nothing here raises into a caller. A tool call
must not fail because EUR-Lex is slow, and — more to the point — an offline
server must not report a regulation as repealed.

**Cached with a status-dependent TTL.** Each lookup pulls ~40KB of HTML, so
caching is a correctness requirement on the hot path, not an optimisation.
Repeals are effectively permanent and cached for a year; an in-force answer
decays in weeks because that is the one that can change under you.
"""

from __future__ import annotations

import html as _html
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# Bump to invalidate every cached record after a parser change.
ANALYSIS_VERSION = 1

STATUS_IN_FORCE = "in_force"
STATUS_NOT_IN_FORCE = "not_in_force"
STATUS_UNKNOWN = "unknown"

EURLEX_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:{celex}"

# The CRA itself. Every catalogue entry anchors here unless it cites something
# else.
CRA_CELEX = "32024R2847"


def _timeout() -> int:
    return int(os.environ.get("CRA_EURLEX_TIMEOUT", "15"))


def _ttl(status: str) -> int:
    """Seconds a status stays fresh.

    Asymmetric on purpose. A repeal does not un-happen, so caching it for a
    year is safe. "In force" is the answer that can be falsified tomorrow, so
    it decays in weeks — the direction of the asymmetry matters more than the
    numbers.
    """
    if status == STATUS_NOT_IN_FORCE:
        return int(os.environ.get("CRA_EURLEX_TTL_REPEALED", str(365 * 24 * 3600)))
    if status == STATUS_IN_FORCE:
        return int(os.environ.get("CRA_EURLEX_TTL_IN_FORCE", str(30 * 24 * 3600)))
    # Don't cache ignorance for long: `unknown` usually means the network was
    # down, and the next call should try again rather than inherit the outage.
    return int(os.environ.get("CRA_EURLEX_TTL_UNKNOWN", str(3600)))


@dataclass(frozen=True)
class Status:
    celex: str
    status: str
    detail: str = ""
    url: str = ""
    checked_at: Optional[str] = None
    analysis_version: int = ANALYSIS_VERSION
    _expires_at: float = field(default=0.0, compare=False)

    @property
    def is_fresh(self) -> bool:
        return (
            self.analysis_version == ANALYSIS_VERSION
            and self._expires_at > time.time()
        )

    def as_dict(self) -> dict:
        return {
            "celex": self.celex,
            "status": self.status,
            "detail": self.detail,
            "url": self.url,
            "checked_at": self.checked_at,
        }


_CACHE: dict[str, Status] = {}


def clear_cache() -> None:
    _CACHE.clear()


def parse_status(head: str) -> tuple[str, str]:
    """Pure mapping of EUR-Lex page HTML → (status, detail).

    The primary signal is the ELI metadata near the top of the head, which is
    machine-readable and authoritative. The human-readable status text is only
    a fallback, and there the **negative phrase is tested first**: "in force"
    is a substring of "no longer in force", so the obvious ordering reports
    every repealed instrument as current.
    """
    m = re.search(r'eli:in_force"[^>]*resource="[^"]*InForce-(inForce|notInForce)"', head)
    if m:
        if m.group(1) == "inForce":
            return STATUS_IN_FORCE, "In force (EUR-Lex ELI metadata)."
        d = re.search(r'eli:date_no_longer_in_force"[^>]*content="([0-9-]+)"', head)
        detail = "No longer in force"
        if d:
            detail += f" (end of validity {d.group(1)})"
        return STATUS_NOT_IN_FORCE, detail + " — repealed or expired; see EUR-Lex."

    low = head.lower()
    if "no longer in force" in low:  # must precede the "in force" test
        d = re.search(r"end of validity:\s*([0-9]{2}/[0-9]{2}/[0-9]{4})", head, re.I)
        detail = "No longer in force"
        if d:
            detail += f" (end of validity {d.group(1)})"
        return STATUS_NOT_IN_FORCE, detail + " — repealed or expired; see EUR-Lex."
    if "in force" in low:
        return STATUS_IN_FORCE, "In force (EUR-Lex status text)."
    return STATUS_UNKNOWN, ""


def _fetch(celex: str) -> tuple[str, str]:
    url = EURLEX_URL.format(celex=celex)
    req = urllib.request.Request(url, headers={"User-Agent": "cra-mcp"})
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            if resp.status != 200:
                return STATUS_UNKNOWN, f"EUR-Lex returned HTTP {resp.status}."
            head = _html.unescape(resp.read(40_000).decode("utf-8", "ignore"))
    except (urllib.error.URLError, OSError, ValueError) as e:  # noqa: BLE001
        # Never raise into a tool call. An offline server reporting a
        # regulation as repealed would be far worse than one saying it does
        # not know.
        log.warning("EUR-Lex lookup failed for %s: %s", celex, e)
        return STATUS_UNKNOWN, f"Could not reach EUR-Lex: {e}"
    return parse_status(head)


def normalise_celex(celex: str) -> str:
    return (celex or "").strip().upper().replace(" ", "")


def in_force(celex: str = CRA_CELEX, *, refresh: bool = False) -> Status:
    """In-force status for a CELEX identifier. Never raises."""
    celex = normalise_celex(celex)
    if not celex:
        return Status(celex="", status=STATUS_UNKNOWN, detail="No CELEX supplied.")

    cached = _CACHE.get(celex)
    if cached is not None and cached.is_fresh and not refresh:
        return cached

    status, detail = _fetch(celex)
    record = Status(
        celex=celex,
        status=status,
        detail=detail,
        url=EURLEX_URL.format(celex=celex),
        checked_at=datetime.now(timezone.utc).isoformat(),
        _expires_at=time.time() + _ttl(status),
    )
    _CACHE[celex] = record
    return record


def citation_url(celex: str, *, article: Optional[str] = None) -> str:
    """A link a human can follow to the text a requirement is anchored to.

    Article-level deep links are not attempted. ELI supports sub-document
    addressing, but a link that silently lands on the whole regulation while
    claiming to point at Annex I Pt I(2)(b) is worse than an honest one to the
    document — the reader would believe they had checked something they had
    not.
    """
    url = EURLEX_URL.format(celex=normalise_celex(celex))
    return f"{url}#{article}" if article else url
