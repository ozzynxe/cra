"""The three outside sources, and the discipline for talking to them.

**CISA KEV** — the Known Exploited Vulnerabilities catalogue. The reason this
exists at all: Article 14's duty turns on a vulnerability being *actively
exploited*, and KEV is the closest thing to a machine-readable, authoritative
statement that exploitation has been observed. Fetched whole (~1.6 MB) and
matched locally, so no component list leaves the host for this half.

**OSV** — which advisories affect which package versions. This half does send
package coordinates to a third party, and that is disclosed in the privacy
policy rather than done quietly. Only name, ecosystem and version go out: never
the SBOM document, which also carries supplier names, hashes, file paths and
whatever else the generator put in it.

**EPSS** — the Exploit Prediction Scoring System: a daily probability that a
CVE will be exploited in the next 30 days, and that probability's percentile
among all scored CVEs. It informs an exploitability judgement and never makes
one; see `epss_scores` for why the distinction is load-bearing rather than
decorative. Fetched whole like KEV, so no CVE list leaves the host — which is
also why the per-CVE `api.first.org` endpoint is *not* used: asking it about
the CVEs in a customer's SBOM would disclose exactly the thing the whole-file
mirror avoids.

Carried over from `regulation/eurlex.py`, deliberately:

**Stdlib only.** `urllib` and `json`. A compliance server should not grow a
dependency to read a JSON file once a day.

**Fails soft, and says so.** Nothing here raises into a caller. But a failed
fetch must never be reported as a clean scan — every result carries whether the
sources were actually reached, because "we checked and found nothing" and "we
could not check" are the same shape and opposite meanings.

**Cached.** KEV changes at most daily and a scan should not re-download it per
product.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Optional

log = logging.getLogger(__name__)

KEV_URL = os.environ.get(
    "CRA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
OSV_BATCH_URL = os.environ.get("CRA_OSV_URL", "https://api.osv.dev/v1/querybatch")
EPSS_URL = os.environ.get(
    "CRA_EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

_UA = "cra-mcp (EU CRA compliance tooling)"
# OSV caps a batch; keep well under it and stay polite.
_OSV_CHUNK = 100


def _timeout() -> int:
    return int(os.environ.get("CRA_ADVISORY_TIMEOUT", "30"))


def _get(url: str, *, data: Optional[bytes] = None) -> Optional[dict]:
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": _UA, **({"Content-Type": "application/json"} if data else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        log.warning("advisory fetch failed for %s: %s", url, e)
        return None


# ---- CISA KEV ----------------------------------------------------------------


@dataclass
class KevCatalogue:
    """CVE ids known to be exploited, with the date CISA said so."""

    entries: dict[str, dict] = field(default_factory=dict)
    fetched_at: float = 0.0
    ok: bool = False

    def __contains__(self, cve_id: str) -> bool:
        return cve_id.upper() in self.entries

    def get(self, cve_id: str) -> Optional[dict]:
        return self.entries.get(cve_id.upper())


_kev_cache = KevCatalogue()


def kev_catalogue(*, force: bool = False) -> KevCatalogue:
    ttl = int(os.environ.get("CRA_KEV_TTL_SECONDS", str(6 * 3600)))
    if not force and _kev_cache.ok and (time.time() - _kev_cache.fetched_at) < ttl:
        return _kev_cache

    payload = _get(KEV_URL)
    if payload is None or not isinstance(payload.get("vulnerabilities"), list):
        # Keep whatever we had. A stale catalogue is far better than an empty
        # one: empty would silently clear every exploitation flag on the next
        # scan and read as good news.
        _kev_cache.ok = _kev_cache.ok and True
        return _kev_cache

    entries = {}
    for v in payload["vulnerabilities"]:
        cve = str(v.get("cveID") or "").upper()
        if cve:
            entries[cve] = {
                "cve_id": cve,
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
                "notes": v.get("notes"),
            }
    _kev_cache.entries = entries
    _kev_cache.fetched_at = time.time()
    _kev_cache.ok = True
    log.info("KEV catalogue refreshed: %d entries", len(entries))
    return _kev_cache


# ---- OSV ---------------------------------------------------------------------


@dataclass
class OsvResult:
    """Advisory ids per component key, plus whether the lookup actually ran."""

    by_component: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)
    ok: bool = False
    queried: int = 0


def osv_query(components: Iterable) -> OsvResult:
    """Ask OSV which advisories affect these exact versions.

    Sends package name, ecosystem and version only. `querybatch` returns
    advisory ids; the details are fetched separately for the few that matter,
    which keeps the common case to one request per hundred components.
    """
    comps = list(components)
    out = OsvResult()
    if not comps:
        out.ok = True
        return out

    all_ok = True
    for i in range(0, len(comps), _OSV_CHUNK):
        chunk = comps[i : i + _OSV_CHUNK]
        body = json.dumps(
            {
                "queries": [
                    {
                        "package": {"name": c.name, "ecosystem": c.ecosystem},
                        "version": c.version,
                    }
                    for c in chunk
                ]
            }
        ).encode()
        payload = _get(OSV_BATCH_URL, data=body)
        if payload is None or not isinstance(payload.get("results"), list):
            all_ok = False
            continue
        results = payload["results"]
        for comp, res in zip(chunk, results):
            ids = [
                str(v.get("id"))
                for v in (res or {}).get("vulns") or []
                if v.get("id")
            ]
            if ids:
                out.by_component[comp.key()] = ids
        out.queried += len(chunk)

    out.ok = all_ok
    return out


@dataclass
class _AdvisoryCache:
    """One advisory record is the same for every customer who matches it.

    Without this, the nightly sweep fetched `/v1/vulns/{id}` once per product
    per advisory. `scan_product` dedupes within one product and then throws the
    result away, so a hundred products shipping the same library re-fetched the
    same handful of records a hundred times, every night, forever. The work
    scaled with `products x advisories` when the distinct advisories are what
    it actually depends on.

    In-memory and per-process on purpose. The duplication being removed happens
    *within* a single nightly pass, which is exactly what an in-memory cache
    captures — a persisted table would add a schema, a migration and a second
    thing to invalidate for the part of the win that barely exists.
    """

    entries: dict[str, dict] = field(default_factory=dict)
    fetched: dict[str, float] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0

    def get(self, advisory_id: str, ttl: int) -> Optional[dict]:
        at = self.fetched.get(advisory_id)
        if at is None or (time.time() - at) >= ttl:
            return None
        return self.entries.get(advisory_id)

    def put(self, advisory_id: str, record: dict, *, cap: int) -> None:
        # Oldest-first eviction. Records are a few KB and the distinct set
        # across all customers is small, so this is a backstop against a
        # long-running process rather than a working constraint.
        if len(self.entries) >= cap:
            for oldest in sorted(self.fetched, key=self.fetched.get)[: max(1, cap // 10)]:
                self.entries.pop(oldest, None)
                self.fetched.pop(oldest, None)
        self.entries[advisory_id] = record
        self.fetched[advisory_id] = time.time()


_advisory_cache = _AdvisoryCache()


def _advisory_ttl() -> int:
    try:
        return max(0, int(os.environ.get("CRA_OSV_ADVISORY_TTL_SECONDS", str(24 * 3600))))
    except ValueError:
        return 24 * 3600


def osv_advisory(advisory_id: str) -> Optional[dict]:
    """Full record for one advisory — summary, severity, and its CVE aliases.

    Cached for a day. An advisory's text, severity and aliases change rarely,
    and a scan that is a few hours behind on the wording of a record it already
    matched is not a scan that missed anything — the *matching* is done against
    KEV and the query result, both of which are refreshed on their own clocks.

    **A failure is never cached.** `_get` returns None on a network error, and
    storing that would turn one blip into a day of missing detail across every
    product — the same trap `kev_catalogue` avoids by keeping a stale catalogue
    rather than accepting an empty one. An unreachable feed has to keep looking
    unreachable, not quietly become an empty answer.
    """
    ttl = _advisory_ttl()
    if ttl:
        hit = _advisory_cache.get(advisory_id, ttl)
        if hit is not None:
            _advisory_cache.hits += 1
            return hit

    record = _get(f"https://api.osv.dev/v1/vulns/{advisory_id}")
    _advisory_cache.misses += 1
    if record is not None and ttl:
        try:
            cap = max(100, int(os.environ.get("CRA_OSV_ADVISORY_CACHE_MAX", "20000")))
        except ValueError:
            cap = 20000
        _advisory_cache.put(advisory_id, record, cap=cap)
    return record


# ---- EPSS --------------------------------------------------------------------


def _raw(url: str) -> Optional[bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            return resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("advisory fetch failed for %s: %s", url, e)
        return None


@dataclass
class EpssScore:
    """One CVE's exploitation probability, and where that sits among all CVEs.

    Both numbers, always. `probability` alone is the number people act on and
    the number that misleads: 0.05 reads as negligible, and on the current
    model CVE-2020-8203 is exactly that — 0.05213 — at the **91.7th
    percentile**. Five percent is unremarkable in isolation and remarkable
    among CVEs, and a queue ordered on probability alone hides that.
    """

    cve_id: str
    probability: float
    percentile: float


@dataclass
class EpssCatalogue:
    """The compressed feed, held as bytes, plus the header's provenance.

    `entries` is deliberately absent. The full file is ~356,000 rows, and a
    dict of them measured 79 MB resident — on a box already running Postgres,
    Caddy and Redis that is not a reasonable thing to hold for a lookup of a
    few dozen CVEs. So the 2.5 MB gzip is what gets cached and
    `scores_for` streams it, at ~1.4 s and 0.3 MB per scan.

    `model_version` and `score_date` come off the file's first line. Both are
    stored on every candidate: EPSS is a model output, it moves when the model
    does, and a score recorded without them cannot be reproduced or explained
    later — which for a number that informed a compliance judgement is the
    difference between evidence and an assertion.
    """

    gz: Optional[bytes] = None
    model_version: Optional[str] = None
    score_date: Optional[str] = None
    fetched_at: float = 0.0
    ok: bool = False


_epss_cache = EpssCatalogue()


def _parse_epss_header(line: str) -> tuple[Optional[str], Optional[str]]:
    """`#model_version:v2026.06.15,score_date:2026-08-07T12:03:11Z`"""
    out: dict[str, str] = {}
    for part in line.lstrip("#").strip().split(","):
        key, _, value = part.partition(":")
        if key.strip() in ("model_version", "score_date"):
            out[key.strip()] = value.strip()
    return out.get("model_version"), out.get("score_date")


def epss_catalogue(*, force: bool = False) -> EpssCatalogue:
    ttl = int(os.environ.get("CRA_EPSS_TTL_SECONDS", str(6 * 3600)))
    if not force and _epss_cache.ok and (time.time() - _epss_cache.fetched_at) < ttl:
        return _epss_cache

    body = _raw(EPSS_URL)
    if not body:
        # Keep whatever we had, exactly as KEV does. An emptied catalogue would
        # turn every score into "unknown" on the next scan, which is not false
        # — but it would silently drop the ordering signal from a queue someone
        # is working, and it would look like the feed had nothing to say.
        return _epss_cache

    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as fh:
            first = fh.readline().decode("utf-8", "replace")
    except (OSError, EOFError) as e:
        log.warning("EPSS feed is not readable gzip: %s", e)
        return _epss_cache

    if not first.startswith("#"):
        log.warning("EPSS feed has no provenance header; refusing it")
        return _epss_cache

    _epss_cache.model_version, _epss_cache.score_date = _parse_epss_header(first)
    _epss_cache.gz = body
    _epss_cache.fetched_at = time.time()
    _epss_cache.ok = True
    log.info(
        "EPSS feed refreshed: %.1f MB, model %s, scored %s",
        len(body) / 1e6,
        _epss_cache.model_version,
        _epss_cache.score_date,
    )
    return _epss_cache


def epss_scores(cve_ids: Iterable[str]) -> dict[str, EpssScore]:
    """Scores for the CVEs asked about — and only those, by omission.

    **A CVE absent from the result has no score. It does not have a low one.**
    The feed simply omits CVEs the model has not scored, so `dict.get` returning
    None is the normal case and not an error. Every caller has to keep those
    apart: defaulting a missing score to 0.0 would sort unscored CVEs to the
    bottom of a queue and read as "assessed, negligible" when the truth is "not
    assessed". That is the absence-of-knowledge-as-knowledge-of-absence trap
    this module already closes in three other places, and it is why this
    returns a sparse dict rather than a score per input.
    """
    wanted = {c.upper() for c in cve_ids}
    if not wanted:
        return {}

    cat = epss_catalogue()
    if not cat.ok or not cat.gz:
        return {}

    out: dict[str, EpssScore] = {}
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(cat.gz)) as fh:
            for line in io.TextIOWrapper(fh, "utf-8", errors="replace"):
                if not line or line[0] == "#" or line.startswith("cve,"):
                    continue
                cve, _, rest = line.partition(",")
                if cve not in wanted:
                    continue
                prob, _, pct = rest.rstrip("\n").partition(",")
                try:
                    out[cve] = EpssScore(cve, float(prob), float(pct))
                except ValueError:
                    continue
                if len(out) == len(wanted):
                    break
    except (OSError, EOFError) as e:
        log.warning("EPSS feed became unreadable mid-stream: %s", e)
        return out

    return out


def cve_aliases(advisory: dict) -> list[str]:
    """CVE ids an advisory is known by.

    KEV is keyed on CVE and OSV frequently answers with a GHSA id, so without
    this the two feeds never meet and every exploitation flag stays false.
    """
    ids = [advisory.get("id", "")] + list(advisory.get("aliases") or [])
    return [i.upper() for i in ids if str(i).upper().startswith("CVE-")]
