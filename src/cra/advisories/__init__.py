"""Proactive detection of exploited vulnerabilities in components you ship.

The rest of this codebase records awareness. This package is the only part that
can *produce* it — and that is a heavier thing than it sounds. Article 14's
clocks run from when a manufacturer becomes aware, so telling someone that a
component they ship carries an actively exploited vulnerability plausibly starts
a 24-hour clock, on the strength of a version-range match that may be wrong.

Hence the shape:

    SBOM (already stored, by value)
      → components with a version and a known ecosystem
      → OSV: which advisories affect these exact versions
      → CISA KEV: which of those are known to be exploited
      → Finding — a candidate, never a record

Nothing here writes a `Vulnerability`, and nothing here opens an `Incident`. A
person confirms a finding and that is what starts the clock, with awareness
anchored on when they were told rather than when they got round to it.

Three failure modes this is built to avoid, all of them the same mistake in
different clothes — reporting an absence of knowledge as knowledge of absence:

  * a fetch that failed must not read as a clean scan (`sources_ok`)
  * components that could not be checked must be counted (`coverage_note`)
  * absence from KEV must not read as "not exploited" — it is high-precision
    and deliberately conservative, so it lags real-world exploitation
"""

from cra.advisories.match import Finding, ScanResult, build_findings
from cra.advisories.sbom import Component, ParsedSbom, parse, parse_purl

__all__ = [
    "Component",
    "Finding",
    "ParsedSbom",
    "ScanResult",
    "build_findings",
    "parse",
    "parse_purl",
]
