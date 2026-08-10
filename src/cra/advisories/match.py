"""Turn two feeds and an SBOM into findings — and be honest about what a
finding is.

Pure: takes already-fetched data, returns dataclasses, touches no network and
no database. That is what makes the interesting behaviour testable without
either.

The output is a `Finding`, never a vulnerability record. The distinction is the
whole design. A match says "an advisory exists for a version string that appears
in your SBOM". It does not say the vulnerable code path is reachable, that the
component ships in the artifact you place on the market, or that your fork has
not already patched it. Those are judgements only the manufacturer can make, and
under Article 14 recording the answer starts a 24-hour clock — so the tool
proposes and a person disposes, exactly as with the risk assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """One advisory affecting one component of one product."""

    advisory_id: str                  # GHSA-… or CVE-…
    component_name: str
    component_version: str
    component_ecosystem: str
    component_purl: Optional[str] = None

    cve_ids: list[str] = field(default_factory=list)
    summary: str = ""
    severity: Optional[str] = None

    # The bit that decides whether this is a reporting question or a backlog
    # question.
    exploited: bool = False
    kev_cve_id: Optional[str] = None
    kev_date_added: Optional[str] = None
    kev_ransomware: Optional[str] = None

    # EPSS. `None` means the model has not scored this CVE — never that the
    # score is low. Nothing in this module may substitute a number for absence.
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_cve_id: Optional[str] = None

    def key(self) -> tuple[str, str, str]:
        """Stable identity, so a nightly rescan re-finds rather than re-raises."""
        return (self.advisory_id, self.component_name, self.component_version)

    def rank(self) -> tuple:
        """Queue order: statutory duty first, then likelihood, then stable.

        Exploited always outranks everything, whatever EPSS says. A KEV listing
        is observed exploitation carrying a 24-hour clock; EPSS is a prediction.
        Letting a 0.97 prediction outrank a confirmed listing would put a
        backlog item above a reporting duty.

        Unscored CVEs sort *after* scored ones rather than at the bottom as
        though they were zero — see `feeds.epss_scores`.
        """
        pct = self.epss_percentile
        return (not self.exploited, -(pct if pct is not None else -1.0), self.advisory_id)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    components_checked: int = 0
    coverage_note: Optional[str] = None

    # Never inferred from an empty finding list. A failed fetch and a clean
    # product produce the same zero, and only one of them is good news.
    sources_ok: bool = False
    kev_ok: bool = False
    osv_ok: bool = False

    # EPSS is deliberately not part of `sources_ok`. KEV and OSV answer "is
    # there a finding at all"; without them the scan did not happen. EPSS only
    # orders findings that already exist, so losing it degrades the queue
    # rather than invalidating the result — and treating it as fatal would mean
    # a scoring outage suppressed a KEV hit.
    epss_ok: bool = False
    epss_model_version: Optional[str] = None
    epss_score_date: Optional[str] = None

    @property
    def exploited(self) -> list[Finding]:
        return [f for f in self.findings if f.exploited]

    def summary_line(self) -> str:
        """Two duties, and they are not the same set.

        The CRA defines both terms separately, and conflating them is the
        easiest mistake to make here:

          Art 3(41) *exploitable* — "has the potential to be effectively used
          by an adversary under practical operational conditions". Annex I
          Pt I(2)(a) bars placing a product on the market with a known one.

          Art 3(42) *actively exploited* — "reliable evidence that a malicious
          actor has exploited it in a system without permission". Article 14's
          reporting clocks run on this.

        CISA KEV is the second. Every other match is a *candidate* for the
        first — broader, and a release question rather than a reporting one.
        Reporting "none actively exploited" as though it were a clean result
        would answer the reporting question and silently drop the other.
        """
        if not self.sources_ok:
            return (
                "Scan incomplete — an advisory source could not be reached. "
                "This is not a clean result; nothing was ruled out."
            )
        if not self.findings:
            return (
                f"No advisories matched the {self.components_checked} components "
                "checked. That is not a statement that the product is "
                "unaffected — only that these feeds know of nothing today."
            )
        n_exp = len(self.exploited)
        n_other = len(self.findings) - n_exp
        base = (
            f"{len(self.findings)} advisory match(es) across "
            f"{self.components_checked} components"
        )
        parts = [base + "."]
        if n_exp:
            parts.append(
                f"{n_exp} CISA lists as actively exploited (Art 3(42)) — those "
                "carry a potential Article 14 reporting duty and a 24-hour clock."
            )
        if n_other:
            parts.append(
                f"{n_other} {'is' if n_other == 1 else 'are'} not known to be "
                "actively exploited, which is NOT the same as not exploitable. "
                "Annex I Pt I(2)(a) bars placing a product on the market with a "
                "known exploitable vulnerability (Art 3(41): potential to be "
                "effectively used under practical operational conditions), "
                "whether or not anyone has used it yet. Each needs an "
                "exploitability determination, not a backlog slot."
            )
        return " ".join(parts)


def build_findings(
    *,
    parsed,
    osv_result,
    kev,
    advisory_details: dict,
    epss: Optional[dict] = None,
    epss_catalogue=None,
) -> ScanResult:
    """Join components → advisories → exploitation status → likelihood.

    `advisory_details` maps advisory id to its OSV record, fetched by the
    caller so this stays pure and so details are only pulled for ids that
    actually matched something. `epss` maps CVE id to an `EpssScore` and is
    sparse: a CVE the model has not scored is simply absent.
    """
    epss = epss or {}
    by_key = {c.key(): c for c in parsed.components}
    findings: list[Finding] = []

    for comp_key, advisory_ids in sorted(osv_result.by_component.items()):
        comp = by_key.get(comp_key)
        if comp is None:
            continue
        for advisory_id in advisory_ids:
            detail = advisory_details.get(advisory_id) or {}
            cves = _cve_ids(advisory_id, detail)

            kev_hit = next((c for c in cves if c in kev), None)
            kev_entry = kev.get(kev_hit) if kev_hit else None
            top = _worst_epss(cves, epss)

            findings.append(
                Finding(
                    advisory_id=advisory_id,
                    component_name=comp.name,
                    component_version=comp.version,
                    component_ecosystem=comp.ecosystem,
                    component_purl=comp.purl,
                    cve_ids=cves,
                    summary=(detail.get("summary") or detail.get("details") or "")[:500],
                    severity=_severity(detail),
                    exploited=kev_entry is not None,
                    kev_cve_id=kev_hit,
                    kev_date_added=(kev_entry or {}).get("date_added"),
                    kev_ransomware=(kev_entry or {}).get("ransomware"),
                    epss_probability=top.probability if top else None,
                    epss_percentile=top.percentile if top else None,
                    epss_cve_id=top.cve_id if top else None,
                )
            )

    # Exploited first: on a list of forty, the three that carry a statutory
    # clock must not be somewhere in the middle. Then most-likely-first, so the
    # rest of the list is worked in an order that means something.
    findings.sort(key=lambda f: f.rank())

    return ScanResult(
        findings=findings,
        components_checked=len(parsed.components),
        coverage_note=parsed.coverage_note,
        sources_ok=kev.ok and osv_result.ok,
        kev_ok=kev.ok,
        osv_ok=osv_result.ok,
        epss_ok=bool(getattr(epss_catalogue, "ok", False)),
        epss_model_version=getattr(epss_catalogue, "model_version", None),
        epss_score_date=getattr(epss_catalogue, "score_date", None),
    )


def _worst_epss(cve_ids: list[str], epss: dict):
    """The highest-percentile score among an advisory's CVE aliases.

    One GHSA can alias several CVEs, and they can score differently. Taking the
    highest is the direction that errs toward a human looking: the alternative
    is an advisory sinking down the queue because one of its aliases happens to
    be unremarkable.
    """
    scored = [epss[c] for c in cve_ids if c in epss]
    return max(scored, key=lambda s: s.percentile) if scored else None


def _cve_ids(advisory_id: str, detail: dict) -> list[str]:
    ids = {advisory_id.upper()} | {
        str(a).upper() for a in (detail.get("aliases") or [])
    }
    return sorted(i for i in ids if i.startswith("CVE-"))


def _severity(detail: dict) -> Optional[str]:
    """Best available severity label, without inventing one.

    OSV carries CVSS vectors in `severity` and a coarse label in
    `database_specific`. Neither is guaranteed, and a fabricated score on a
    compliance record is worse than a blank.
    """
    for sev in detail.get("severity") or []:
        if sev.get("score"):
            return str(sev["score"])
    ds = detail.get("database_specific") or {}
    if ds.get("severity"):
        return str(ds["severity"])
    return None
