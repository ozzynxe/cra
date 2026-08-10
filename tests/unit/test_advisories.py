"""SBOM parsing and advisory matching — the pure half, tested without a network.

The assertions that matter here are all variations on one theme: this is the
only part of the system that can *create* awareness of an exploited
vulnerability, and awareness starts a 24-hour statutory clock. So an empty
result must never be able to mean two things, and a match must never be able to
pass itself off as a finding of fact.
"""

from __future__ import annotations

import json

from cra.advisories import parse, parse_purl
from cra.advisories.feeds import KevCatalogue, OsvResult
from cra.advisories.match import build_findings


# ---- purls -------------------------------------------------------------------


def test_a_scoped_npm_purl_round_trips():
    c = parse_purl("pkg:npm/%40scope/pkg@1.2.3")
    assert (c.ecosystem, c.name, c.version) == ("npm", "@scope/pkg", "1.2.3")


def test_purl_types_are_mapped_to_osv_ecosystem_names():
    """Not identity: purl says golang, OSV says Go. Get this wrong and every
    lookup silently returns nothing."""
    assert parse_purl("pkg:golang/github.com/x/y@v1.0.0").ecosystem == "Go"
    assert parse_purl("pkg:pypi/requests@2.31.0").ecosystem == "PyPI"
    assert parse_purl("pkg:cargo/serde@1.0.0").ecosystem == "crates.io"


def test_a_maven_purl_becomes_group_colon_artifact():
    c = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    assert c.name == "org.apache.logging.log4j:log4j-core"


def test_a_versionless_component_is_unusable():
    """A version range cannot be matched against nothing."""
    assert parse_purl("pkg:npm/left-pad") is None


def test_an_unknown_ecosystem_is_unusable():
    assert parse_purl("pkg:weirdthing/foo@1.0") is None
    assert parse_purl("not-a-purl") is None


# ---- SBOM documents ----------------------------------------------------------


def _cyclonedx(*purls, extra=()):
    comps = [{"name": p.split("/")[-1], "purl": p} for p in purls]
    comps.extend(extra)
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": comps})


def test_cyclonedx_components_are_extracted():
    doc = _cyclonedx("pkg:pypi/requests@2.31.0", "pkg:npm/lodash@4.17.20")
    out = parse(doc)
    assert out.format == "cyclonedx"
    assert {(c.ecosystem, c.name) for c in out.components} == {
        ("PyPI", "requests"),
        ("npm", "lodash"),
    }


def test_spdx_purls_are_found_in_external_refs():
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "requests",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}
                    ],
                }
            ],
        }
    )
    out = parse(doc)
    assert out.format == "spdx"
    assert out.components[0].name == "requests"


def test_duplicate_components_collapse():
    doc = _cyclonedx("pkg:pypi/requests@2.31.0", "pkg:pypi/requests@2.31.0")
    assert len(parse(doc).components) == 1


def test_what_could_not_be_checked_is_counted_and_said_out_loud():
    """"We checked your SBOM" and "we checked 1 of your 3 components" are very
    different claims. Only one of them is true here."""
    doc = _cyclonedx(
        "pkg:pypi/requests@2.31.0",
        "pkg:npm/left-pad",              # no version
        "pkg:weirdthing/thing@1.0",      # unknown ecosystem
    )
    out = parse(doc)
    assert len(out.components) == 1
    assert out.skipped_no_version == 1
    assert out.skipped_unknown_ecosystem == 1
    note = out.coverage_note
    assert "1 of 3" in note
    assert "not the same as them being unaffected" in note


def test_a_fully_checkable_sbom_says_so_rather_than_saying_nothing():
    """This returned None, and `scan_advisories` tells its caller to read the
    field. Null carried two meanings — everything was covered, and this was not
    worked out — with no way to tell them apart, so an agent reading null as
    full coverage was right by luck. A field the description says to read has to
    say something."""
    note = parse(_cyclonedx("pkg:pypi/requests@2.31.0")).coverage_note
    assert note is not None
    assert "could be checked" in note


def test_an_uncheckable_component_is_still_named(_=None):
    note = parse(_cyclonedx("pkg:pypi/requests")).coverage_note
    assert "without a version" in note
    assert "not the same as them being unaffected" in note


def test_rubbish_parses_to_nothing_rather_than_raising():
    for doc in ("", "not json", "[]", json.dumps({"unrelated": True})):
        out = parse(doc)
        assert out.components == ()


# ---- matching ----------------------------------------------------------------


def _kev(*cves, ok=True):
    cat = KevCatalogue(ok=ok)
    for c in cves:
        cat.entries[c] = {"cve_id": c, "date_added": "2026-07-01", "ransomware": "Known"}
    return cat


def _osv(parsed, mapping, ok=True):
    res = OsvResult(ok=ok, queried=len(parsed.components))
    by_name = {c.name: c for c in parsed.components}
    for name, ids in mapping.items():
        res.by_component[by_name[name].key()] = ids
    return res


def test_a_kev_listed_advisory_is_flagged_as_exploited():
    parsed = parse(_cyclonedx("pkg:pypi/requests@2.31.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"requests": ["GHSA-xxxx"]}),
        kev=_kev("CVE-2026-1234"),
        advisory_details={"GHSA-xxxx": {"summary": "RCE", "aliases": ["CVE-2026-1234"]}},
    )
    (f,) = result.findings
    assert f.exploited is True
    assert f.kev_cve_id == "CVE-2026-1234"
    assert f.kev_date_added == "2026-07-01"


def test_ghsa_and_kev_are_joined_through_cve_aliases():
    """OSV answers with GHSA ids; KEV is keyed on CVE. Without the alias hop
    the two feeds never meet and nothing is ever flagged exploited."""
    parsed = parse(_cyclonedx("pkg:npm/lodash@4.17.20"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"lodash": ["GHSA-abcd"]}),
        kev=_kev("CVE-2020-8203"),
        advisory_details={"GHSA-abcd": {"aliases": ["CVE-2020-8203"], "summary": "x"}},
    )
    assert result.findings[0].exploited is True


def test_an_advisory_absent_from_kev_is_not_exploited_but_is_still_reported():
    parsed = parse(_cyclonedx("pkg:pypi/requests@2.31.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"requests": ["GHSA-quiet"]}),
        kev=_kev("CVE-2026-9999"),
        advisory_details={"GHSA-quiet": {"aliases": ["CVE-2026-0001"], "summary": "x"}},
    )
    assert result.findings[0].exploited is False
    assert result.exploited == []


def test_exploited_findings_sort_first():
    parsed = parse(_cyclonedx("pkg:pypi/a@1.0", "pkg:pypi/b@1.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"a": ["GHSA-quiet"], "b": ["GHSA-loud"]}),
        kev=_kev("CVE-2026-1234"),
        advisory_details={
            "GHSA-quiet": {"aliases": ["CVE-2026-0001"]},
            "GHSA-loud": {"aliases": ["CVE-2026-1234"]},
        },
    )
    assert result.findings[0].advisory_id == "GHSA-loud"


def test_a_failed_source_is_never_reported_as_a_clean_scan():
    """The assertion this whole module exists to protect. A fetch failure and a
    genuinely clean product produce the same empty list."""
    parsed = parse(_cyclonedx("pkg:pypi/requests@2.31.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {}, ok=False),
        kev=_kev("CVE-2026-1234"),
        advisory_details={},
    )
    assert result.findings == []
    assert result.sources_ok is False
    assert "not a clean result" in result.summary_line()
    assert "nothing was ruled out" in result.summary_line()


def test_a_clean_scan_still_refuses_to_claim_the_product_is_unaffected():
    parsed = parse(_cyclonedx("pkg:pypi/requests@2.31.0"))
    result = build_findings(
        parsed=parsed, osv_result=_osv(parsed, {}), kev=_kev(), advisory_details={}
    )
    assert result.sources_ok is True
    assert "not a statement that the product is unaffected" in result.summary_line()


def test_a_severity_is_never_invented():
    parsed = parse(_cyclonedx("pkg:pypi/requests@2.31.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"requests": ["GHSA-nosev"]}),
        kev=_kev(),
        advisory_details={"GHSA-nosev": {"summary": "no severity here"}},
    )
    assert result.findings[0].severity is None


def test_findings_have_a_stable_identity_so_a_rescan_re_finds():
    parsed = parse(_cyclonedx("pkg:pypi/requests@2.31.0"))
    kwargs = dict(
        parsed=parsed,
        osv_result=_osv(parsed, {"requests": ["GHSA-xxxx"]}),
        kev=_kev("CVE-2026-1234"),
        advisory_details={"GHSA-xxxx": {"aliases": ["CVE-2026-1234"]}},
    )
    assert build_findings(**kwargs).findings[0].key() == build_findings(**kwargs).findings[0].key()


# ---- exploitable is not exploited --------------------------------------------


def test_the_summary_distinguishes_the_two_duties():
    """Art 3(41) exploitable and Art 3(42) actively exploited are separately
    defined, and they drive different obligations: Annex I Pt I(2)(a) bars
    placing on the market, Article 14 starts a 24-hour clock. A summary that
    only names the exploited ones answers one duty and drops the other."""
    parsed = parse(_cyclonedx("pkg:pypi/a@1.0", "pkg:pypi/b@1.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"a": ["GHSA-loud"], "b": ["GHSA-quiet"]}),
        kev=_kev("CVE-2026-1234"),
        advisory_details={
            "GHSA-loud": {"aliases": ["CVE-2026-1234"]},
            "GHSA-quiet": {"aliases": ["CVE-2026-0001"]},
        },
    )
    line = result.summary_line()
    assert "Article 14" in line and "3(42)" in line
    assert "I(2)(a)" in line and "3(41)" in line


def test_no_kev_hits_is_not_described_as_clean():
    """The regression this exists to prevent: 'none actively exploited' read as
    a clean result, when every one of them may still be exploitable."""
    parsed = parse(_cyclonedx("pkg:pypi/a@1.0"))
    result = build_findings(
        parsed=parsed,
        osv_result=_osv(parsed, {"a": ["GHSA-quiet"]}),
        kev=_kev(),
        advisory_details={"GHSA-quiet": {"aliases": ["CVE-2026-0001"]}},
    )
    line = result.summary_line()
    assert result.exploited == []
    assert "NOT the same as not exploitable" in line
    assert "placing a product on the market" in line
    assert "backlog" in line  # ...as the thing it explicitly is not
