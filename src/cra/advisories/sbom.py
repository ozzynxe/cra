"""Read a stored SBOM back into a component list.

`record_sbom` keeps the document by value in `evidence.inline_body`, which is
what makes any of this possible: the component inventory is already on the
server, so nothing has to be re-uploaded or re-generated to check it against an
advisory feed.

Both formats Annex I Pt II(1) is satisfied by are handled — CycloneDX and SPDX —
because a manufacturer picks one and the checker should not be the reason they
have to pick the other.

Parsing is deliberately forgiving. A component with no version cannot be matched
against a version range, and a component with no recognisable ecosystem cannot
be looked up at all; both are dropped from the query and *counted*, because
"we checked 40 of your 260 components" and "we checked your SBOM" are very
different claims and the second one must never be made on the first one's
evidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

# purl type → OSV ecosystem. OSV keys advisories by ecosystem name, and the
# mapping is not identity: purl says "golang", OSV says "Go".
_PURL_TO_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "conan": "ConanCenter",
    "swift": "SwiftURL",
    "deb": "Debian",
    "apk": "Alpine",
    "rpm": "Red Hat",
}


@dataclass(frozen=True)
class Component:
    """One dependency, in the terms OSV can be asked about."""

    name: str
    version: str
    ecosystem: str
    purl: Optional[str] = None

    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass(frozen=True)
class ParsedSbom:
    components: tuple[Component, ...]
    total_entries: int
    skipped_no_version: int
    skipped_unknown_ecosystem: int
    format: str

    @property
    def coverage_note(self) -> str:
        """What could and could not be checked, in words. Never None.

        It used to return None when nothing was skipped, and `scan_advisories`
        tells its caller to read this field. Null then carried two meanings —
        "everything was covered" and "this was not worked out" — with no way to
        tell them apart, so an agent reading null as full coverage was right by
        luck rather than by construction. A field the description says to read
        has to say something.
        """
        missed = self.skipped_no_version + self.skipped_unknown_ecosystem
        if not missed:
            return (
                f"All {self.total_entries} components in the bill of materials "
                "could be checked: each carries a version and an ecosystem the "
                "advisory database covers."
            )
        parts = []
        if self.skipped_no_version:
            parts.append(f"{self.skipped_no_version} without a version")
        if self.skipped_unknown_ecosystem:
            parts.append(
                f"{self.skipped_unknown_ecosystem} in an ecosystem the advisory "
                "database does not cover"
            )
        return (
            f"{len(self.components)} of {self.total_entries} components could be "
            f"checked — {', and '.join(parts)}. Nothing is known about the rest, "
            "which is not the same as them being unaffected."
        )


_PURL_RE = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?P<ns_name>[^@?#]+)(?:@(?P<version>[^?#]+))?"
)


def parse_purl(purl: str) -> Optional[Component]:
    """`pkg:npm/@scope/name@1.2.3` → a Component, or None if unusable."""
    m = _PURL_RE.match((purl or "").strip())
    if not m:
        return None
    ptype = m.group("type").lower()
    ecosystem = _PURL_TO_OSV.get(ptype)
    if ecosystem is None:
        return None
    name = m.group("ns_name")
    version = (m.group("version") or "").strip()
    if not version:
        return None
    # Maven uses group:artifact; the purl spells it namespace/artifact.
    if ecosystem == "Maven" and "/" in name:
        name = name.replace("/", ":", 1)
    from urllib.parse import unquote

    return Component(
        name=unquote(name), version=unquote(version), ecosystem=ecosystem, purl=purl
    )


def parse(document: str) -> ParsedSbom:
    """Parse a CycloneDX or SPDX JSON SBOM into components OSV can be asked about."""
    try:
        doc = json.loads(document)
    except (ValueError, TypeError):
        return ParsedSbom((), 0, 0, 0, "unparseable")
    if not isinstance(doc, dict):
        return ParsedSbom((), 0, 0, 0, "unparseable")

    if "bomFormat" in doc or "components" in doc:
        entries, fmt = doc.get("components") or [], "cyclonedx"
        purl_of = lambda c: c.get("purl")  # noqa: E731
    elif "packages" in doc or "spdxVersion" in doc:
        entries, fmt = doc.get("packages") or [], "spdx"

        def purl_of(pkg):  # SPDX hides the purl in externalRefs
            for ref in pkg.get("externalRefs") or []:
                if ref.get("referenceType") == "purl":
                    return ref.get("referenceLocator")
            return None
    else:
        return ParsedSbom((), 0, 0, 0, "unrecognised")

    seen: dict[tuple[str, str, str], Component] = {}
    no_version = unknown_eco = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        purl = purl_of(entry)
        if not purl:
            unknown_eco += 1
            continue
        comp = parse_purl(purl)
        if comp is None:
            # Distinguish the two reasons, because they mean different things to
            # someone reading the coverage note.
            m = _PURL_RE.match(purl.strip())
            if m and not (m.group("version") or "").strip():
                no_version += 1
            else:
                unknown_eco += 1
            continue
        seen.setdefault(comp.key(), comp)

    return ParsedSbom(
        components=tuple(seen.values()),
        total_entries=len(entries),
        skipped_no_version=no_version,
        skipped_unknown_ecosystem=unknown_eco,
        format=fmt,
    )
