"""The ENISA SRP reporting template, as a resolvable field catalogue.

ENISA's Q16 is not a document template — it is a table of fields with a marker
per reporting stage. So drafting a report is not rendering prose into a form;
it is resolving that catalogue against a stage and the facts already recorded.

Three of ENISA's five markers are behavioural requirements rather than
annotations, and they are the reason this module exists:

**`C` — copied from the previous step.** A stage's draft must arrive
pre-populated from the previous submission, with the user editing deltas. At
hour 70 of a 72-hour clock, retyping the early warning is how a notification
gets filed late.

**`A` — automated, not visible to the submitter.** These are never collected
and never rendered. Emitting a value for a field the platform computes is
worse than leaving it out: it invites the user to reconcile our number against
ENISA's, and they will assume ours is the one that matters.

**`I` — obligatory if the information is available.** The regulator's own
"send what you know, then follow up" posture, encoded in the schema. A missing
`I` field is never a blocker; a missing `X` field always is. Collapsing the two
would make the 24-hour draft refuse to emit, which is the one thing it must
never do.

The catalogue is data (`v1.yaml`), not code. ENISA calls the fields provisional
and the platform is not yet live, so a change is a new version file rather than
an edit — a draft records the version it was produced under, because the
technical file is retained ten years and a 2036 auditor has to know which
template a 2026 report was written against.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from cra.schemas.enums import IncidentKind, ReportStage

_DIR = Path(__file__).parent
DEFAULT_VERSION = "v1"

# ENISA's stage columns, in table order.
STAGE_ORDER: tuple[ReportStage, ...] = (
    ReportStage.EARLY_WARNING,
    ReportStage.NOTIFICATION,
    ReportStage.FINAL,
)

# Which ENISA stream a CRA incident kind reports under. Both share the common
# fields; they diverge below row 12.
STREAM_FOR_KIND: dict[IncidentKind, str] = {
    IncidentKind.ACTIVELY_EXPLOITED_VULN: "vulnerability",
    IncidentKind.SEVERE_INCIDENT: "incident",
}


class Marker(str, Enum):
    OBLIGATORY = "X"
    OPTIONAL = "O"
    COPIED = "C"
    AUTOMATED = "A"
    IF_AVAILABLE = "I"


class Disposition(str, Enum):
    """What the drafter should do with a field at a given stage."""

    REQUIRED = "required"        # X — must be filled; a gap blocks
    OPTIONAL = "optional"        # O — offer it, never chase it
    CARRY_FORWARD = "carry_forward"  # C — prefill from the previous stage
    IF_AVAILABLE = "if_available"    # I — include if known, never block
    PLATFORM = "platform"        # A — the SRP fills this; do not collect
    GUIDANCE = "guidance"        # no marker — explanatory text beside a field


_DISPOSITION = {
    Marker.OBLIGATORY: Disposition.REQUIRED,
    Marker.OPTIONAL: Disposition.OPTIONAL,
    Marker.COPIED: Disposition.CARRY_FORWARD,
    Marker.IF_AVAILABLE: Disposition.IF_AVAILABLE,
    Marker.AUTOMATED: Disposition.PLATFORM,
}


@dataclass(frozen=True)
class Field:
    id: str
    stream: str
    label: str
    markers: tuple[Optional[Marker], ...]
    parent: bool = False
    parent_id: Optional[str] = None
    guidance_only: bool = False
    note: str = ""

    def marker_at(self, stage: ReportStage | str) -> Optional[Marker]:
        return self.markers[STAGE_ORDER.index(ReportStage(stage))]

    def disposition_at(self, stage: ReportStage | str) -> Disposition:
        marker = self.marker_at(stage)
        if marker is None:
            return Disposition.GUIDANCE
        return _DISPOSITION[marker]


@dataclass(frozen=True)
class Template:
    version: str
    source: str
    published: str
    provisional: bool
    fields: tuple[Field, ...]

    def by_id(self, field_id: str) -> Field:
        for f in self.fields:
            if f.id == field_id:
                return f
        raise KeyError(field_id)

    def for_stream(self, stream: str) -> tuple[Field, ...]:
        """Common fields plus one stream's, in ENISA's table order."""
        return tuple(f for f in self.fields if f.stream in ("common", stream))

    def for_kind(self, kind: IncidentKind | str) -> tuple[Field, ...]:
        return self.for_stream(STREAM_FOR_KIND[IncidentKind(kind)])


def available_versions() -> list[str]:
    return sorted(p.stem for p in _DIR.glob("v*.yaml"))


@functools.lru_cache(maxsize=None)
def load(version: str = DEFAULT_VERSION) -> Template:
    path = _DIR / f"{version}.yaml"
    if not path.exists():
        raise KeyError(
            f"unknown template version {version!r}; have {available_versions()}"
        )
    raw = yaml.safe_load(path.read_text())
    fields = tuple(
        Field(
            id=str(f["id"]),
            stream=f["stream"],
            label=f["label"],
            markers=tuple(Marker(m) if m else None for m in f["stages"]),
            parent=bool(f.get("parent", False)),
            parent_id=f.get("parent_id"),
            guidance_only=bool(f.get("guidance_only", False)),
            note=f.get("note", "") or "",
        )
        for f in raw["fields"]
    )
    return Template(
        version=raw["version"],
        source=raw["source"],
        published=raw["published"],
        provisional=bool(raw.get("provisional", True)),
        fields=fields,
    )


@dataclass(frozen=True)
class ResolvedField:
    field: Field
    disposition: Disposition
    value: Optional[str]
    carried_from_previous: bool

    @property
    def is_gap(self) -> bool:
        """Missing and someone is waiting for it.

        `IF_AVAILABLE` is deliberately not a gap: ENISA's `I` means "obligatory
        if such information is available", so absence is an answer.
        """
        return self.disposition is Disposition.REQUIRED and not self.value


def resolve(
    kind: IncidentKind | str,
    stage: ReportStage | str,
    *,
    known: Optional[dict[str, str]] = None,
    previous: Optional[dict[str, str]] = None,
    fallback: Optional[dict[str, str]] = None,
    version: str = DEFAULT_VERSION,
) -> list[ResolvedField]:
    """Work out, field by field, what this stage's draft should contain.

    Three tiers, in precedence order:

    `known` — authoritative facts: what the caller supplied this time, and
    structured values off the record (product name, CVE id, the date a fix
    shipped). These beat a carried value, because a `C` field is "copied by
    default, **or updated**" and correcting the record is how you correct them.

    `previous` — the last drafted stage's payload. This is where prose lives:
    the narrative a human typed at hour 70 has no other home, so it must
    outrank anything we could re-derive.

    `fallback` — a seed the record can offer when nobody has written the field
    yet, typically the one-line description captured when the incident was
    opened. Lowest precedence by design: it is a starting point, and once a
    person has improved on it, reverting would lose their work silently.

    Platform-automated fields are dropped entirely rather than returned empty.
    """
    known = known or {}
    previous = previous or {}
    fallback = fallback or {}
    out: list[ResolvedField] = []

    for field in load(version).for_kind(kind):
        disposition = field.disposition_at(stage)
        if disposition is Disposition.PLATFORM:
            continue

        value = known.get(field.id)
        carried = False
        if not value and disposition is Disposition.CARRY_FORWARD:
            value = previous.get(field.id)
            carried = value is not None
        if not value:
            value = fallback.get(field.id)
        out.append(ResolvedField(field, disposition, value or None, carried))

    return out


def gaps(resolved: list[ResolvedField]) -> list[ResolvedField]:
    return [r for r in resolved if r.is_gap]
