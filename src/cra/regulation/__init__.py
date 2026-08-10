"""The regulation catalogue: Annex I requirements and the Annex III/IV classes.

Data, not code — `annex_i.yaml` and `product_classes.yaml` — for the same
reason the SRP template is: the CRA is amendable by delegated act under Article
7(4), and a change should be a data edit with a provenance date, not a
migration.

**The provenance state is part of the contract.** Each catalogue carries a
`source_verified` flag and a date, `provenance()` reports the **oldest**
verification date across all four, and every tool built on this data passes it
through to the caller. A compliance tool that presents unverified paraphrase as
the text of the law is worse than one with no catalogue at all, because the user
stops checking.

Verified means the anchors exist and the paraphrases are faithful as of that
date. It does not make them the text of the law, which is why
`provenance()["caveat"]` is never null in either state, and it says nothing
about amendments since — re-reconcile after any delegated act under Article
7(4), and fetch the text rather than setting the flag by inspection.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from cra.regulation import eurlex

_DIR = Path(__file__).parent


@dataclass(frozen=True)
class Requirement:
    id: str
    part: str
    anchor: str
    summary: str
    evidence_hint: str = ""

    def citation_url(self, celex: str = eurlex.CRA_CELEX) -> str:
        return eurlex.citation_url(celex)


@dataclass(frozen=True)
class UserInfoItem:
    """One Annex II item the product must be accompanied by.

    `conditional` records that the annex itself qualifies the item — "where
    applicable", "if the manufacturer decides". It is a statement about the
    regulation and not permission to skip: ruling one out still takes an
    explicit determination with a justification, the same as Annex I.
    """

    id: str
    anchor: str
    summary: str
    evidence_hint: str = ""
    conditional: bool = False
    condition: str = ""
    also_required_by: str = ""


@dataclass(frozen=True)
class TechnicalFileSlot:
    id: str
    anchor: str
    title: str
    needs: tuple[str, ...]
    optional: bool = False
    auto_from: tuple[str, ...] = ()
    auto_from_part: Optional[str] = None
    satisfied_by: Optional[str] = None
    # Annex VII(3) needs the Article 13(2) assessment itself, not just the
    # checklist derived from it. Data rather than a hardcoded slot id so a
    # catalogue edit can move the requirement without a code change.
    requires_risk_assessment: bool = False
    note: str = ""


@dataclass(frozen=True)
class DoCField:
    id: str
    anchor: str
    title: str
    source: str
    text: str = ""
    from_slot: Optional[str] = None
    required_when_notified_body: bool = False


@dataclass(frozen=True)
class ProductClassSpec:
    id: str
    title: str
    anchor: str
    conformity_route: str
    notified_body_required: bool
    description: str
    categories: tuple[str, ...] = ()


@functools.lru_cache(maxsize=1)
def _annex_i() -> dict:
    return yaml.safe_load((_DIR / "annex_i.yaml").read_text())


@functools.lru_cache(maxsize=1)
def _classes() -> dict:
    return yaml.safe_load((_DIR / "product_classes.yaml").read_text())


@functools.lru_cache(maxsize=1)
def requirements() -> tuple[Requirement, ...]:
    """Every Annex I requirement, Part I then Part II, in published order."""
    out: list[Requirement] = []
    for part in _annex_i()["parts"]:
        for r in part["requirements"]:
            out.append(
                Requirement(
                    id=r["id"],
                    part=part["id"],
                    anchor=r["anchor"],
                    summary=r["summary"].strip(),
                    evidence_hint=(r.get("evidence_hint") or "").strip(),
                )
            )
    return tuple(out)


def requirements_for_part(part: str) -> tuple[Requirement, ...]:
    return tuple(r for r in requirements() if r.part == part)


@functools.lru_cache(maxsize=1)
def _annex_ii() -> dict:
    return yaml.safe_load((_DIR / "annex_ii.yaml").read_text())


@functools.lru_cache(maxsize=1)
def user_information() -> tuple[UserInfoItem, ...]:
    """The Annex II items, in published order.

    Article 13(18) requires the product to be *accompanied by* these. Point 8's
    six sub-points are separate entries — each is a distinct thing a reader has
    to find, the same reasoning that flattens Annex I Pt I(2)(a)-(m).
    """
    return tuple(
        UserInfoItem(
            id=i["id"],
            anchor=i["anchor"],
            summary=i["summary"].strip(),
            evidence_hint=(i.get("evidence_hint") or "").strip(),
            conditional=bool(i.get("conditional")),
            condition=(i.get("condition") or "").strip(),
            also_required_by=(i.get("also_required_by") or "").strip(),
        )
        for i in _annex_ii()["items"]
    )


@functools.lru_cache(maxsize=1)
def _annex_vii() -> dict:
    return yaml.safe_load((_DIR / "annex_vii.yaml").read_text())


@functools.lru_cache(maxsize=1)
def technical_file_slots() -> tuple[TechnicalFileSlot, ...]:
    """The Annex VII sections, in published order.

    A flat list, not a tree. The technical file has exactly these slots, so
    there is nothing to move, split or merge — which is what lets this repo
    omit an entire document-structure subsystem.
    """
    return tuple(
        TechnicalFileSlot(
            id=s["id"],
            anchor=s["anchor"],
            title=s["title"],
            needs=tuple(s.get("needs") or ()),
            optional=bool(s.get("optional", False)),
            auto_from=tuple(s.get("auto_from") or ()),
            auto_from_part=s.get("auto_from_part"),
            satisfied_by=s.get("satisfied_by"),
            requires_risk_assessment=bool(s.get("requires_risk_assessment", False)),
            note=(s.get("note") or "").strip(),
        )
        for s in _annex_vii()["technical_file"]["slots"]
    )


@functools.lru_cache(maxsize=1)
def doc_fields() -> tuple[DoCField, ...]:
    """Annex V — the EU Declaration of Conformity's required content."""
    return tuple(
        DoCField(
            id=f["id"],
            anchor=f["anchor"],
            title=f["title"],
            source=f["source"],
            text=(f.get("text") or "").strip(),
            from_slot=f.get("from_slot"),
            required_when_notified_body=bool(f.get("required_when_notified_body", False)),
        )
        for f in _annex_vii()["declaration_of_conformity"]["fields"]
    )


def technical_file_retention() -> dict:
    """The Article 13(13) rule, not a number.

    Ten years from placing on the market **or the support period, whichever is
    longer**. Callers that have a product compute a date from this with
    `conformity.retention_status`; callers that do not can still state the rule.
    """
    r = dict(_annex_vii()["technical_file"]["retention"])
    r["floor_years"] = int(r["floor_years"])
    return r


@functools.lru_cache(maxsize=1)
def product_classes() -> tuple[ProductClassSpec, ...]:
    return tuple(
        ProductClassSpec(
            id=c["id"],
            title=c["title"],
            anchor=c["anchor"],
            conformity_route=c["conformity_route"],
            notified_body_required=bool(c["notified_body_required"]),
            description=c["description"].strip(),
            categories=tuple(c.get("categories") or ()),
        )
        for c in _classes()["classes"]
    )


def product_class(class_id: str) -> ProductClassSpec:
    for c in product_classes():
        if c.id == class_id:
            return c
    raise KeyError(class_id)


def out_of_scope_hints() -> tuple[dict, ...]:
    return tuple(_classes().get("out_of_scope_hints") or ())


def provenance(*, check_in_force: bool = False) -> dict:
    """What this catalogue is, and how far it can be trusted.

    Returned by every tool that reads the catalogue. `check_in_force` makes a
    network call to EUR-Lex, so it is off by default — no tool should put a
    remote fetch on its hot path, and an offline server must not start
    reporting the CRA as repealed.
    """
    a, c, v, ii = _annex_i(), _classes(), _annex_vii(), _annex_ii()
    # Every catalogue file, so adding one cannot quietly leave its verification
    # state out of the answer every tool reports.
    files = (a, c, v, ii)
    verified = all(bool(f.get("source_verified")) for f in files)
    # The oldest verification date across the set. Reporting the newest would
    # let a freshly transcribed annex make an older one look re-checked.
    verified_at = min(f.get("verified_at") or "" for f in files) or None
    out = {
        "celex": a["celex"],
        "source_verified": verified,
        "verified_at": verified_at,
        "verified_against": a.get("verified_against"),
        "url": eurlex.citation_url(a["celex"]),
        # There is always a caveat. Verification establishes that the anchors
        # point at provisions that exist and that the summaries say what those
        # provisions say — it does not turn a paraphrase into a quotation, and
        # it cannot outlive a delegated act. A `None` here would read as "this
        # is the law", which is the one thing the catalogue must never claim.
        "caveat": (
            (
                f"Reconciled against the published text on {verified_at} (oldest of "
                f"the catalogue files). "
                "The summaries are still paraphrases, not quotations — cite the "
                "link for authoritative wording. Article 7(4) delegated acts can "
                "amend the annexes, so this is true as of that date."
            )
            if verified
            else (
                "This catalogue has not been reconciled against the published "
                "EUR-Lex text by any automated check. Requirement ids and "
                "structure are stable; the summaries are working paraphrases. "
                "Treat it as a checklist, not as a quotation of the law, and "
                "follow the link for authoritative wording."
            )
        ),
        "amendable_by": c.get("amendable_by"),
    }
    if check_in_force:
        out["in_force"] = eurlex.in_force(a["celex"]).as_dict()
    return out
