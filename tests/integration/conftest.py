"""Shared setup for tests that need a product it is legitimate to release.

`record_release` gates on the record being there, not only on the advisory
scan: no confirmed Article 13(2) assessment, a stale one, missing 13(3)
statements, or unsettled Annex I requirements all block it. That gate is the
reason the retention design does not have to keep working state indefinitely
against the chance it matters later — the check happens at the transition.

Fixtures that want a release in order to test something *else* — evidence
currency, SBOM linking, the support period — therefore need a product that
passes it. `make_releasable` does that through the real tools rather than by
writing state directly, so these fixtures exercise the happy path they depend
on instead of asserting around it.

Deliberately not `accepted_rationale`. Waiving the gate in every fixture would
make the waiver the only path anything tested, and the clean path would rot
unnoticed.
"""

from __future__ import annotations

import pytest

from cra.advisories.feeds import KevCatalogue, OsvResult
from cra.server import advisories


@pytest.fixture
def clean_scan(monkeypatch):
    """Feeds that match nothing: a genuinely clean product.

    Shared because more than one module now needs a release to *succeed* in
    order to test something downstream of it, and a real scan of a real SBOM
    finds real advisories — which is correct behaviour and the wrong fixture.
    """
    kev = KevCatalogue(ok=True)
    monkeypatch.setattr(
        advisories, "osv_query", lambda comps: OsvResult(ok=True, queried=len(list(comps)))
    )
    monkeypatch.setattr(advisories, "kev_catalogue", lambda **kw: kev)
    monkeypatch.setattr(advisories, "osv_advisory", lambda i: {})
    monkeypatch.setattr(
        advisories,
        "epss_catalogue",
        lambda **kw: type("C", (), {"ok": False, "model_version": None, "score_date": None})(),
    )
    monkeypatch.setattr(advisories, "epss_scores", lambda ids: {})
    return kev


@pytest.fixture
def make_releasable():
    """Returns `make(call, product_id, owner)`.

    A fixture rather than an importable function: `tests/integration` is not a
    package and is not on `sys.path`, so `from conftest import ...` fails at
    collection. `call` is threaded in because each module has its own
    dispatcher helper, and a second dispatch path here would be one more thing
    to drift.
    """
    return _make_releasable


def _ok(result, what: str):
    """A fixture that swallows a refusal produces a misleading green."""
    assert result.get("ok") is not False, f"{what} failed during setup: {result}"
    return result


def _make_releasable(call, product_id: str, owner: str) -> None:
    _ok(call(
        "start_risk_assessment",
        product_id,
        owner,
        method="Threat modelling against the intended purpose.",
        intended_purpose="Network gateway on a customer LAN.",
        foreseeable_misuse="Exposed directly to the internet without a firewall.",
        conditions_of_use="Deployed behind a perimeter firewall, admin on loopback.",
        part_i_1_approach=(
            "Delivered without known exploitable vulnerabilities; secure "
            "default configuration reviewed at each release."
        ),
        part_ii_approach=(
            "Coordinated disclosure policy, SBOM maintained, advisories "
            "scanned daily against OSV and CISA KEV."
        ),
    ), "start_risk_assessment")
    # `confirm_risk_assessment` refuses an assessment identifying no risks —
    # "nothing to see here" is the conclusion an auditor tests hardest, so the
    # tool makes you record it as a decided risk rather than an empty list. A
    # fixture has to go through that too.
    _ok(
        call(
            "propose_risks",
            product_id,
            owner,
            basis="fixture: repository at HEAD",
            risks=[
                {
                    "title": "Unauthenticated access to the admin API",
                    "asset": "administrative control plane",
                    "threat": "an unauthenticated caller reconfigures routing",
                    "attack_vector": "admin listener bound to 0.0.0.0",
                    "impact": "full traffic interception",
                }
            ],
        ),
        "propose_risks",
    )
    _ok(
        call(
            "decide_risk",
            product_id,
            owner,
            risk_id="risk-001",
            decision="accept",
            treatment="mitigate",
            rationale="Fixture: bound to loopback and authenticated.",
        ),
        "decide_risk",
    )
    _ok(
        call(
            "confirm_risk_assessment",
            product_id,
            owner,
            rationale="Assessed for the fixture; no risks proposed.",
        ),
        "confirm_risk_assessment",
    )

    # Confirming names nothing, so every requirement is still `undetermined` —
    # which is a gap by design, and exactly what the gate objects to. Ruling
    # each one out with a justification is the shortest honest way to a settled
    # checklist: the tool refuses `not_applicable` on its own, and an auditor
    # reads the justification rather than the flag.
    for item in call("list_requirements", product_id, owner)["requirements"]:
        _ok(
            call(
                "update_requirement",
                product_id,
                owner,
                req_id=item["req_id"],
                applicability="not_applicable",
                justification=(
                    "Fixture product: ruled out for test setup, not a real "
                    "conformity determination."
                ),
            ),
            f"update_requirement({item['req_id']})",
        )


@pytest.fixture
def make_file_freezable():
    """Returns `make(call, product_id, owner)` — fills every mandatory Annex VII
    slot so `assemble_technical_file(finalize=True)` will actually freeze.

    Driven by what the tool reports as missing rather than a hardcoded list, so
    adding a mandatory slot to the catalogue does not silently leave this
    fixture filling the wrong ones.

    `tf.4` is the exception and needs `set_support_period` rather than an
    attachment: Article 13(8) puts the reasoning in the file, so a date alone
    does not complete it and neither does a document stapled to the slot.
    """

    def _make(call, product_id: str, owner: str) -> None:
        _ok(
            call(
                "set_support_period",
                product_id,
                owner,
                end="2036-01-01T00:00:00+00:00",
                rationale="Fixture: ten years, matching expected deployment life.",
            ),
            "set_support_period",
        )
        # tf.1 reports Annex II coverage *as well as* needing its own evidence:
        # Annex VII(1) wants the general description and the software versions,
        # and completing the slot on evidence alone would drop most of it.
        for item in call("list_user_information", product_id, owner).get("items", []):
            _ok(
                call(
                    "update_user_information",
                    product_id,
                    owner,
                    item_id=item["item_id"],
                    provided=True,
                    location="Fixture: shipped with the product documentation.",
                ),
                f"update_user_information({item['item_id']})",
            )

        for _round in range(6):
            out = call("assemble_technical_file", product_id, owner)
            missing = [s["slot"] for s in out.get("missing_slots", [])]
            if not missing:
                return
            for slot in missing:
                if slot == "tf.4":
                    continue
                _ok(
                    call(
                        "attach_evidence",
                        product_id,
                        owner,
                        subject_ref=f"technical_file:{slot}",
                        title=f"Fixture evidence for {slot}",
                        body=f"Fixture artefact for {slot}. Not a real record.",
                        source_ref="git:fixture",
                    ),
                    f"attach_evidence({slot})",
                )
        raise AssertionError(f"could not fill the technical file; still missing {missing}")

    return _make
