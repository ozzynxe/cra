"""The ENISA SRP field catalogue.

Half of this file pins the transcription itself — specific rows, specific
markers. That is unusual for a test suite and deliberate here: `v1.yaml` is
transcribed legal-adjacent data, and a typo in a marker is invisible until it
produces a report that gets rejected or, worse, one that omits an obligatory
field and doesn't say so.
"""

from __future__ import annotations

import pytest

from cra.report_templates import (
    DEFAULT_VERSION,
    STAGE_ORDER,
    Disposition,
    Marker,
    gaps,
    load,
    resolve,
)
from cra.schemas.enums import IncidentKind, ReportStage

EARLY, NOTIF, FINAL = STAGE_ORDER


@pytest.fixture(scope="module")
def t():
    return load()


# ---- the transcription -------------------------------------------------------


def test_the_catalogue_is_marked_provisional(t):
    """ENISA says the platform isn't final. If we ever present the fields as
    settled, that claim has to be a deliberate edit."""
    assert t.provisional is True
    assert t.version == DEFAULT_VERSION
    assert "Q16" in t.source


@pytest.mark.parametrize(
    "field_id,expected",
    [
        # Common
        ("1", ["X", "C", "C"]),   # Notification type
        ("2", ["X", "X", "X"]),   # Notification level
        ("6", ["A", "A", "A"]),   # Reporter — platform-side
        ("7", ["X", "C", "C"]),   # Manufacturer / steward
        ("8", ["X", "C", "C"]),   # Product
        ("11", ["I", "C", "C"]),  # Member States where available
        ("12", ["X", "C", "C"]),  # Title
        # Vulnerability
        ("v13", ["O", "C", "C"]),  # CVE ID — optional even at 72h
        ("v15", ["O", "X", "C"]),  # General information
        ("v20", ["O", "I", "C"]),  # Considered sensitivity
        ("v21", ["O", "O", "X"]),  # Date corrective measure available
        ("v25", ["O", "O", "I"]),  # Malicious actor
        ("v26", ["O", "O", "X"]),  # Security update details
        # Incident
        ("i13", ["X", "C", "C"]),  # Suspected unlawful or malicious acts
        ("i15", ["O", "X", "C"]),  # When detected
        ("i20", ["O", "I", "C"]),  # Considered sensitivity
        ("i24", ["O", "O", "X"]),  # Threat / root cause
        ("i25", ["O", "O", "X"]),  # Applied and ongoing mitigation
    ],
)
def test_markers_match_the_published_table(t, field_id, expected):
    assert [m.value if m else None for m in t.by_id(field_id).markers] == expected


def test_the_severity_definition_row_carries_no_markers(t):
    """i22 is the CRA's two-limb test for a severe incident, printed under
    "Severity" as guidance. ENISA leaves its cells blank; treating it as a
    field would ask the user to fill in a definition."""
    i22 = t.by_id("i22")
    assert i22.markers == (None, None, None)
    assert i22.guidance_only
    assert i22.parent_id == "i21"
    for stage in STAGE_ORDER:
        assert i22.disposition_at(stage) is Disposition.GUIDANCE


def test_the_unnumbered_incident_row_is_flagged_as_ours(t):
    """ENISA's table gives the incident "Detailed description" parent no id,
    unlike its vulnerability counterpart. Ours must not masquerade as theirs."""
    row = t.by_id("i20a")
    assert row.parent
    assert "not an ENISA identifier" in row.note


def test_each_stream_sees_the_common_fields_plus_its_own(t):
    vuln = {f.id for f in t.for_kind(IncidentKind.ACTIVELY_EXPLOITED_VULN)}
    inc = {f.id for f in t.for_kind(IncidentKind.SEVERE_INCIDENT)}
    assert {"1", "7", "12"} <= vuln & inc          # common to both
    assert {"v13", "v26"} <= vuln and not (vuln & {"i13"})
    assert {"i13", "i25"} <= inc and not (inc & {"v13"})


def test_table_order_is_preserved(t):
    """Field order is ENISA's, so a draft reads like their form."""
    ids = [f.id for f in t.for_kind(IncidentKind.SEVERE_INCIDENT)]
    assert ids[:3] == ["1", "2", "3"]
    assert ids.index("i13") > ids.index("12")


def test_an_unknown_version_says_what_exists():
    with pytest.raises(KeyError, match="v1"):
        load("v99")


# ---- marker semantics --------------------------------------------------------


def test_platform_automated_fields_are_never_offered():
    """`A` means the SRP computes it. Rendering our own value invites the user
    to reconcile two numbers and assume ours is authoritative."""
    ids = {r.field.id for r in resolve(IncidentKind.SEVERE_INCIDENT, EARLY)}
    assert not (ids & {"3", "4", "5", "6"})
    assert Marker.AUTOMATED in load().by_id("6").markers


def test_a_missing_obligatory_field_is_a_gap():
    resolved = resolve(IncidentKind.SEVERE_INCIDENT, EARLY, known={"12": "RCE in v2.1"})
    gap_ids = {r.field.id for r in gaps(resolved)}
    # Everything X at 24h and not supplied.
    assert gap_ids == {"1", "2", "7", "8", "i13"}
    assert "12" not in gap_ids


def test_a_missing_if_available_field_is_not_a_gap():
    """ENISA's `I` is "obligatory if such information available", so absence is
    an answer. Treating it as a blocker would make the 24h draft refuse to
    emit — the one thing it must never do."""
    resolved = resolve(IncidentKind.SEVERE_INCIDENT, EARLY)
    member_states = next(r for r in resolved if r.field.id == "11")
    assert member_states.disposition is Disposition.IF_AVAILABLE
    assert member_states.value is None
    assert member_states.is_gap is False


def test_an_optional_field_is_never_a_gap():
    resolved = resolve(IncidentKind.ACTIVELY_EXPLOITED_VULN, EARLY)
    cve = next(r for r in resolved if r.field.id == "v13")
    assert cve.disposition is Disposition.OPTIONAL
    assert cve.is_gap is False


def test_the_early_warning_can_always_be_emitted_with_the_bare_facts():
    """The 24h stage asks for very little by design — "send what you know".
    Six fields, all of which we hold at incident time."""
    known = {
        "1": "Incident",
        "2": "24h",
        "7": "Acme Oy",
        "8": "Acme Gateway",
        "12": "Unauthorised access via update channel",
        "i13": "yes",
    }
    assert gaps(resolve(IncidentKind.SEVERE_INCIDENT, EARLY, known=known)) == []


# ---- carry-forward, the behaviour that makes the 72h clock survivable --------


def test_copied_fields_prefill_from_the_previous_submission():
    previous = {"1": "Incident", "7": "Acme Oy", "8": "Acme Gateway", "12": "Breach"}
    resolved = resolve(IncidentKind.SEVERE_INCIDENT, NOTIF, previous=previous)
    carried = {r.field.id: r.value for r in resolved if r.carried_from_previous}
    assert carried == previous
    assert not any(r.field.id in previous for r in gaps(resolved))


def test_a_fresher_fact_beats_a_carried_one():
    """`C` is "copied by default, **or updated**". If the record has moved on,
    the record wins — otherwise a corrected product name would silently revert
    to whatever was filed at hour 23."""
    resolved = resolve(
        IncidentKind.SEVERE_INCIDENT,
        NOTIF,
        known={"8": "Acme Gateway 2.x"},
        previous={"8": "Acme Gateway"},
    )
    product = next(r for r in resolved if r.field.id == "8")
    assert product.value == "Acme Gateway 2.x"
    assert product.carried_from_previous is False


def test_precedence_is_known_then_carried_then_seed():
    """Three tiers, and the middle one is the reason this isn't a dict merge.

    A seed is what the record could approximate before anyone wrote the field
    properly. It must lose to a carried value, or the narrative typed at hour
    70 silently reverts to the one-liner captured while the incident was still
    unfolding.
    """
    args = dict(known={"12": "known"}, previous={"12": "carried"}, fallback={"12": "seed"})
    pick = lambda **kw: next(  # noqa: E731
        r for r in resolve(IncidentKind.SEVERE_INCIDENT, NOTIF, **kw) if r.field.id == "12"
    )

    assert pick(**args).value == "known"
    assert pick(previous=args["previous"], fallback=args["fallback"]).value == "carried"
    assert pick(fallback=args["fallback"]).value == "seed"


def test_a_seed_is_not_reported_as_carried_forward():
    """It came from the record, not from a previous filing — labelling it
    "carried forward" would tell the user it had already been sent."""
    r = next(
        x
        for x in resolve(IncidentKind.SEVERE_INCIDENT, EARLY, fallback={"12": "seed"})
        if x.field.id == "12"
    )
    assert r.value == "seed"
    assert r.carried_from_previous is False


def test_a_seed_can_satisfy_an_obligatory_field():
    """At 24h the title is X and nobody has typed one — the seed is what stops
    the early warning going out with a hole in it."""
    resolved = resolve(IncidentKind.SEVERE_INCIDENT, EARLY, fallback={"12": "seed"})
    assert "12" not in {r.field.id for r in gaps(resolved)}


def test_without_a_previous_submission_carried_fields_are_simply_empty():
    """Filing the 72h without a 24h on record is late, not impossible, and the
    draft must still come out."""
    resolved = resolve(IncidentKind.SEVERE_INCIDENT, NOTIF)
    title = next(r for r in resolved if r.field.id == "12")
    assert title.disposition is Disposition.CARRY_FORWARD
    assert title.value is None
    assert title.is_gap is False  # C, not X — nothing is blocked


# ---- what each stage actually demands ----------------------------------------


def test_the_final_report_is_where_the_full_account_is_required():
    vuln_final = {
        r.field.id
        for r in resolve(IncidentKind.ACTIVELY_EXPLOITED_VULN, FINAL)
        if r.disposition is Disposition.REQUIRED
    }
    # The date a corrective measure became available — the field that anchors
    # this stage's own 14-day clock — is obligatory only here.
    assert "v21" in vuln_final
    assert (
        load().by_id("v21").disposition_at(EARLY) is Disposition.OPTIONAL
    )


def test_the_notification_is_where_the_narrative_becomes_obligatory():
    required = {
        r.field.id
        for r in resolve(IncidentKind.ACTIVELY_EXPLOITED_VULN, NOTIF)
        if r.disposition is Disposition.REQUIRED
    }
    assert {"v15", "v16", "v17", "v18", "v19"} <= required
    assert "2" in required  # notification level, obligatory at every stage


def test_notification_level_is_the_only_field_obligatory_at_every_stage(t):
    always = [
        f.id
        for f in t.fields
        if all(f.disposition_at(s) is Disposition.REQUIRED for s in STAGE_ORDER)
    ]
    assert always == ["2"]


def test_resolve_accepts_plain_strings_off_the_database():
    assert resolve("severe_incident", "early_warning") == resolve(
        IncidentKind.SEVERE_INCIDENT, ReportStage.EARLY_WARNING
    )
