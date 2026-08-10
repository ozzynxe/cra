"""Storing by value is permanent here, so it has to be bounded.

`attach_evidence` took an arbitrary body with no ceiling until 2026-08-09. The
bytes go into a Postgres `Text` column, the database is dumped nightly, and the
statutory record is archived under Object Lock for a decade — so a single call
wrote data
that could not be removed by ordinary means for a decade, and nothing in the
application expires anything.

That is not a security hole. It is what made "can the free tier afford
`EVIDENCE`" unanswerable, because the honest answer was "one caller decides".

The per-artifact cap alone bounds nothing — a thousand artifacts just under it
are the same liability arrived at slowly — so the product total is the half that
actually closes it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from cra.server import artifact_limits as lim  # noqa: E402
from cra.server.errors import InvalidState  # noqa: E402

MIB = 1024 * 1024


def test_an_ordinary_artifact_is_nowhere_near_the_limit():
    """A cap a real user meets is a cap set wrong."""
    for size in (200, 40 * 1024, 900 * 1024):  # a SHA, a report, a large SBOM
        lim.check_artifact_size(size)


def test_an_oversized_artifact_is_refused():
    with pytest.raises(InvalidState) as e:
        lim.check_artifact_size(9 * MIB)
    msg = str(e.value)
    assert "9.0 MiB" in msg and "4 MiB" in msg


def test_the_refusal_does_not_suggest_storing_a_link_instead():
    """The whole design is that evidence is stored by value.

    A refusal that says "just reference it" would trade a bounded cost for an
    unevidenced technical file, which is the failure this product exists to
    prevent. It offers the material part plus a source_ref, or splitting.
    """
    with pytest.raises(InvalidState) as e:
        lim.check_artifact_size(9 * MIB)
    msg = str(e.value).lower()
    assert "source_ref" in msg
    assert "splitting" in msg
    assert "instead of storing" not in msg


def test_both_limits_are_env_overridable(monkeypatch):
    monkeypatch.setenv("CRA_EVIDENCE_MAX_BYTES", str(16 * MIB))
    monkeypatch.setenv("CRA_EVIDENCE_MAX_PRODUCT_BYTES", str(500 * MIB))
    assert lim.max_artifact_bytes() == 16 * MIB
    assert lim.max_product_bytes() == 500 * MIB
    lim.check_artifact_size(9 * MIB)


def test_a_nonsense_override_falls_back_rather_than_crashing(monkeypatch):
    """A typo in an env var must not take evidence recording down."""
    monkeypatch.setenv("CRA_EVIDENCE_MAX_BYTES", "four megabytes")
    assert lim.max_artifact_bytes() == 4 * MIB


def test_an_override_cannot_be_set_absurdly_low(monkeypatch):
    """Zero would refuse everything, including a one-line signed statement."""
    monkeypatch.setenv("CRA_EVIDENCE_MAX_BYTES", "0")
    assert lim.max_artifact_bytes() >= 1024


class _FakeDb:
    def __init__(self, used: int):
        self._used = used

    def execute(self, _stmt):
        used = self._used

        class _R:
            def scalar_one(self):
                return used

        return _R()


def test_the_product_total_is_what_actually_bounds_it():
    """Under the per-artifact cap, over the product cap."""
    with pytest.raises(InvalidState) as e:
        lim.check_product_total(_FakeDb(99 * MIB), "p", 2 * MIB)
    assert "past the 100 MiB limit" in str(e.value)


def test_being_over_the_total_does_not_imply_anything_was_lost():
    """A refusal here is about the incoming write, not the stored record."""
    with pytest.raises(InvalidState) as e:
        lim.check_product_total(_FakeDb(99 * MIB), "p", 2 * MIB)
    assert "Nothing already stored has been touched" in str(e.value)


def test_room_for_the_incoming_artifact_is_allowed():
    lim.check_product_total(_FakeDb(10 * MIB), "p", 2 * MIB)


def test_an_empty_product_starts_from_zero():
    lim.check_product_total(_FakeDb(0), "p", 1 * MIB)
