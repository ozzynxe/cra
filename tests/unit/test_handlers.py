"""Handler behaviour that needs no database.

The one that matters here is the deadline block's failure mode. Everything
else in this file is shape-checking.
"""

from __future__ import annotations

import uuid

import pytest

from cra.agents import dispatch as dispatcher
from cra.server import handlers, store_backend


@pytest.fixture(autouse=True)
def file_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("CRA_STORE", "file")
    monkeypatch.setenv("CRA_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert store_backend.get_backend().__name__.endswith("store")


def _create(actor="u1", **kw):
    return dispatcher.dispatch(
        "create_product", "", actor, {"name": kw.pop("name", "Acme Gateway"), **kw}
    )


def test_a_new_product_id_is_a_uuid():
    """Every id column that references a product is typed UUID.

    A prefixed id ("prod-abc123") is not merely ugly here — it fails as a
    Postgres cast on read, so the break shows up far from its cause.
    """
    pid = _create()["product_id"]
    uuid.UUID(pid)  # raises if it isn't one


def test_classification_is_not_guessed_at_creation():
    pid = _create()["product_id"]
    status = dispatcher.dispatch("get_compliance_status", pid, "u1", {})
    assert status["classification"]["product_class"] == "unknown"
    assert status["classification"]["in_scope"] is None


def test_missing_deadlines_read_as_unavailable_never_as_nothing_due():
    """With no database configured the deadline block must say so.

    Rendering an empty list would let an agent tell a user "nothing is due"
    on the strength of a missing connection string. Unknown and clear is the
    only acceptable answer.
    """
    pid = _create()["product_id"]
    deadlines = dispatcher.dispatch("get_compliance_status", pid, "u1", {})["deadlines"]
    assert deadlines["open_obligations"] is None
    assert "does not mean nothing is due" in deadlines["unavailable"]
    assert "open_count" not in deadlines


def test_deadlines_lead_the_status_payload():
    """Ordering is load-bearing: one call should surface anything urgent."""
    pid = _create()["product_id"]
    status = dispatcher.dispatch("get_compliance_status", pid, "u1", {})
    assert list(status)[:4] == ["ok", "product_id", "name", "deadlines"]


def test_the_creating_user_becomes_the_owner():
    pid = _create(actor="priya")["product_id"]
    status = dispatcher.dispatch("get_compliance_status", pid, "priya", {})
    assert status["members"] == [{"user_id": "priya", "role": "owner"}]


def test_an_unknown_economic_operator_role_lists_the_valid_ones():
    """The model has to choose this value, so the error has to be usable."""
    r = _create(economic_operator_role="vendor")
    assert r["ok"] is False
    assert r["code"] == "invalid_state"
    assert "open_source_steward" in r["error"]


def test_overview_needs_no_product_and_carries_the_disclaimer():
    r = dispatcher.dispatch("cra_overview", "", "u1", {})
    assert r["ok"] is True
    assert "cannot certify" in r["disclaimer"]
    assert r["key_dates"]["reporting_obligations_start"] == "2026-09-11"


def test_a_product_scoped_tool_called_without_a_product_says_what_to_do():
    r = dispatcher.dispatch("get_compliance_status", "", "u1", {})
    assert r["ok"] is False
    assert r["code"] == "product_required"
    assert "list_products()" in r["error"]


def test_reporting_tools_are_registered_with_the_dispatcher():
    """Registration is an import side-effect, so it is worth asserting.

    `handlers.py` imports `reporting` at the bottom for exactly this; if that
    import is tidied away, every reporting tool silently becomes unknown.
    """
    for name in (
        "record_vulnerability",
        "update_vulnerability",
        "report_incident",
        "record_report_submission",
    ):
        assert dispatcher.dispatch(name, "", "u1", {}).get("code") != "unknown_tool"
    assert (
        dispatcher.dispatch("get_reporting_deadlines", "", "u1", {}).get("code")
        != "unknown_tool"
    )


def test_get_reporting_deadlines_works_without_a_product_id():
    """The "is anything due across everything I own" call."""
    assert "get_reporting_deadlines" in dispatcher._SESSION_AGNOSTIC


def test_importing_one_domain_module_does_not_hide_the_others():
    """A regression with a nasty signature: no error, just most tools missing.

    `_ensure_handlers_loaded` used to skip its import when the registration
    tables were non-empty. Importing any single domain module — which the
    advisory sweeper does at startup — filled them with that module's handful
    and made the dispatcher decline to load the rest. Every other tool then
    answered `unknown_tool`, with nothing anywhere to explain why.
    """
    import importlib
    import sys

    from cra.agents import dispatch

    for name in [m for m in list(sys.modules) if m.startswith("cra.")]:
        del sys.modules[name]

    # The poisoning order: a domain module first, dispatch used afterwards.
    importlib.import_module("cra.server.advisories")
    d = importlib.import_module("cra.agents.dispatch")
    d._ensure_handlers_loaded()

    names = {*d._READ, *d._MUTATING}
    assert "scan_advisories" in names          # the module we imported
    assert "get_reporting_deadlines" in names  # and everything else
    assert "cra_overview" in names
    assert len(names) >= 35
