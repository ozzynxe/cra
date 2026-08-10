"""The connector-token prefix, and the drift that broke it once.

`auth.py` used to test `presented.startswith("coauth_")` with its own literal
while `connector_tokens.TOKEN_PREFIX` held the real value. Renaming the prefix
for the fork moved one and not the other, so every freshly minted token got a
401 from the middleware — with no error text pointing anywhere near the cause.

These tests exist so the two can never disagree again.
"""

from __future__ import annotations

import inspect

from cra.server import auth, connector_tokens


def test_a_minted_token_carries_the_configured_prefix(monkeypatch):
    assert connector_tokens.TOKEN_PREFIX == "cra_"
    assert connector_tokens.is_connector_token("cra_abc123")
    assert not connector_tokens.is_connector_token("tok_a_legacy")
    assert not connector_tokens.is_connector_token("")


def test_the_prefix_is_configurable_without_touching_code():
    """A fork should be able to rename it in one place."""
    src = inspect.getsource(connector_tokens)
    assert "CRA_TOKEN_PREFIX" in src


def test_auth_does_not_keep_its_own_copy_of_the_prefix():
    """The actual regression guard.

    The middleware must reach `connector_tokens` for this judgement rather than
    embedding a literal that can rot independently.
    """
    src = inspect.getsource(auth)
    assert "is_connector_token" in src
    assert 'startswith("coauth_")' not in src
    assert 'startswith("cra_")' not in src


def test_the_legacy_static_bearer_is_not_mistaken_for_a_connector_token():
    """`tok_a_*` takes the legacy path; misrouting it would 401 the POC mounts."""
    for legacy in ("tok_a_demo", "tok_b_demo"):
        assert not connector_tokens.is_connector_token(legacy)
