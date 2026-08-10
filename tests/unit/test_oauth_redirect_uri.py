"""Unit tests for the OAuth `redirect_uri` allowlist (open-redirect defense).

Locks down the allowlist behavior so a regression can't accidentally
re-open the surface a connector reviewer would otherwise flag.
"""

from __future__ import annotations

import pytest

from cra.server import oauth


# ---- _redirect_uri_allowed: scheme + host rules --------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://chat.claude.ai/whatever",          # subdomain
        "https://chatgpt.com/connectors/cb",
        "https://platform.openai.com/oauth/cb",
        "http://localhost:8080/cb",                  # loopback http is ok
        "http://127.0.0.1:9000/cb",
        "https://anthropic.com/mcp",
    ],
)
def test_redirect_uri_allowed_accepts_known_hosts(url):
    assert oauth._redirect_uri_allowed(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "",                                          # empty
        "javascript:alert(1)",                       # bad scheme
        "data:text/html,<script>",                   # bad scheme
        "file:///etc/passwd",                        # bad scheme
        "ftp://claude.ai/cb",                        # bad scheme
        "http://claude.ai/cb",                       # http on non-loopback
        "https://evil.com/cb",                       # off-allowlist
        "https://attacker.example/cb",
        "https://claude.ai.evil.com/cb",             # suffix-confusion: NOT a claude.ai subdomain
        "not-a-url",
    ],
)
def test_redirect_uri_allowed_rejects_bad_inputs(url):
    assert oauth._redirect_uri_allowed(url) is False


# ---- _redirect_uri_registered: client-DCR check --------------------------


def test_redirect_uri_registered_when_no_client_record_is_permissive():
    """If we have no DCR record for the client, the allowlist is the only
    gate — _redirect_uri_registered returns True so the caller can proceed
    to the allowlist check upstream."""
    assert oauth._redirect_uri_registered("unknown-client", "https://x/y") is True


def test_redirect_uri_registered_enforced_against_dcr_set(monkeypatch):
    """Registrations live in Postgres now, so the lookup is stubbed: this is a
    test of the narrowing rule, not of storage."""
    monkeypatch.setattr(
        oauth,
        "_client_record",
        lambda cid: {
            "redirect_uris": ["https://claude.ai/cb", "https://chatgpt.com/cb"],
            "client_name": "test",
            "issued_at": 0,
        }
        if cid == "test-client"
        else None,
    )
    assert oauth._redirect_uri_registered("test-client", "https://claude.ai/cb") is True
    assert oauth._redirect_uri_registered("test-client", "https://chatgpt.com/cb") is True
    # Allowlisted host but NOT in this client's registered set → reject
    assert oauth._redirect_uri_registered("test-client", "https://anthropic.com/cb") is False


def test_redirect_uri_registered_empty_set_falls_through(monkeypatch):
    """A client that registered with no redirect_uris (rare) doesn't get to
    skip the allowlist — the allowlist gate upstream still applies. We return
    True here only because there is no per-client restriction to enforce."""
    monkeypatch.setattr(
        oauth,
        "_client_record",
        lambda cid: {"redirect_uris": [], "client_name": "empty", "issued_at": 0}
        if cid == "empty-client"
        else None,
    )
    assert oauth._redirect_uri_registered("empty-client", "https://claude.ai/cb") is True


def test_an_unreadable_registry_does_not_lock_clients_out(monkeypatch):
    """Fail open, like `entitlements.plan_for`. "We could not check whether
    this client is registered" must not become "this client is forbidden" —
    the host allowlist is the real open-redirect gate and does not depend on
    this table."""
    monkeypatch.setattr(oauth, "_client_record", lambda cid: None)
    assert oauth._redirect_uri_registered("anything", "https://claude.ai/cb") is True


# ---- env override --------------------------------------------------------


def test_allowed_redirect_hosts_env_override(monkeypatch):
    monkeypatch.setenv(
        "CRA_OAUTH_REDIRECT_HOSTS", "example.com,foo.bar"
    )
    hosts = oauth._allowed_redirect_hosts()
    assert hosts == ("example.com", "foo.bar")
    # And the allowlist check honors it
    assert oauth._redirect_uri_allowed("https://example.com/cb") is True
    assert oauth._redirect_uri_allowed("https://x.foo.bar/cb") is True
    assert oauth._redirect_uri_allowed("https://claude.ai/cb") is False  # not on the override list
