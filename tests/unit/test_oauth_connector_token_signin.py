"""The connector-token sign-in path on `/oauth/authorize`.

This deployment has no SPA and no `/login` route, so a signed-out user used to
be redirected to a URL that 404s — which meant the Claude.ai and Codex web
connector UIs, both of which force an OAuth dance, could never complete a
connection. The consent page now accepts the `cra_…` connector token the
operator already issues.

These tests pin the parts that are load-bearing for security:

  * a product-scoped token cannot buy a user-wide grant,
  * failures do not reveal whether a token exists,
  * and the page asks for a token rather than redirecting anywhere.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cra.server import connector_tokens, oauth


class _FakeUser:
    def __init__(self, uid="u-1", email="operator@example.test"):
        self.id = uid
        self.email = email


def _verification(*, user_id="u-1", product_id=None):
    return connector_tokens.TokenVerification(
        user_id=user_id,
        product_id=product_id,
        role=None,
        token_id="t-1",
    )


# ---- _user_from_connector_token -------------------------------------------


def test_resolves_a_user_wide_token_to_its_user():
    user = _FakeUser()
    with patch.object(connector_tokens, "verify_token", return_value=_verification()), \
         patch.object(oauth.sso, "get_user", return_value=user):
        assert oauth._user_from_connector_token("cra_abc123") is user


def test_product_scoped_token_is_refused():
    """The grant issued here is user-wide. Accepting a token that can only
    touch one product would let it mint one that can touch everything."""
    with patch.object(
        connector_tokens, "verify_token",
        return_value=_verification(product_id="prod-9"),
    ), patch.object(oauth.sso, "get_user", return_value=_FakeUser()):
        with pytest.raises(oauth._TokenSignInError) as e:
            oauth._user_from_connector_token("cra_abc123")
    assert "single product" in str(e.value)


def test_empty_and_malformed_tokens_are_rejected_before_any_lookup():
    with patch.object(connector_tokens, "verify_token") as verify:
        for presented in ("", "   ", "tok_a_legacy", "not-a-token"):
            with pytest.raises(oauth._TokenSignInError):
                oauth._user_from_connector_token(presented)
        verify.assert_not_called()


@pytest.mark.parametrize(
    "exc, expected",
    [
        (connector_tokens.TokenRevoked, "revoked"),
        (connector_tokens.TokenExpired, "expired"),
        (connector_tokens.TokenInvalid, "not accepted"),
    ],
)
def test_verification_failures_map_to_safe_messages(exc, expected):
    with patch.object(connector_tokens, "verify_token", side_effect=exc("boom")):
        with pytest.raises(oauth._TokenSignInError) as e:
            oauth._user_from_connector_token("cra_abc123")
    assert expected in str(e.value)


def test_invalid_token_message_does_not_reveal_whether_it_exists():
    """A distinct 'no such token' vs 'wrong token' message would be a
    guessing oracle."""
    with patch.object(connector_tokens, "verify_token", side_effect=connector_tokens.TokenInvalid("no row")):
        with pytest.raises(oauth._TokenSignInError) as e:
            oauth._user_from_connector_token("cra_abc123")
    message = str(e.value).lower()
    assert "no row" not in message
    assert "exist" not in message


def test_token_whose_user_row_vanished_is_refused():
    with patch.object(connector_tokens, "verify_token", return_value=_verification()), \
         patch.object(oauth.sso, "get_user", return_value=None):
        with pytest.raises(oauth._TokenSignInError):
            oauth._user_from_connector_token("cra_abc123")


# ---- the rendered page -----------------------------------------------------


def _render(**kw):
    defaults = dict(
        client_id="client-abc",
        hidden_fields={"state": "xyz", "redirect_uri": "https://claude.ai/cb"},
        cancel_url="https://claude.ai/cb?error=access_denied",
    )
    return oauth._render_token_form(**{**defaults, **kw})


def test_form_asks_for_a_connector_token_and_preserves_oauth_state():
    body = _render().body.decode()
    assert 'name="connector_token"' in body
    assert 'type="password"' in body          # not echoed back on screen
    assert 'name="state" value="xyz"' in body  # OAuth state survives the round-trip
    assert 'method="post"' in body             # never a query string


def test_form_escapes_hostile_values():
    """Both the hidden fields and the error text are attacker-reachable: the
    hidden fields come straight from the query string, and the error can carry
    a value the caller supplied. Neither may break out of its context."""
    body = _render(
        hidden_fields={"state": '"><script>alert(1)</script>'},
        error="<img src=x onerror=alert(1)>",
    ).body.decode()
    # Nothing survives as markup — the tags are text, and the quote that would
    # have closed the value attribute is escaped.
    assert "<script>" not in body
    assert "<img" not in body
    assert "&lt;script&gt;" in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body
    assert '"><script>' not in body


def test_error_is_shown_with_a_401():
    resp = _render(error="That token was not accepted.", status=401)
    assert resp.status_code == 401
    assert "That token was not accepted." in resp.body.decode()


def test_page_loads_no_third_party_assets():
    """The consent screen guards unreported vulnerability records. It should
    not depend on another host being up, nor leak a referrer to one."""
    body = _render().body.decode()
    assert "http://" not in body
    assert "https://app.coauthor.skarp.app" not in body
