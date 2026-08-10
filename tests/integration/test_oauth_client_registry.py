"""Registered OAuth clients survive a restart, and can remove themselves.

Both halves come from one incident. The registry was a module-level dict, so a
deploy — which is a restart — forgot every client that had ever connected. The
damage was invisible at the time: an unknown client falls through to the host
allowlist rather than failing loudly, so it surfaced later as a connector that
could neither reconnect nor be deleted. It could not be deleted because RFC
7592 was not implemented: the client asks to clean up, gets a 404, and refuses
to finish.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

_NEEDS_DB = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.server.http_app import build_app  # noqa: E402

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def client():
    return TestClient(build_app())


def _register(client, name="test client"):
    r = client.post(
        "/oauth/register", json={"client_name": name, "redirect_uris": [REDIRECT]}
    )
    assert r.status_code == 201, r.text
    return r.json()


# ---- it survives a restart ---------------------------------------------------


@_NEEDS_DB
def test_a_registration_outlives_the_process(client):
    """The whole bug: a deploy used to wipe every client. A second app object
    is the closest thing to a restart without one."""
    reg = _register(client)

    fresh = TestClient(build_app())
    r = fresh.get(
        f"/oauth/register/{reg['client_id']}",
        headers={"Authorization": f"Bearer {reg['registration_access_token']}"},
    )
    assert r.status_code == 200, "registration did not survive a new app instance"
    assert r.json()["client_id"] == reg["client_id"]
    assert r.json()["redirect_uris"] == [REDIRECT]


@_NEEDS_DB
def test_registration_returns_what_rfc_7592_needs(client):
    reg = _register(client)
    assert reg["registration_access_token"].startswith("regtok_")
    assert reg["registration_client_uri"].endswith(f"/oauth/register/{reg['client_id']}")


# ---- a client can remove itself ----------------------------------------------


@_NEEDS_DB
def test_a_client_can_delete_its_own_registration(client):
    reg = _register(client)
    auth = {"Authorization": f"Bearer {reg['registration_access_token']}"}

    assert client.delete(f"/oauth/register/{reg['client_id']}", headers=auth).status_code == 204
    # Gone: the read now refuses rather than returning the record.
    assert client.get(f"/oauth/register/{reg['client_id']}", headers=auth).status_code == 401


@_NEEDS_DB
def test_deleting_twice_succeeds(client):
    """A client retrying a delete it already completed must not be told it
    failed — that is exactly what strands an entry in a connector list."""
    reg = _register(client)
    auth = {"Authorization": f"Bearer {reg['registration_access_token']}"}
    assert client.delete(f"/oauth/register/{reg['client_id']}", headers=auth).status_code == 204
    assert client.delete(f"/oauth/register/{reg['client_id']}", headers=auth).status_code == 204


# ---- and nobody else can -----------------------------------------------------


@_NEEDS_DB
def test_the_client_id_alone_does_not_authorise_deletion(client):
    """A client_id travels in every authorize URL and sits in browser history.
    If it were proof, anyone who saw one could delete that registration."""
    reg = _register(client)
    cid = reg["client_id"]

    assert client.delete(f"/oauth/register/{cid}").status_code == 401
    assert client.delete(
        f"/oauth/register/{cid}", headers={"Authorization": "Bearer regtok_wrong"}
    ).status_code == 401

    # Still there.
    ok = client.get(
        f"/oauth/register/{cid}",
        headers={"Authorization": f"Bearer {reg['registration_access_token']}"},
    )
    assert ok.status_code == 200


@_NEEDS_DB
def test_one_clients_token_cannot_delete_another(client):
    a, b = _register(client, "a"), _register(client, "b")
    r = client.delete(
        f"/oauth/register/{b['client_id']}",
        headers={"Authorization": f"Bearer {a['registration_access_token']}"},
    )
    assert r.status_code == 401


@_NEEDS_DB
def test_an_unknown_client_id_is_not_confirmed_or_denied(client):
    """With no bearer it is 401 whether or not the id exists, so the endpoint
    cannot be used to enumerate registrations."""
    assert client.delete("/oauth/register/client_doesnotexist").status_code == 401
    assert client.get("/oauth/register/client_doesnotexist").status_code == 401


# ---- the registration still gates redirect_uris ------------------------------


@_NEEDS_DB
def test_a_registered_client_is_held_to_its_own_redirect_uris(client):
    """The reason the table matters beyond persistence: it narrows the host
    allowlist to the exact set this client registered."""
    from cra.server import oauth

    reg = _register(client)
    assert oauth._redirect_uri_registered(reg["client_id"], REDIRECT) is True
    assert (
        oauth._redirect_uri_registered(reg["client_id"], "https://claude.ai/somewhere-else")
        is False
    )


@_NEEDS_DB
def test_an_unknown_client_falls_through_to_the_allowlist(client):
    """Fail open, deliberately: DCR is not mandatory, and the host allowlist is
    the real open-redirect gate. Refusing here would lock out clients that
    never registered."""
    from cra.server import oauth

    assert oauth._redirect_uri_registered("client_never_seen", REDIRECT) is True
