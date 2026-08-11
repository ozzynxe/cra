"""End-to-end smoke test over the real MCP wire.

Spawns `cra.server.http_app` in a subprocess on a random port and drives it
with the MCP client, because the failure mode that matters here — a connector
that silently won't attach — is invisible to unit tests. Everything below the
transport can be green while Claude.ai still refuses to connect.

Marked `integration`: ~3-5s of server startup.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

TOKEN_A = "tok_a_smoke_test_value"


def _payload(result) -> dict:
    """Read a tool result the way a real client has to.

    FastMCP only populates `structuredContent` when the tool declares an output
    schema; a bare `-> dict` return arrives as JSON in a text content block.
    Preferring the structured field and falling back keeps this test honest
    across SDK versions rather than pinning us to one shape.
    """
    if result.structuredContent is not None:
        return result.structuredContent
    assert result.content, "tool returned no content"
    return json.loads(result.content[0].text)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    tmp = tmp_path_factory.mktemp("cra")
    state_dir = tmp / "state"
    state_dir.mkdir()
    log = tmp / "server.log"

    env = {
        **os.environ,
        "PYTHONPATH": "src",
        "CRA_TOKEN_A": TOKEN_A,
        "CRA_PARTIES": "a",
        "CRA_PORT": str(port),
        "CRA_HOST": "127.0.0.1",
        "CRA_STATE_DIR": str(state_dir),
        "CRA_STORE": "file",
        "CRA_LOG_LEVEL": "warning",
        # This test is about the MCP wire. A live sweeper against the shared
        # test database would write alert rows other tests then trip over.
        "CRA_DEADLINE_ALERTS_ENABLED": "0",
    }
    venv_python = Path(".venv/bin/python")
    py = str(venv_python) if venv_python.exists() else sys.executable
    proc = subprocess.Popen(
        [py, "-m", "cra.server.http_app"],
        env=env,
        stdout=open(log, "w"),
        stderr=subprocess.STDOUT,
        cwd=os.getcwd(),
    )

    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"server exited early:\n{log.read_text()}")
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001 — still booting
            time.sleep(0.25)
    else:
        pytest.fail(f"server never became ready:\n{log.read_text()}")

    try:
        yield base
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            proc.kill()


@pytest.mark.integration
def test_health_needs_no_auth(server):
    r = httpx.get(f"{server}/health")
    assert r.status_code == 200
    assert r.text.strip() == "ok"


@pytest.mark.integration
def test_version_reports_new_identity(server):
    body = httpx.get(f"{server}/version").json()
    assert body["name"] == "cra-mcp"
    assert body["version"]


@pytest.mark.integration
def test_mcp_mount_rejects_missing_bearer(server):
    """The gate that matters: an unauthenticated caller must not reach a store
    holding unreported vulnerability details."""
    r = httpx.post(
        f"{server}/mcp/a/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 401


@pytest.mark.integration
def test_mcp_mount_rejects_wrong_bearer(server):
    r = httpx.post(
        f"{server}/mcp/a/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers={
            "Authorization": "Bearer tok_a_wrong",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert r.status_code == 401


@pytest.mark.integration
@pytest.mark.anyio
async def test_tools_round_trip_over_mcp(server):
    """Initialize, list tools, and drive a create → read cycle over the wire."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {TOKEN_A}"}
    async with streamablehttp_client(f"{server}/mcp/a/mcp", headers=headers) as (
        read,
        write,
        _,
    ):
        async with ClientSession(read, write) as session:
            init = await session.initialize()

            # The instructions field is the discovery surface — if it stops
            # mentioning the CRA, Tool Search stops surfacing this server.
            assert "Cyber Resilience Act" in (init.instructions or "")

            # Exact set, not a subset: an accidentally exported tool is a
            # surface an agent will find and call.
            names = {t.name for t in (await session.list_tools()).tools}
            assert names == {
                "get_upgrade_link",
                "manage_subscription",
                "cra_overview",
                "list_products",
                "get_compliance_status",
                "create_product",
                "delete_product",
                "export_product",
                "record_vulnerability",
                "update_vulnerability",
                "report_incident",
                "get_reporting_deadlines",
                "record_report_submission",
                "draft_report",
                "check_reporting_readiness",
                "set_submitter_profile",
                "classify_product",
                "set_economic_operator_role",
                "scan_advisories",
                "list_advisory_candidates",
                "confirm_advisory",
                "dismiss_advisory",
                "start_risk_assessment",
                "propose_risks",
                "decide_risk",
                "confirm_risk_assessment",
                "get_risk_assessment",
                "get_applicable_csirt",
                "record_sbom",
                "set_support_period",
                "add_member",
                "remove_member",
                "get_recent_activity",
                "list_requirements",
                "list_user_information",
                "update_user_information",
                "update_requirement",
                "attach_evidence",
                "list_evidence",
                "list_releases",
                "place_on_market",
                "record_build",
                "assemble_technical_file",
                "generate_declaration_of_conformity",
                "generate_simplified_declaration",
                "sign_off",
                "get_conformity_status",
            }

            # Recording a legal filing must not be auto-approvable.
            by_name = {t.name: t for t in (await session.list_tools()).tools}
            assert by_name["record_report_submission"].annotations.destructiveHint is True
            assert by_name["get_reporting_deadlines"].annotations.readOnlyHint is True
            # Handing back a Stripe URL is not read-only — it creates a session
            # on another service — but nothing is charged until the user acts
            # on the link, so it must not be flagged destructive either.
            upgrade = by_name["get_upgrade_link"].annotations
            assert upgrade.readOnlyHint is False
            assert upgrade.destructiveHint is False
            assert upgrade.openWorldHint is True
            # Nor may deciding a risk or confirming an assessment: both make
            # determinations that end up in a ten-year artifact. Drafting is
            # additive and may be auto-approved — it determines nothing.
            assert by_name["decide_risk"].annotations.destructiveHint is True
            assert by_name["confirm_risk_assessment"].annotations.destructiveHint is True
            assert by_name["propose_risks"].annotations.destructiveHint is False

            overview = _payload(await session.call_tool("cra_overview", {}))
            assert overview["ok"] is True
            assert overview["key_dates"]["reporting_obligations_start"] == "2026-09-11"

            created = _payload(
                await session.call_tool("create_product", {"name": "Acme Gateway"})
            )
            assert created["ok"] is True
            pid = created["product_id"]

            status = _payload(
                await session.call_tool("get_compliance_status", {"product_id": pid})
            )
            assert status["ok"] is True
            assert status["name"] == "Acme Gateway"
            # Classification must not be guessed at creation time.
            assert status["classification"]["product_class"] == "unknown"
            # Deadlines lead the payload so one call surfaces anything urgent.
            assert list(status)[3] == "deadlines"


@pytest.fixture
def anyio_backend():
    return "asyncio"
