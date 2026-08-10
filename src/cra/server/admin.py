"""Unauthenticated service endpoints.

Routes:
  GET /health   — liveness
  GET /version  — service metadata

The Coauthor session-lifecycle admin routes (`/admin/init`, `/admin/sessions`,
state dump, hard delete) are gone. They existed to bootstrap demo documents by
hand; products here are created through the MCP tool surface under a real
identity, which is also what makes the audit trail meaningful. If ops tooling
is needed later it should read Postgres directly rather than reintroduce an
admin-token backdoor into a store holding unreported vulnerability details.
"""

from __future__ import annotations

import os

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response


async def health(_request: Request) -> Response:
    return PlainTextResponse("ok")


async def version(_request: Request) -> Response:
    """What code is running here.

    Unauthenticated on purpose: this is the endpoint you hit when a client is
    behaving as though it is talking to a different build, and needing a
    credential to answer "which build" would defeat it. It exposes a commit
    hash and a tool count — nothing about products, users or vulnerabilities.
    """
    from cra import __version__
    from cra.buildinfo import build_info, tool_names

    return JSONResponse(
        {
            "name": "cra-mcp",
            "version": __version__,
            "build": build_info(),
            "tool_count": len(tool_names()),
            "env": os.environ.get("CRA_ENV", "production"),
        }
    )
