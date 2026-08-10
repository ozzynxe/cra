#!/usr/bin/env python
"""Mint a user and a connector token you can paste into an MCP client.

For local work and for the box itself, where there is no mail to receive a code
from. `/access` and the OAuth email-code flow are the supported ways to get a
credential otherwise.

    DATABASE_URL=... CRA_STORE=pg .venv/bin/python scripts/dev_token.py you@example.com

Prints the token once — it is bcrypt-hashed on the way in and cannot be
recovered afterwards. Re-run to mint another.

Why not just use the `CRA_TOKEN_A` party bearer? Because the legacy party
mounts carry a party id ("a"), not a user id, and every product-scoped table is
keyed on a real `users.id`. The static bearer is fine for the /health-level
smoke tests it was kept for; anything that writes needs a user behind it.
"""

from __future__ import annotations

import os
import sys
import uuid

if not os.environ.get("DATABASE_URL"):
    sys.exit("DATABASE_URL is not set — run scripts/dev_up.sh first.")
os.environ.setdefault("CRA_STORE", "pg")

from sqlalchemy import select  # noqa: E402

from cra.db import User, session_scope  # noqa: E402
from cra.server import connector_tokens  # noqa: E402


def main() -> None:
    email = sys.argv[1] if len(sys.argv) > 1 else "dev@example.test"
    label = sys.argv[2] if len(sys.argv) > 2 else "local dev"

    with session_scope() as s:
        user = s.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = User(id=str(uuid.uuid4()), email=email)
            s.add(user)
            s.flush()
            created = True
        else:
            created = False
        user_id = user.id

    token, row = connector_tokens.mint_token(user_id=user_id, label=label)

    port = os.environ.get("CRA_PORT", "8000")
    print(
        f"""
{"created" if created else "found"} user {email}
  user_id  {user_id}
  token id {row.id}

Token (shown once — it is stored only as a bcrypt hash):

  {token}

Attach Claude Code:

  claude mcp add --transport http cra http://127.0.0.1:{port}/mcp/me/mcp \\
    --header "Authorization: Bearer {token}"

Or call it directly:

  curl -sX POST http://127.0.0.1:{port}/mcp/me/mcp \\
    -H "Authorization: Bearer {token}" \\
    -H "Accept: application/json, text/event-stream" \\
    -H "Content-Type: application/json" \\
    -d '{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}'
"""
    )


if __name__ == "__main__":
    main()
