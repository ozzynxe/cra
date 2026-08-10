"""Per-request contextvars set by auth middleware, read by the dispatcher.

When a request arrives with a `coauth_*` connector token, the auth middleware
verifies it against Postgres and stashes the resolved (user_id, product_id)
into these contextvars. The dispatcher reads them to override the closure-bound
`party_id` from `register_tools` and the `session_id` arg from tool calls.

Legacy `tok_a_*` / `tok_b_*` static tokens leave these unset; the dispatcher
falls back to the closure-bound values, so cloud-test and friends keep working.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

current_user_id: ContextVar[Optional[str]] = ContextVar("current_user_id", default=None)
current_product_id: ContextVar[Optional[str]] = ContextVar("current_product_id", default=None)
