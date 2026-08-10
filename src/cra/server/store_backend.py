"""State-backend selector, chosen by `CRA_STORE`.

  pg    — Postgres JSONB. The only backend that can commit the state write and
          the audit write in one transaction, which is why it is the production
          target. Requires DATABASE_URL.
  file  — JSON + filelock. Fine for tests and local dev; cannot give the audit
          trail transactional integrity.

The indirection exists so swapping backends never touches the dispatcher.

## Why the default is derived rather than fixed

`CRA_STORE` used to default to `file`. That meant the way to run this
non-transactionally was to do nothing, and the way to get the guarantee the
product is *sold* on — an audit trail that cannot lose a row — was to know a
variable name. A default should not be the option you would never deploy.

Defaulting to `pg` outright was the other wrong answer: it breaks every
contributor who has not started Postgres, and turns a first `pytest` run into a
connection error rather than a passing suite.

So the default follows the environment. `DATABASE_URL` set means a database was
configured on purpose, and a configured database is the one to use. Without it
there is nothing to connect to, so `file` is the only thing that can work — and
it says so once, loudly, because a silent fallback to the backend that cannot
keep the write/audit promise is indistinguishable from one that can.

Setting `CRA_STORE` explicitly always wins over both.
"""

from __future__ import annotations

import logging
import os
from types import ModuleType

log = logging.getLogger(__name__)

_WARNED = False


def _default_backend() -> str:
    """`pg` where a database is configured, `file` where none is."""
    return "pg" if os.environ.get("DATABASE_URL") else "file"


def get_backend() -> ModuleType:
    global _WARNED

    backend = (os.environ.get("CRA_STORE") or _default_backend()).lower()
    if backend == "file":
        from cra.server import store  # noqa: WPS433

        if not _WARNED:
            _WARNED = True
            log.warning(
                "CRA_STORE=file: the state write and its audit row are NOT in "
                "one transaction, so a crash between them loses the record of "
                "who changed what. Development only — production must set "
                "DATABASE_URL and CRA_STORE=pg."
            )
        return store
    if backend == "pg":
        from cra.server import store_pg  # noqa: WPS433

        return store_pg
    raise ValueError(
        f"unknown CRA_STORE backend: {backend!r} (expected 'pg' or 'file')"
    )


def mutate(product_id: str, fn):
    """Apply a state change and its audit row as one transaction.

    `fn(state, db)` receives the current state and an open session, mutates the
    state, writes its audit row through `db`, and returns `(state, result)`.
    Raising from `fn` rolls back both — which is the point, and the inversion
    this codebase is built around: under the CRA the trail is the deliverable,
    so a state change nobody can evidence is worse than no state change.

    Every blob-mutating tool used to do this in two transactions — `save_state`
    and then a separate `session_scope` for the audit row — which meant a
    failure between them left a classification, a decided risk or a frozen
    technical file with no record of who did it. `store_pg.with_lock` existed
    for precisely this and nothing called it.

    The lock matters as much as the atomicity. `with_lock` re-reads the row
    `FOR UPDATE`, so two agents on the same product serialise instead of the
    second silently overwriting the first's blob.

    On `CRA_STORE=file` the backend has no transaction to enlist in and hands
    `fn` a `None` session; a session is opened just for the audit row so the
    trail still exists, but the two writes are not atomic. That is unchanged
    from before and is why the file backend is dev-only.
    """
    backend = get_backend()

    def _run(state, db):
        if db is not None:
            return fn(state, db)
        from cra.db import session_scope  # noqa: WPS433 — file backend only

        with session_scope() as fallback:
            return fn(state, fallback)

    return backend.with_lock(product_id, _run)
