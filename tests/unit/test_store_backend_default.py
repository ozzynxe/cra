"""`CRA_STORE` defaults to whichever backend the environment can actually keep.

The old default was `file` unconditionally. That put the non-transactional
backend — the one that can lose the audit row a technical file is evidenced by
— behind doing nothing, and the transactional one behind knowing a variable
name. The guarantee this product is sold on should not be opt-in.

Defaulting to `pg` outright is the opposite error: it breaks a contributor who
has not started Postgres, turning their first `pytest` into a connection error.

So the default is derived from `DATABASE_URL`, and these tests pin all four
corners of that plus the explicit override, because a selector that silently
picks the wrong backend fails in the one way nobody notices until the record is
already gone.
"""

from __future__ import annotations

import importlib
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))


def _backend_name(monkeypatch, **env) -> str:
    for key in ("CRA_STORE", "DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import cra.server.store_backend as sb

    importlib.reload(sb)
    return sb.get_backend().__name__.rsplit(".", 1)[-1]


_URL = "postgresql+psycopg://user@localhost/db"


def test_a_configured_database_is_the_one_used(monkeypatch):
    """`DATABASE_URL` alone is enough — it used to silently not be.

    Setting only `DATABASE_URL` left the dispatcher reading through the file
    backend while integration tests seeded through `store_pg`, so ~80 tests
    failed on state the dispatcher could not see. It read as a broken suite
    rather than a missing variable, and the fix was a documented incantation.
    Deriving the default removes the trap rather than documenting it.
    """
    assert _backend_name(monkeypatch, DATABASE_URL=_URL) == "store_pg"


def test_no_database_falls_back_to_the_file_backend(monkeypatch):
    assert _backend_name(monkeypatch) == "store"


def test_the_fallback_says_what_it_costs(monkeypatch, caplog):
    """Silence is what let production run on a backend that cannot promise."""
    with caplog.at_level(logging.WARNING):
        _backend_name(monkeypatch)
    assert any(
        "NOT in one transaction" in r.message for r in caplog.records
    ), "the file backend was selected without warning that it loses audit rows"


@pytest.mark.parametrize(
    "env,expected",
    [
        ({"CRA_STORE": "file", "DATABASE_URL": _URL}, "store"),
        ({"CRA_STORE": "pg"}, "store_pg"),
    ],
)
def test_an_explicit_setting_always_wins(monkeypatch, env, expected):
    assert _backend_name(monkeypatch, **env) == expected


def test_an_unknown_backend_is_refused_rather_than_guessed(monkeypatch):
    """`dynamo` was removed. Falling back would pick a backend nobody asked for."""
    import cra.server.store_backend as sb

    monkeypatch.setenv("CRA_STORE", "dynamo")
    importlib.reload(sb)
    with pytest.raises(ValueError, match="dynamo"):
        sb.get_backend()
