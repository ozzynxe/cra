"""JSON-file + filelock state store. Mirrors ContractPlatform's Phase-1 store.

Atomic-write pattern: dump JSON to a sibling tmp file, then `os.replace` into place.
The filelock guards both load and save against concurrent writers within the same host.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, TypeVar

from filelock import FileLock

from cra.schemas import ComplianceState

T = TypeVar("T")


def state_dir() -> Path:
    p = Path(os.environ.get("CRA_STATE_DIR", "state"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def state_path(session_id: str) -> Path:
    return state_dir() / f"{session_id}.json"


def lock_path(session_id: str) -> Path:
    return state_dir() / f"{session_id}.json.lock"


@contextmanager
def _lock(session_id: str) -> Iterator[None]:
    fl = FileLock(str(lock_path(session_id)), timeout=10)
    with fl:
        yield


def load_state(session_id: str) -> ComplianceState:
    p = state_path(session_id)
    if not p.exists():
        raise FileNotFoundError(f"no state file at {p}")
    return ComplianceState.model_validate_json(p.read_text(encoding="utf-8"))


def save_state(state: ComplianceState) -> Path:
    p = state_path(state.product_id)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(
        json.dumps(json.loads(state.model_dump_json()), indent=2, sort_keys=False),
        encoding="utf-8",
    )
    os.replace(tmp, p)
    return p


def with_lock(
    session_id: str,
    fn: Callable[[ComplianceState, object], tuple[ComplianceState, T]],
) -> T:
    """Acquire the per-product lock, load state, call fn, save, return result.

    `fn` receives `(state, db)` to match `store_pg.with_lock`, but `db` is
    always None here: a file backend has no transaction to enlist an audit
    write in. Anything needing the audit trail to be atomic must run on
    `CRA_STORE=pg`.
    """
    with _lock(session_id):
        state = load_state(session_id)
        new_state, result = fn(state, None)
        save_state(new_state)
        return result


def session_exists(session_id: str) -> bool:
    return state_path(session_id).exists()


def list_sessions() -> list[str]:
    """Return all session ids the file store knows about."""
    d = state_dir()
    return sorted(p.stem for p in d.glob("*.json") if not p.name.endswith(".tmp"))


def delete_session(session_id: str) -> None:
    """Hard-delete a session's state + lock files (file backend)."""
    p = state_path(session_id)
    p.unlink(missing_ok=True)
    lock_path(session_id).unlink(missing_ok=True)
