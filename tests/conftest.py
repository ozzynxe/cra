from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Make `src/` importable in tests without an editable install
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402


@pytest.fixture
def isolate_state(tmp_path, monkeypatch):
    """Per-test isolated state directory."""
    monkeypatch.setenv("CRA_STATE_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def fresh_state(now) -> ComplianceState:
    """A minimal product owned by `u-owner`, classification undetermined.

    Undetermined is the correct starting point: the tool must never imply a
    product class before `classify_product` has run.
    """
    return ComplianceState(
        product_id="prod-test",
        name="Test Product",
        description="A product under CRA assessment",
        members={
            "u-owner": MemberInfo(role=Role.OWNER, user_id="u-owner", joined_at=now),
        },
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def anyio_backend():
    return "asyncio"
