"""SQLAlchemy engine + session helpers.

`DATABASE_URL` env var is the source of truth — never hardcoded.

Examples:
    postgresql+psycopg://app_user:****@postgres:5432/appdb    (container)
    postgresql+psycopg://localhost/cra                        (dev)
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker[Session]] = None


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return url


def create_engine_from_env(*, echo: bool = False) -> Engine:
    """Create a fresh engine from $DATABASE_URL. Mostly for tests/migrations."""
    return create_engine(
        database_url(),
        echo=echo,
        pool_pre_ping=True,
        future=True,
    )


def get_engine() -> Engine:
    """Process-wide engine singleton; lazy-initialized."""
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine_from_env()
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, class_=Session)
    return _engine


def engine_for(url: str, *, echo: bool = False) -> Engine:
    return create_engine(url, echo=echo, pool_pre_ping=True, future=True)


def db_session() -> Session:
    """Return a fresh Session bound to the singleton engine."""
    if _SessionLocal is None:
        get_engine()
    assert _SessionLocal is not None
    return _SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope around a series of operations.

        with session_scope() as s:
            s.add(...)
            # commits on exit, rolls back on exception
    """
    s = db_session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def reset_engine_for_tests() -> None:
    """Force the next get_engine() call to rebuild from env. Test fixtures use this."""
    global _engine, _SessionLocal
    _engine = None
    _SessionLocal = None
