"""SQLAlchemy engine and session management for vuln-scanner.

The engine is created lazily so importing the scanner package never touches
the database. The connection string comes from ``DATABASE_URL``; the default
is a SQLite file next to the repository root.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_DEFAULT_DB_FILE = Path(__file__).resolve().parent.parent / "vuln_scanner.db"

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _default_url() -> str:
    return os.getenv("DATABASE_URL", f"sqlite:///{_DEFAULT_DB_FILE}")


def init_db(database_url: str | None = None) -> None:
    """Create the engine, tables, and session factory (idempotent)."""
    global _engine, _session_factory
    if _engine is not None and database_url is None:
        return
    url = database_url or _default_url()
    kwargs: dict = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    Base.metadata.create_all(_engine)
    _session_factory = sessionmaker(
        bind=_engine, autoflush=False, expire_on_commit=False
    )


def get_session() -> Session:
    """Return a new session, initializing the engine on first use."""
    if _session_factory is None:
        init_db()
    assert _session_factory is not None
    return _session_factory()
