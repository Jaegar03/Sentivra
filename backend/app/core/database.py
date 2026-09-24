"""SQLAlchemy engine/session wiring.

This is the one place that knows the concrete database engine. Everything
else in the app talks to `app.services.*` repositories, never to SQLAlchemy
directly — that boundary is what lets SQLite be replaced by PostgreSQL later
(docs/architecture.md §2) without touching detector or API code.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine():
    settings = get_settings()
    connect_args = {}
    if settings.database_url.startswith("sqlite"):
        # Required for SQLite + FastAPI's threaded request handling.
        connect_args = {"check_same_thread": False}
    return create_engine(settings.database_url, connect_args=connect_args)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create tables that don't exist yet. Demo-mode migration strategy —
    a real deployment would use Alembic; out of scope for this phase."""
    from app import models  # noqa: F401  (ensure ORM models are registered)

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
