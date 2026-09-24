"""Test fixtures: an isolated temp-file SQLite DB per test session, and a
FastAPI TestClient wired to it (never the real sentivra.db)."""

from __future__ import annotations

import os
import tempfile

import pytest

# Point at a throwaway DB *before* app.core.config / app.core.database is
# imported anywhere, since Settings() is cached via lru_cache.
_TMP_DB_FD, _TMP_DB_PATH = tempfile.mkstemp(suffix=".db")
os.close(_TMP_DB_FD)
os.environ["SENTIVRA_DATABASE_URL"] = f"sqlite:///{_TMP_DB_PATH}"
os.environ["SENTIVRA_SECRET_KEY"] = "test-secret-key"


@pytest.fixture(scope="session", autouse=True)
def _cleanup_tmp_db():
    yield
    try:
        os.remove(_TMP_DB_PATH)
    except OSError:
        pass


@pytest.fixture()
def db_session():
    from app.core.database import SessionLocal, init_db

    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def app_client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        yield client
