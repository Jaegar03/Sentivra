"""Test fixtures: an isolated temp-file SQLite DB per test session, explicit
API clients (never the generated development client), and TestClients that
are either authenticated with every scope or anonymous."""

from __future__ import annotations

import os
import tempfile

import pytest

# Set before app.core.config is imported anywhere, since Settings() is cached.
_TMP_DB_FD, _TMP_DB_PATH = tempfile.mkstemp(suffix=".db")
os.close(_TMP_DB_FD)
os.environ["SENTIVRA_DATABASE_URL"] = f"sqlite:///{_TMP_DB_PATH}"
os.environ["SENTIVRA_SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-hs256-signing"
os.environ["SENTIVRA_STATE_DIR"] = tempfile.mkdtemp(prefix="sentivra-state-")
# Rate limits are exercised by their own tests; don't let the suite's own
# request volume trip them.
os.environ["SENTIVRA_RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["SENTIVRA_TOKEN_RATE_LIMIT_PER_MINUTE"] = "100000"

CLIENT_SECRETS = {
    "admin": "admin-secret-0123456789abcdef0123456789abcdef",
    "reader": "reader-secret-0123456789abcdef0123456789abcdef",
    "agent": "agent-secret-0123456789abcdef0123456789abcdef",
}
os.environ["SENTIVRA_OAUTH_CLIENTS"] = ";".join([
    f"admin:{CLIENT_SECRETS['admin']}:read analyze ingest alerts:write",
    f"reader:{CLIENT_SECRETS['reader']}:read",
    f"agent:{CLIENT_SECRETS['agent']}:ingest",
])


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


def token_for(client, client_id: str) -> str:
    resp = client.post("/api/v1/auth/token", data={
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": CLIENT_SECRETS[client_id]})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture()
def anon_client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        yield client


@pytest.fixture()
def app_client(anon_client):
    """Authenticated with every scope (the admin test client)."""
    anon_client.headers["Authorization"] = f"Bearer {token_for(anon_client, 'admin')}"
    return anon_client
