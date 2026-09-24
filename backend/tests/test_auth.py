"""API authentication: OAuth2 client credentials, scopes, token validation,
and the rule that no route is reachable without a token unless it's meant to be."""

from __future__ import annotations

import base64
import json
import os
import time

import jwt
import pytest

from tests.conftest import CLIENT_SECRETS, token_for

PUBLIC = {("POST", "/api/v1/auth/token"), ("GET", "/api/v1/health/live")}


def test_every_api_route_requires_a_token_unless_explicitly_public(anon_client):
    # Enumerate from the OpenAPI schema: it lists every route however routers
    # are mounted, so a route added later without a scope fails here.
    spec = anon_client.get("/openapi.json").json()
    checked = 0
    for path, operations in spec["paths"].items():
        for method in operations:
            method = method.upper()
            if not path.startswith("/api/") or (method, path) in PUBLIC:
                continue
            url = path.replace("{alert_id}", "x").replace("{event_id}", "x")
            resp = anon_client.request(method, url)
            assert resp.status_code == 401, f"{method} {path} answered {resp.status_code} without a token"
            assert resp.headers["WWW-Authenticate"].startswith("Bearer")
            checked += 1
    assert checked >= 20


def test_liveness_is_public_and_says_nothing_else(anon_client):
    assert anon_client.get("/api/v1/health/live").json() == {"status": "ok"}


# ---- token endpoint -------------------------------------------------------------


def test_token_issued_with_client_scopes(anon_client):
    resp = anon_client.post("/api/v1/auth/token", data={
        "grant_type": "client_credentials", "client_id": "reader", "client_secret": CLIENT_SECRETS["reader"]})
    body = resp.json()
    assert resp.status_code == 200 and body["token_type"] == "bearer" and body["scope"] == "read"
    assert resp.headers["Cache-Control"] == "no-store"


def test_http_basic_client_authentication(anon_client):
    basic = base64.b64encode(f"reader:{CLIENT_SECRETS['reader']}".encode()).decode()
    resp = anon_client.post("/api/v1/auth/token", data={"grant_type": "client_credentials"},
                            headers={"Authorization": f"Basic {basic}"})
    assert resp.status_code == 200


@pytest.mark.parametrize("client_id,secret", [("reader", "wrong-secret"), ("nobody", "whatever-secret")])
def test_bad_credentials_get_the_same_answer(anon_client, client_id, secret):
    # Same status and body whether the id or the secret is wrong: no enumeration.
    resp = anon_client.post("/api/v1/auth/token", data={
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret})
    assert resp.status_code == 401 and resp.json()["error"] == "invalid_client"


def test_unsupported_grant_and_unknown_scope(anon_client):
    assert anon_client.post("/api/v1/auth/token", data={"grant_type": "password"}).json()["error"] == \
        "unsupported_grant_type"
    resp = anon_client.post("/api/v1/auth/token", data={
        "grant_type": "client_credentials", "client_id": "admin", "client_secret": CLIENT_SECRETS["admin"],
        "scope": "read superuser"})
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_scope"


def test_requested_scope_narrows_the_token(anon_client):
    resp = anon_client.post("/api/v1/auth/token", data={
        "grant_type": "client_credentials", "client_id": "admin", "client_secret": CLIENT_SECRETS["admin"],
        "scope": "read"})
    token = resp.json()["access_token"]
    assert resp.json()["scope"] == "read"
    assert anon_client.post("/api/v1/network/demo", headers={"Authorization": f"Bearer {token}"}).status_code == 403


# ---- scopes -----------------------------------------------------------------------


def test_read_only_client_cannot_write_or_analyze(anon_client):
    headers = {"Authorization": f"Bearer {token_for(anon_client, 'reader')}"}
    assert anon_client.get("/api/v1/alerts", headers=headers).status_code == 200
    assert anon_client.post("/api/v1/network/demo", headers=headers).status_code == 403
    resp = anon_client.patch("/api/v1/alerts/x", json={"status": "RESOLVED"}, headers=headers)
    assert resp.status_code == 403 and "alerts:write" in resp.json()["detail"]


def test_ingest_only_agent_can_submit_but_not_read(anon_client):
    headers = {"Authorization": f"Bearer {token_for(anon_client, 'agent')}"}
    event = {"event_type": "system_log", "source": "agent", "source_type": "LIVE", "content": {"body": "hello"}}
    assert anon_client.post("/api/v1/events", json=event, headers=headers).status_code == 200
    assert anon_client.get("/api/v1/alerts", headers=headers).status_code == 403


# ---- token validation -----------------------------------------------------------------


def _claims(**overrides):
    now = int(time.time())
    return {"iss": "sentivra", "sub": "admin", "scope": "read", "iat": now, "exp": now + 60, **overrides}


def _get(anon_client, token):
    return anon_client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})


def test_expired_token_rejected(anon_client):
    from app.security.auth import signing_key

    token = jwt.encode(_claims(exp=int(time.time()) - 5), signing_key(), algorithm="HS256")
    assert _get(anon_client, token).status_code == 401


def test_token_signed_with_another_key_rejected(anon_client):
    assert _get(anon_client, jwt.encode(_claims(), "someone-elses-key-" * 3, algorithm="HS256")).status_code == 401


def test_unsigned_alg_none_token_rejected(anon_client):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(_claims(scope="read analyze")).encode()).rstrip(b"=").decode()
    assert _get(anon_client, f"{header}.{payload}.").status_code == 401


def test_tampered_scope_claim_rejected(anon_client):
    header, payload, signature = token_for(anon_client, "reader").split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["scope"] = "read analyze ingest alerts:write"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    assert _get(anon_client, f"{header}.{forged}.{signature}").status_code == 401


def test_token_for_unknown_client_rejected(anon_client):
    from app.security.auth import signing_key

    assert _get(anon_client, jwt.encode(_claims(sub="deleted-client"), signing_key(), algorithm="HS256")).status_code == 401


def test_audit_log_records_the_acting_client(app_client):
    app_client.post("/api/v1/network/demo")
    entries = app_client.get("/api/v1/audit", params={"action": "analyze"}).json()["entries"]
    assert entries and entries[0]["actor"] == "admin"


# ---- configuration safety ------------------------------------------------------------


def _settings(tmp_path, **kw):
    from app.core.config import Settings

    return Settings(state_dir=tmp_path, oauth_clients=kw.pop("oauth_clients", ""), **kw)


@pytest.mark.parametrize("secret", [
    "",                                    # unset
    "insecure-development-key-override-me",  # the old built-in default
    "changeme-generate-a-real-secret",     # the .env.example placeholder, copied as-is
    "short-but-not-published",             # under 256 bits
])
def test_production_refuses_unsafe_signing_secrets(tmp_path, monkeypatch, secret):
    from app.security import auth

    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="production", secret_key=secret))
    with pytest.raises(auth.AuthConfigError):
        auth.signing_key.__wrapped__()


def test_development_replaces_a_copied_placeholder_secret(tmp_path, monkeypatch):
    from app.security import auth

    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="development",
                                                                 secret_key="changeme-generate-a-real-secret"))
    key = auth.signing_key.__wrapped__()
    assert key != "changeme-generate-a-real-secret" and (tmp_path / "signing.key").exists()


def test_a_real_secret_is_used_as_is(tmp_path, monkeypatch):
    from app.security import auth

    real = "a" * 20 + "-real-random-secret-value-xyz"
    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="production", secret_key=real))
    assert auth.signing_key.__wrapped__() == real


def test_production_requires_configured_clients(tmp_path, monkeypatch):
    from app.security import auth

    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="production"))
    with pytest.raises(auth.AuthConfigError):
        auth.load_clients.__wrapped__()


def test_development_bootstrap_stores_only_a_hash(tmp_path, monkeypatch):
    from app.security import auth

    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="development", secret_key=""))
    clients = auth.load_clients.__wrapped__()
    stored = json.loads((tmp_path / "clients.json").read_text(encoding="utf-8"))
    assert set(clients) == {"dashboard"} and "secret_sha256" in stored[0] and "client_secret" not in stored[0]
    # With no secret configured, a random per-install signing key is generated.
    key = auth.signing_key.__wrapped__()
    assert len(key) >= 48 and (tmp_path / "signing.key").read_text(encoding="utf-8").strip() == key


def test_concurrent_first_starts_agree_on_one_key_and_one_client(tmp_path, monkeypatch):
    # uvicorn --workers N starts N processes that bootstrap at the same time.
    # They must end up with the same signing key and client, or tokens from
    # one worker are rejected by the next and the printed secret may not work.
    import threading

    from app.security import auth

    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="development", secret_key=""))
    workers = 8
    barrier = threading.Barrier(workers)
    keys, client_sets = [], []

    def start():
        barrier.wait()
        keys.append(auth.signing_key.__wrapped__())
        client_sets.append(auth.load_clients.__wrapped__())

    threads = [threading.Thread(target=start) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stored = json.loads((tmp_path / "clients.json").read_text(encoding="utf-8"))
    assert len(set(keys)) == 1 and keys[0] == (tmp_path / "signing.key").read_text(encoding="utf-8").strip()
    assert {c["dashboard"].secret_sha256 for c in client_sets} == {stored[0]["secret_sha256"]}
    assert not list(tmp_path.glob(".*.tmp")), "temporary files left behind"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits; Windows uses the directory's ACLs")
def test_state_files_are_owner_only_from_creation(tmp_path, monkeypatch):
    from app.security import auth

    monkeypatch.setattr(auth, "get_settings", lambda: _settings(tmp_path, env="development", secret_key=""))
    auth.signing_key.__wrapped__()
    auth.load_clients.__wrapped__()
    for name in ("signing.key", "clients.json"):
        assert (tmp_path / name).stat().st_mode & 0o077 == 0, name


def test_weak_or_unknown_client_config_rejected(tmp_path, monkeypatch):
    from app.security import auth

    for bad in ("x:short:read", f"x:{'s' * 40}:read superpower"):
        monkeypatch.setattr(auth, "get_settings", lambda bad=bad: _settings(tmp_path, oauth_clients=bad))
        with pytest.raises(auth.AuthConfigError):
            auth.load_clients.__wrapped__()
