"""Request-size limits, the token endpoint's own rate budget, response
headers, and CORS behavior."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_declared_oversized_json_body_refused_before_reading(app_client):
    resp = app_client.post("/api/v1/events", content=b"{}", headers={
        "Content-Type": "application/json", "Content-Length": str(10 * 1024 * 1024)})
    assert resp.status_code == 413


def test_chunked_body_cut_off_at_the_limit(app_client):
    def chunks():
        for _ in range(40):
            yield b"x" * 65536  # 2.5 MB with no Content-Length

    resp = app_client.post("/api/v1/events", content=chunks(), headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_upload_over_limit_refused(app_client, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_bytes", 1024)
    resp = app_client.post("/api/v1/analyze/file", files={"file": ("big.bin", b"\0" * 200_000)})
    assert resp.status_code == 413


def test_token_endpoint_has_its_own_tighter_budget():
    from app.security.rate_limit import TOKEN_PATH, RateLimiter, RateLimitMiddleware

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(1000), token_limiter=RateLimiter(3))
    app.add_api_route(TOKEN_PATH, lambda: {"ok": True}, methods=["POST"])
    app.add_api_route("/api/v1/other", lambda: {"ok": True}, methods=["GET"])
    client = TestClient(app)
    codes = [client.post(TOKEN_PATH).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert client.post(TOKEN_PATH).headers["Retry-After"] == "60"
    assert all(client.get("/api/v1/other").status_code == 200 for _ in range(10))


def test_api_responses_carry_strict_headers(app_client):
    h = app_client.get("/api/v1/alerts").headers
    assert h["Content-Security-Policy"].startswith("default-src 'none'")
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store"


def test_docs_page_gets_a_policy_that_lets_it_render(anon_client):
    resp = anon_client.get("/docs")
    assert resp.status_code == 200 and "cdn.jsdelivr.net" in resp.headers["Content-Security-Policy"]


def test_cors_allows_the_dashboard_and_nothing_else(anon_client):
    ok = anon_client.options("/api/v1/alerts", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "authorization" in ok.headers.get("access-control-allow-headers", "").lower()
    assert "access-control-allow-credentials" not in ok.headers
    evil = anon_client.options("/api/v1/alerts", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert evil.headers.get("access-control-allow-origin") is None
