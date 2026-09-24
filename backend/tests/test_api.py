"""End-to-end API tests via FastAPI's TestClient — exercises the real app,
real SQLite (temp file, see conftest.py), real YARA compilation."""

from __future__ import annotations

import json

EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("ascii")


def test_health_reports_real_engine_state(app_client):
    resp = app_client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("ok", "degraded")
    assert "YaraDetector" in body["engines"]
    assert body["engines"]["YaraDetector"]["status"] == "Available"
    # ClamAV is genuinely not installed on this dev machine — must say so honestly.
    assert body["engines"]["ClamAVDetector"]["status"] == "Not Configured"
    # Suricata/Zeek are not wired as detectors yet in this phase.
    assert body["engines"]["Suricata"]["status"] == "Not Configured"


def test_detectors_endpoint_lists_registered_detectors(app_client):
    resp = app_client.get("/api/v1/detectors")
    assert resp.status_code == 200
    names = {d["name"] for d in resp.json()}
    assert {"MalwareDetector", "YaraDetector", "ClamAVDetector", "NetworkAnomalyDetector"} <= names


def test_models_endpoint_reports_trained_and_untrained_models_honestly(app_client):
    resp = app_client.get("/api/v1/models")
    assert resp.status_code == 200
    entries = {f"{e['domain']}/{e['name']}": e for e in resp.json()}
    # Trained models carry their provenance: pinned hash, evaluation date,
    # datasets and limitations.
    for key in ("network/isolation_forest", "network/autoencoder", "network/classifier"):
        meta = entries[key]["metadata"]
        assert entries[key]["trained"] is True
        assert len(meta["sha256"]) == 64 and meta["evaluation_date"] and meta["datasets"] and meta["limitations"]
    # Models that haven't been trained say so rather than being faked.
    assert entries["malware/ember"]["trained"] is False
    assert entries["malware/ember"]["reason_untrained"]


def test_analyze_file_detects_eicar(app_client):
    resp = app_client.post(
        "/api/v1/analyze/file",
        files={"file": ("eicar.txt", EICAR, "text/plain")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_assessment"]["severity"] != "SAFE"
    assert any(f["detector"] == "YaraDetector" for f in body["findings"])


def test_analyze_file_benign_is_safe(app_client):
    resp = app_client.post(
        "/api/v1/analyze/file",
        files={"file": ("notes.txt", b"just some ordinary notes", "text/plain")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_assessment"]["severity"] == "SAFE"


def test_analyze_file_flags_disguised_executable(app_client):
    fake_pe = b"MZ" + b"\x90" * 500
    resp = app_client.post(
        "/api/v1/analyze/file",
        files={"file": ("cute_cat.png", fake_pe, "image/png")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_assessment"]["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert body["file_metadata"]["extension_mismatch"] is True


def test_unimplemented_analyze_endpoints_return_501_not_fake_success(app_client):
    for path in ("text", "url", "prompt", "sql"):
        resp = app_client.post(f"/api/v1/analyze/{path}")
        assert resp.status_code == 501


def test_events_roundtrip(app_client):
    ingest = app_client.post(
        "/api/v1/events",
        json={
            "event_type": "system_log",
            "source": "test",
            "source_type": "DEMO_DATA",
            "content": {"body": "user login succeeded"},
        },
    )
    assert ingest.status_code == 200
    event_id = ingest.json()["event_id"]

    fetched = app_client.get(f"/api/v1/events/{event_id}")
    assert fetched.status_code == 200
    assert fetched.json()["event_id"] == event_id

    listing = app_client.get("/api/v1/events")
    assert listing.status_code == 200
    assert any(e["event_id"] == event_id for e in listing.json())


def test_alert_created_for_malicious_file_and_retrievable(app_client):
    resp = app_client.post(
        "/api/v1/analyze/file",
        files={"file": ("eicar2.txt", EICAR, "text/plain")},
    )
    alert_id = resp.json()["risk_assessment"]["assessment_id"]

    fetched = app_client.get(f"/api/v1/alerts/{alert_id}")
    assert fetched.status_code == 200
    assert fetched.json()["severity"] != "SAFE"

    listing = app_client.get("/api/v1/alerts")
    assert any(a["assessment_id"] == alert_id for a in listing.json())


def test_metrics_endpoint_has_no_fake_ml_accuracy(app_client):
    resp = app_client.get("/api/v1/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body["totals"]
    assert "accuracy" not in json.dumps(body).lower()
    assert "note" in body


def test_status_endpoints_do_not_disclose_absolute_paths(app_client):
    import re

    for path in ("/api/v1/health", "/api/v1/detectors", "/api/v1/integrations", "/api/v1/models"):
        text = app_client.get(path).text
        assert not re.search(r"[A-Za-z]:\\|/home/|/Users/|\\Users\\\\", text), path
