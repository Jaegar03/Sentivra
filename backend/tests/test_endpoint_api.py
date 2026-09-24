"""Endpoint, log and rules endpoints end to end."""

from __future__ import annotations

import json

from app.demo.endpoint_sim import FleetConfig, simulate


def test_endpoint_demo_is_simulated_and_detected(app_client):
    body = app_client.post("/api/v1/endpoint/demo").json()
    assert body["source_type"] == "SIMULATED"
    assert body["normalizer_stats"]["unrecognized_query_rows"] == 0
    detectors = {f["detector"] for f in body["findings"]}
    assert {"SigmaDetector", "LogDetector", "BehavioralAnomalyDetector"} <= detectors
    assert body["risk_assessment"]["severity"] in ("HIGH", "CRITICAL")
    assert body["analysis"]["behavior"]["baseline"].startswith("Available")


def test_benign_osquery_upload_is_live_and_safe(app_client):
    rows = simulate(FleetConfig(windows_hosts=4, linux_hosts=1, hours=2.0, seed=630, episodes={}))
    ndjson = "\n".join(json.dumps(r) for r in rows).encode()
    body = app_client.post("/api/v1/endpoint/osquery", files={"file": ("osqueryd.results.log", ndjson)}).json()
    assert body["source_type"] == "LIVE"
    assert body["risk_assessment"]["severity"] == "SAFE"


def test_osquery_upload_accepts_json_array(app_client):
    rows = simulate(FleetConfig(windows_hosts=2, linux_hosts=0, hours=1.0, seed=631, episodes={}))
    resp = app_client.post("/api/v1/endpoint/osquery", files={"file": ("results.json", json.dumps(rows).encode())})
    assert resp.status_code == 200 and resp.json()["event_count"] == len(rows)


def test_malformed_osquery_upload_rejected(app_client):
    resp = app_client.post("/api/v1/endpoint/osquery", files={"file": ("x.log", b"not json\n")})
    assert resp.status_code == 400


def test_log_upload_detects_password_guessing(app_client):
    lines = "\n".join(f"Sep 24 10:00:{i:02d} srv01 sshd[42]: Failed password for admin from 203.0.113.9 port "
                      f"{50000 + i} ssh2" for i in range(15))
    body = app_client.post("/api/v1/logs/analyze", files={"file": ("auth.log", lines.encode())}).json()
    assert body["parse_stats"]["linux_auth"] == 15
    log = next(f for f in body["findings"] if f["detector"] == "LogDetector")
    assert [m["technique_id"] for m in log["mitre_attack"]] == ["T1110.001"]


def test_rules_inventory(app_client):
    body = app_client.get("/api/v1/rules").json()
    assert len(body["sigma"]["loaded"]) >= 8 and body["sigma"]["unsupported"] == []
    assert {c["file"].rsplit("/", 1)[-1] for c in body["custom"]} >= {"network_rules.yaml", "endpoint_rules.yaml"}
    assert all("error" not in c for c in body["custom"])
    assert body["attack_index"]["attack_version"]


def test_health_lists_phase6_detectors(app_client):
    engines = app_client.get("/api/v1/health").json()["engines"]
    for name in ("SigmaDetector", "LogDetector", "BehavioralAnomalyDetector"):
        assert engines[name]["status"] == "Available"
