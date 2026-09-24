"""Endpoints the dashboard depends on: alert annotation and status changes,
metrics aggregates, the audit log, and integration status."""

from __future__ import annotations

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode("ascii")


def _make_alert(app_client) -> str:
    body = app_client.post("/api/v1/analyze/file", files={"file": ("eicar.txt", EICAR, "text/plain")}).json()
    return body["risk_assessment"]["assessment_id"]


def test_alerts_carry_source_type_and_status(app_client):
    alert_id = _make_alert(app_client)
    listing = app_client.get("/api/v1/alerts").json()
    alert = next(a for a in listing if a["assessment_id"] == alert_id)
    assert alert["status"] == "OPEN"
    assert alert["event"]["source_type"] == "LIVE" and alert["event"]["event_type"] == "file_analysis"
    body = app_client.post("/api/v1/analyze/file", files={"file": ("x.txt", b"hello", "text/plain")}).json()
    assert body["source_type"] == "LIVE"  # every analysis response carries its input label
    detail = app_client.get(f"/api/v1/alerts/{alert_id}").json()
    assert detail["event"]["attachments"][0]["filename"] == "eicar.txt"


def test_status_change_is_applied_and_audited(app_client):
    alert_id = _make_alert(app_client)
    resp = app_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "ACKNOWLEDGED", "note": "triaging"})
    assert resp.status_code == 200 and resp.json() == {"alert_id": alert_id, "status": "ACKNOWLEDGED",
                                                        "previous_status": "OPEN"}
    audit = app_client.get("/api/v1/audit", params={"action": "alert_status_change"}).json()
    entry = next(e for e in audit["entries"] if e["resource"] == f"alert:{alert_id}")
    assert entry["detail"] == {"from": "OPEN", "to": "ACKNOWLEDGED", "note": "triaging"}


def test_invalid_status_rejected(app_client):
    alert_id = _make_alert(app_client)
    assert app_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "DELETED"}).status_code == 422


def test_severity_filter_is_applied_before_the_page_limit(app_client):
    for _ in range(3):
        _make_alert(app_client)
    app_client.post("/api/v1/network/demo")  # adds a HIGH/CRITICAL alert on top
    page = app_client.get("/api/v1/alerts", params={"min_severity": "HIGH", "limit": 1}).json()
    assert len(page) == 1 and page[0]["severity"] in ("HIGH", "CRITICAL")


def test_metrics_aggregates_and_explained_score(app_client):
    _make_alert(app_client)
    body = app_client.get("/api/v1/metrics", params={"window_hours": 24}).json()
    window = body["window"]
    assert window["alerts"] >= 1 and sum(window["timeline"]["counts"]) == window["alerts"]
    assert set(window["by_severity"]) == {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert "MalwareDetector" in window["by_detector"] or "YaraDetector" in window["by_detector"]
    score = body["security_score"]
    assert 0 <= score["value"] <= 100 and "open CRITICAL" in score["formula"] and score["note"]


def test_integrations_report_honest_status(app_client):
    items = {i["name"]: i for i in app_client.get("/api/v1/integrations").json()}
    for name in ("Gmail", "Telegram", "WhatsApp Business"):
        assert items[name]["status"] == "Not implemented"
    assert items["Suricata"]["status"] == "Not implemented"
    assert items["osquery"]["status"] == "Available"
    assert items["YARA"]["status"] == "Available"
    assert items["ClamAV"]["status"] == "Not configured"


def test_setting_an_engine_path_does_not_claim_coverage(app_client, monkeypatch):
    # Regression: a configured SURICATA_EVE_LOG / ZEEK_LOG_DIR used to show
    # "Available", though nothing reads those logs.
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "suricata_eve_log", "/var/log/suricata/eve.json")
    monkeypatch.setattr(get_settings(), "zeek_log_dir", "/opt/zeek/logs/current")
    items = {i["name"]: i for i in app_client.get("/api/v1/integrations").json()}
    for name in ("Suricata", "Zeek"):
        assert items[name]["status"] == "Not implemented"
        assert "nothing reads it yet" in items[name]["detail"]
    findings = app_client.post("/api/v1/network/demo").json()["findings"]
    notes = [e["detail"] for f in findings for e in f["evidence"] if e["type"] == "engine_status"]
    assert any(n.startswith("Suricata: Not implemented") and "nothing reads it yet" in n for n in notes)
