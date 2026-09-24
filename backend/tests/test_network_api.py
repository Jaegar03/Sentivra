"""Network endpoints end to end: demo data, CSV and PCAP uploads, a single
network_flow event, and input validation."""

from __future__ import annotations

from app.demo.network_flows import CATEGORIES, ScenarioConfig, generate
from app.detectors.network.flow import flows_to_csv


def test_demo_endpoint_is_labeled_demo_data_and_detects_every_category(app_client):
    resp = app_client.post("/api/v1/network/demo")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_type"] == "DEMO_DATA"
    rules = {f["rule"] for f in body["network"]["behavior_findings"]}
    assert set(CATEGORIES) <= rules
    assert body["risk_assessment"]["severity"] in ("HIGH", "CRITICAL")


def test_demo_findings_carry_verified_mitre_mappings_only_where_defensible(app_client):
    findings = app_client.post("/api/v1/network/demo").json()["network"]["behavior_findings"]
    by_rule = {f["rule"]: [m["technique_id"] for m in f["mitre_attack"]] for f in findings}
    assert by_rule["port_scan"] == ["T1046"]
    assert by_rule["brute_force"] == ["T1110"]
    assert by_rule["dns_tunneling"] == ["T1071.004"]
    # Deliberately unmapped: volume and timing patterns don't identify a technique.
    assert by_rule["bulk_outbound"] == [] and by_rule["beaconing"] == []


def test_flagged_flows_are_explained(app_client):
    flagged = app_client.post("/api/v1/network/demo").json()["network"]["flagged_flows"]
    model_flagged = [f for f in flagged if len(f["fired_layers"]) >= 2]
    assert model_flagged
    assert all(f["explanations"] for f in model_flagged)


def test_csv_upload_is_live_data(app_client):
    flows = generate(ScenarioConfig(hosts=10, hours=1, episodes={"port_scan": 1}, seed=3))
    resp = app_client.post(
        "/api/v1/network/analyze",
        files={"file": ("flows.csv", flows_to_csv(flows).encode(), "text/csv")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_type"] == "LIVE" and body["input_format"] == "sentivra"
    assert "port_scan" in {f["rule"] for f in body["network"]["behavior_findings"]}


def test_benign_csv_upload_is_safe(app_client):
    flows = generate(ScenarioConfig(hosts=10, hours=1, episodes={}, seed=11))
    resp = app_client.post(
        "/api/v1/network/analyze",
        files={"file": ("benign.csv", flows_to_csv(flows).encode(), "text/csv")},
    )
    body = resp.json()
    assert body["network"]["behavior_findings"] == []
    # Some benign flows pass the fusion cut by construction; that alone must
    # not raise an alert (the multiple-comparisons problem).
    assert body["network"]["model_flag_significance"]["significant"] is False
    assert body["risk_assessment"]["severity"] == "SAFE"


def test_pcap_upload(app_client):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from tests.test_network import _write_pcap

    pkts = []
    for i, port in enumerate(range(1, 120)):  # one host probing many ports: a scan
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.50", dst="10.0.0.7") / TCP(
            sport=40000 + i, dport=port, flags="S")
        p.time = 1_700_000_000.0 + i * 0.01
        pkts.append(p)
    resp = app_client.post("/api/v1/network/analyze", files={"file": ("scan.pcap", _write_pcap(pkts), "application/octet-stream")})
    assert resp.status_code == 200
    body = resp.json()
    assert body["input_format"] == "pcap"
    assert "port_scan" in {f["rule"] for f in body["network"]["behavior_findings"]}


def test_unparseable_upload_rejected(app_client):
    resp = app_client.post("/api/v1/network/analyze", files={"file": ("x.csv", b"name,age\nbob,4\n", "text/csv")})
    assert resp.status_code == 400


def test_single_network_flow_event_scored_by_per_flow_layers(app_client):
    resp = app_client.post("/api/v1/events", json={
        "event_type": "network_flow",
        "source": "test",
        "source_type": "SIMULATED",
        "network": {"src_ip": "10.0.0.5", "dst_ip": "192.0.2.10", "src_port": 51000, "dst_port": 443,
                    "protocol": "tcp", "bytes_sent": 1800, "bytes_received": 24000,
                    "packets_sent": 14, "packets_received": 22, "duration_ms": 1600},
    })
    assert resp.status_code == 200
    # An ordinary HTTPS flow: no behavior rules can fire on one flow, and it
    # shouldn't get two model layers to agree either.
    assert resp.json()["risk_assessment"]["severity"] == "SAFE"
