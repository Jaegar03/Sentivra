"""Network anomaly detection: flow parsing, features, behavior rules, PCAP
aggregation, scoring math, and the detector itself."""

from __future__ import annotations

import os
import tempfile

import numpy as np
import pytest

from app.demo.network_flows import CATEGORIES, ScenarioConfig, demo_batch, generate
from app.detectors.network import batch_rules
from app.detectors.network.features import FEATURE_NAMES, feature_matrix, flow_features
from app.detectors.network.flow import FlowParseError, FlowRecord, flows_to_csv, parse_flow_csv
from app.detectors.network.pcap import looks_like_capture, parse_pcap
from app.detectors.network.scoring import LAYER_WEIGHTS, EmpiricalTail, LayerResult, fuse

# ---- features --------------------------------------------------------------


def test_feature_vector_matches_schema_and_is_finite():
    x = feature_matrix(demo_batch())
    assert x.shape[1] == len(FEATURE_NAMES)
    assert np.isfinite(x).all()


def test_zero_duration_single_packet_flow_has_finite_rates():
    v = flow_features(FlowRecord(dst_port=80, fwd_packets=1, fwd_bytes=60, duration_s=0.0))
    assert np.isfinite(v).all()


def test_port_encoded_as_service_flags_not_raw_number():
    v = dict(zip(FEATURE_NAMES, flow_features(FlowRecord(dst_port=53, protocol="udp")), strict=True))
    assert v["port_dns"] == 1.0 and v["port_web"] == 0.0 and v["is_udp"] == 1.0


# ---- CSV parsing -------------------------------------------------------------


def test_sentivra_csv_round_trip():
    flows = demo_batch()[:50]
    parsed, fmt = parse_flow_csv(flows_to_csv(flows).encode(), max_rows=1000)
    assert fmt == "sentivra"
    assert [p.to_dict() for p in parsed] == [f.to_dict() for f in flows]


def test_cicflowmeter_columns_mapped_and_units_converted():
    csv_bytes = (
        b" Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,"
        b"Total Length of Fwd Packets, Total Length of Bwd Packets, SYN Flag Count, Label\n"
        b"443,2500000,10,12,1200,15000,1,BENIGN\n"
        b"80,Infinity,1,0,0,0,1,DoS\n"
    )
    flows, fmt = parse_flow_csv(csv_bytes, max_rows=10)
    assert fmt == "cicflowmeter"
    assert flows[0].dst_port == 443 and flows[0].duration_s == pytest.approx(2.5)  # microseconds -> seconds
    assert flows[0].label == "BENIGN"
    assert flows[1].duration_s == 0.0  # CIC's "Infinity" doesn't leak into features


def test_csv_row_cap_is_enforced():
    flows, _ = parse_flow_csv(flows_to_csv(demo_batch()[:100]).encode(), max_rows=10)
    assert len(flows) == 10


def test_unrecognized_csv_rejected():
    with pytest.raises(FlowParseError):
        parse_flow_csv(b"name,age\nalice,30\n", max_rows=10)


# ---- behavior rules ------------------------------------------------------------


def test_no_rule_findings_on_benign_only_traffic():
    assert batch_rules.evaluate(generate(ScenarioConfig(hosts=30, hours=3, episodes={}, seed=11))) == []


@pytest.mark.parametrize("category", CATEGORIES)
def test_each_behavior_rule_fires_on_its_episode(category):
    flows = generate(ScenarioConfig(hosts=20, hours=2, episodes={category: 1}, seed=5))
    fired = {f.rule for f in batch_rules.evaluate(flows)}
    assert category in fired


def test_finding_members_are_the_episode_flows():
    flows = generate(ScenarioConfig(hosts=20, hours=2, episodes={"port_scan": 1}, seed=5))
    finding = next(f for f in batch_rules.evaluate(flows) if f.rule == "port_scan")
    assert finding.members and all(m.label == "port_scan" for m in finding.members)
    assert finding.flow_count == len(finding.members)


def test_beaconing_survives_one_unrelated_flow_to_same_destination():
    beacons = [f for f in generate(ScenarioConfig(hosts=5, hours=4, episodes={"beaconing": 1}, seed=9))
               if f.label == "beaconing"]
    stray = FlowRecord(src_ip=beacons[0].src_ip, dst_ip=beacons[0].dst_ip, dst_port=443, protocol="tcp",
                       start_time=beacons[3].start_time + 7.0, fwd_packets=40, fwd_bytes=90_000)
    assert "beaconing" in {f.rule for f in batch_rules.evaluate([*beacons, stray])}


def test_documentation_ranges_count_as_external():
    # ipaddress.is_private is True for RFC 5737 ranges; the rules must not use it.
    assert batch_rules._is_internal("10.1.2.3") and not batch_rules._is_internal("192.0.2.10")


# ---- PCAP ----------------------------------------------------------------------


def _write_pcap(packets) -> bytes:
    from scapy.utils import wrpcap

    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, packets)
        with open(path, "rb") as f:
            return f.read()
    finally:
        os.remove(path)


@pytest.fixture(scope="module")
def small_capture() -> bytes:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    def at(p, dt):
        p.time = 1_700_000_000.0 + dt
        return p

    def eth():
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    c, s = "10.0.0.5", "192.0.2.10"
    return _write_pcap([
        at(eth() / IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="S"), 0.00),
        at(eth() / IP(src=s, dst=c) / TCP(sport=443, dport=50000, flags="SA"), 0.01),
        at(eth() / IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="A") / ("x" * 200), 0.02),
        at(eth() / IP(src=s, dst=c) / TCP(sport=443, dport=50000, flags="A") / ("y" * 900), 0.03),
        at(eth() / IP(src=c, dst="10.0.0.2") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="docs.example")), 0.10),
        at(eth() / IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="S"), 200.0),  # after idle timeout
    ])


def test_pcap_detected_by_magic_bytes(small_capture):
    assert looks_like_capture(small_capture)
    assert not looks_like_capture(b"src_ip,dst_ip\n")


def test_pcap_aggregates_bidirectional_flows(small_capture):
    flows, stats = parse_pcap(small_capture, max_packets=100)
    assert stats.packets_read == 6 and not stats.truncated
    tcp = flows[0]
    assert (tcp.src_ip, tcp.dst_port, tcp.fwd_packets, tcp.bwd_packets) == ("10.0.0.5", 443, 2, 2)
    assert tcp.syn_count == 2  # SYN + SYN-ACK
    dns = next(f for f in flows if f.dst_port == 53)
    assert dns.dns_query == "docs.example"


def test_pcap_idle_timeout_starts_new_flow(small_capture):
    flows, _ = parse_pcap(small_capture, max_packets=100)
    assert sum(1 for f in flows if f.dst_port == 443) == 2


def test_pcap_packet_cap(small_capture):
    _, stats = parse_pcap(small_capture, max_packets=2)
    assert stats.truncated and stats.packets_read == 2


# ---- scoring math --------------------------------------------------------------


def test_empirical_p_values_are_monotonic_with_a_floor():
    tail = EmpiricalTail.fit(np.arange(1000, dtype=float))
    p = tail.p_value(np.array([0.0, 500.0, 990.0, 10_000.0]))
    assert list(p) == sorted(p, reverse=True)
    assert p[-1] == pytest.approx(1 / 1001)  # can't be rarer than the calibration set shows


def test_single_layer_cannot_reach_the_fusion_cut():
    # The cut is chosen on calibration data (0.615 for v0.1.0), and at that
    # cut no layer's weight alone is enough: flagging needs corroboration.
    cut = 0.615
    for layer, weight in LAYER_WEIGHTS.items():
        assert fuse([LayerResult(layer, True, 0.0)]) == pytest.approx(weight) and weight < cut
    two = fuse([LayerResult("isolation_forest", True, 0.0), LayerResult("autoencoder", True, 0.0)])
    assert two >= cut
