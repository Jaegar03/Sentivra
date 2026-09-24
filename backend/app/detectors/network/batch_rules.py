"""Behavior rules over a batch of flows. Thresholds come from
detection-rules/custom/network_rules.yaml; the logic for each rule is below.

Every finding says which rule fired, for which source/destination, and the
numbers that crossed the threshold, so an analyst can check the claim
against the raw flows.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache

import numpy as np

from app.core.rules import load_yaml, rules_path
from app.detectors.network.flow import FlowRecord


@dataclass
class BehaviorFinding:
    rule: str
    category: str
    description: str
    weight: float
    mitre_key: str | None
    subject: str                  # e.g. "198.51.100.7 -> 10.0.1.12"
    details: dict = field(default_factory=dict)
    flow_count: int = 0
    members: list[FlowRecord] = field(default_factory=list, repr=False)  # the flows this finding covers


@lru_cache
def load_network_rules() -> dict:
    return (load_yaml(rules_path("custom", "network_rules.yaml")) or {}).get("rules", {})


# Explicit list rather than ipaddress.is_private: is_private also returns
# True for the RFC 5737 documentation ranges and other special-purpose
# blocks, which here stand in for internet hosts and must count as external.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
              "::1/128", "fc00::/7", "fe80::/10")
)


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS if net.version == addr.version)


def _cv(values: list[float]) -> float:
    arr = np.asarray(values, dtype=float)
    mean = arr.mean() if len(arr) else 0.0
    return float(arr.std() / mean) if mean > 0 else 0.0


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def _finding(name: str, rule: dict, subject: str, members: list[FlowRecord], **details) -> BehaviorFinding:
    return BehaviorFinding(
        rule=name,
        category=rule["category"],
        description=rule["description"],
        weight=float(rule["weight"]),
        mitre_key=rule.get("mitre"),
        subject=subject,
        details=details,
        flow_count=len(members),
        members=list(members),
    )


def _port_scan(flows, rule):
    by_pair = defaultdict(list)
    for f in flows:
        if f.protocol == "tcp":
            by_pair[(f.src_ip, f.dst_ip)].append(f)
    for (src, dst), group in by_pair.items():
        ports = {f.dst_port for f in group}
        if len(ports) < rule["min_distinct_ports"]:
            continue
        minimal = sum(f.fwd_packets + f.bwd_packets <= rule["max_packets_per_flow"] for f in group) / len(group)
        if minimal >= rule["min_fraction_minimal_flows"]:
            yield _finding("port_scan", rule, f"{src} -> {dst}", group,
                           distinct_ports=len(ports), fraction_minimal_flows=round(minimal, 2))


def _host_sweep(flows, rule):
    by_src_port = defaultdict(list)
    for f in flows:
        by_src_port[(f.src_ip, f.dst_port)].append(f)
    for (src, port), group in by_src_port.items():
        small = [f for f in group if f.fwd_packets + f.bwd_packets <= rule["max_packets_per_flow"]]
        hosts = {f.dst_ip for f in small}
        if len(hosts) >= rule["min_distinct_hosts"]:
            yield _finding("host_sweep", rule, f"{src} -> *:{port}", small, distinct_hosts=len(hosts), port=port)


def _brute_force(flows, rule):
    ports = set(rule["ports"])
    by_target = defaultdict(list)
    for f in flows:
        if f.dst_port in ports:
            by_target[(f.src_ip, f.dst_ip, f.dst_port)].append(f)
    for (src, dst, port), group in by_target.items():
        if len(group) < rule["min_connections"]:
            continue
        mean_duration = float(np.mean([f.duration_s for f in group]))
        bytes_cv = _cv([f.fwd_bytes for f in group])
        if mean_duration <= rule["max_mean_duration_s"] and bytes_cv <= rule["max_bytes_cv"]:
            yield _finding("brute_force", rule, f"{src} -> {dst}:{port}", group,
                           connections=len(group), mean_duration_s=round(mean_duration, 2),
                           bytes_cv=round(bytes_cv, 3))


def _flood(flows, rule):
    # Rate is judged per destination per time window. Measured over a whole
    # batch, unrelated traffic hours apart stretches the time span and hides
    # a burst.
    window = float(rule.get("window_s", 60))
    by_dst_window = defaultdict(list)
    for f in flows:
        by_dst_window[(f.dst_ip, int(f.start_time // window))].append(f)
    reported: set[str] = set()
    for (dst, _), group in sorted(by_dst_window.items(), key=lambda kv: kv[0][1]):
        if dst in reported:
            continue
        sources = {f.src_ip for f in group}
        if len(sources) < rule["min_sources"]:
            continue
        start = min(f.start_time for f in group)
        end = max(f.start_time + f.duration_s for f in group)
        packets = sum(f.fwd_packets for f in group)
        rate = packets / max(end - start, 1.0)
        mean_size = sum(f.fwd_bytes for f in group) / max(packets, 1)
        if rate >= rule["min_packets_per_s"] and mean_size <= rule["max_mean_packet_bytes"]:
            reported.add(dst)
            yield _finding("flood", rule, f"* -> {dst}", group, sources=len(sources),
                           packets_per_s=round(rate), mean_packet_bytes=round(mean_size, 1),
                           window_s=window)


def _bulk_outbound(flows, rule):
    by_pair = defaultdict(list)
    for f in flows:
        if _is_internal(f.src_ip) and not _is_internal(f.dst_ip):
            by_pair[(f.src_ip, f.dst_ip)].append(f)
    for (src, dst), group in by_pair.items():
        fwd = sum(f.fwd_bytes for f in group)
        bwd = sum(f.bwd_bytes for f in group)
        ratio = fwd / max(bwd, 1)
        if fwd >= rule["min_bytes"] and ratio >= rule["min_fwd_bwd_ratio"]:
            yield _finding("bulk_outbound", rule, f"{src} -> {dst}", group,
                           bytes_out=fwd, bytes_in=bwd, out_in_ratio=round(ratio, 1))


def _dns_tunneling(flows, rule):
    by_src_parent = defaultdict(list)
    for f in flows:
        if f.dst_port == 53 and f.dns_query:
            labels = f.dns_query.rstrip(".").split(".")
            parent = ".".join(labels[-2:]) if len(labels) >= 2 else f.dns_query
            by_src_parent[(f.src_ip, parent)].append((labels[0], f))
    for (src, parent), entries in by_src_parent.items():
        first_labels = [label for label, _ in entries]
        if len(first_labels) < rule["min_queries"]:
            continue
        suspicious = [
            lab for lab in first_labels
            if len(lab) >= rule["min_label_length"] and _entropy(lab) >= rule["min_label_entropy"]
        ]
        fraction = len(suspicious) / len(first_labels)
        if fraction >= rule["min_fraction_suspicious"]:
            yield _finding("dns_tunneling", rule, f"{src} -> *.{parent}", [flow for _, flow in entries],
                           queries=len(first_labels), unique_labels=len(set(first_labels)),
                           fraction_long_high_entropy=round(fraction, 2))


def _beaconing(flows, rule):
    by_pair = defaultdict(list)
    for f in flows:
        by_pair[(f.src_ip, f.dst_ip, f.dst_port)].append(f)
    # Look for a *dominant* regular interval rather than demanding every
    # connection fit: one ordinary visit to the same address shouldn't hide
    # a beacon.
    tolerance = float(rule["tolerance"])
    for (src, dst, port), group in by_pair.items():
        if len(group) < rule["min_connections"]:
            continue
        group = sorted(group, key=lambda f: f.start_time)
        intervals = np.diff([f.start_time for f in group])
        median_interval = float(np.median(intervals)) if len(intervals) else 0.0
        if median_interval < 1.0:
            continue  # sub-second repetition is a burst, not a beacon
        regular_intervals = float(np.mean(np.abs(intervals - median_interval) <= tolerance * median_interval))
        sizes = np.array([f.fwd_bytes for f in group], dtype=float)
        median_size = float(np.median(sizes))
        regular_sizes = float(np.mean(np.abs(sizes - median_size) <= tolerance * max(median_size, 1.0)))
        if regular_intervals >= rule["min_fraction_regular"] and regular_sizes >= rule["min_fraction_regular"]:
            yield _finding("beaconing", rule, f"{src} -> {dst}:{port}", group,
                           connections=len(group), median_interval_s=round(median_interval, 1),
                           fraction_regular_intervals=round(regular_intervals, 2),
                           fraction_regular_sizes=round(regular_sizes, 2))


_EVALUATORS = {
    "port_scan": _port_scan,
    "host_sweep": _host_sweep,
    "brute_force": _brute_force,
    "flood": _flood,
    "bulk_outbound": _bulk_outbound,
    "dns_tunneling": _dns_tunneling,
    "beaconing": _beaconing,
}


def evaluate(flows: list[FlowRecord]) -> list[BehaviorFinding]:
    rules = load_network_rules()
    findings: list[BehaviorFinding] = []
    for name, evaluator in _EVALUATORS.items():
        rule = rules.get(name)
        if rule:
            findings.extend(evaluator(flows, rule))
    return findings
