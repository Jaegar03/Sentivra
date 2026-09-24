"""Per-flow feature vector — the single definition shared by training
(research/experiments/train_network_models.py) and inference, so a model is
never served features computed differently from the ones it learned on.

Heavy-tailed counts (bytes, packets, rates) are log1p-transformed: raw
byte counts span nine orders of magnitude, and without the transform a
tree- or distance-based model spends all its capacity on the largest
flows. Destination port is encoded as service-class flags instead of a raw
number, because port 443 isn't numerically "close" to port 445 in any
useful sense.
"""

from __future__ import annotations

import math

import numpy as np

from app.detectors.network.flow import FlowRecord

AUTH_PORTS = frozenset({21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900})
WEB_PORTS = frozenset({80, 443, 8080, 8443})
MAIL_PORTS = frozenset({25, 110, 143, 465, 587, 993, 995})

FEATURE_NAMES: tuple[str, ...] = (
    "log_duration_s",
    "log_fwd_packets",
    "log_bwd_packets",
    "log_fwd_bytes",
    "log_bwd_bytes",
    "log_bytes_per_s",
    "log_packets_per_s",
    "mean_fwd_packet_size",
    "mean_bwd_packet_size",
    "log_fwd_bwd_byte_ratio",
    "no_response",
    "syn_ratio",
    "rst_ratio",
    "fin_ratio",
    "is_tcp",
    "is_udp",
    "port_web",
    "port_dns",
    "port_auth",
    "port_mail",
    "port_ephemeral",
)


def flow_features(flow: FlowRecord) -> np.ndarray:
    packets = flow.fwd_packets + flow.bwd_packets
    total_bytes = flow.fwd_bytes + flow.bwd_bytes
    # Floor the duration so single-packet flows don't produce infinite rates.
    duration = max(flow.duration_s, 1e-3)
    tcp_packets = max(packets, 1)
    port = flow.dst_port
    return np.array(
        [
            math.log1p(flow.duration_s),
            math.log1p(flow.fwd_packets),
            math.log1p(flow.bwd_packets),
            math.log1p(flow.fwd_bytes),
            math.log1p(flow.bwd_bytes),
            math.log1p(total_bytes / duration),
            math.log1p(packets / duration),
            flow.fwd_bytes / max(flow.fwd_packets, 1),
            flow.bwd_bytes / max(flow.bwd_packets, 1),
            math.log1p(flow.fwd_bytes) - math.log1p(flow.bwd_bytes),
            1.0 if flow.bwd_packets == 0 else 0.0,
            flow.syn_count / tcp_packets,
            flow.rst_count / tcp_packets,
            flow.fin_count / tcp_packets,
            1.0 if flow.protocol == "tcp" else 0.0,
            1.0 if flow.protocol == "udp" else 0.0,
            1.0 if port in WEB_PORTS else 0.0,
            1.0 if port == 53 else 0.0,
            1.0 if port in AUTH_PORTS else 0.0,
            1.0 if port in MAIL_PORTS else 0.0,
            1.0 if port >= 49152 else 0.0,
        ],
        dtype=np.float64,
    )


def feature_matrix(flows: list[FlowRecord]) -> np.ndarray:
    if not flows:
        return np.zeros((0, len(FEATURE_NAMES)))
    return np.vstack([flow_features(f) for f in flows])
