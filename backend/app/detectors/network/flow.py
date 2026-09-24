"""FlowRecord — one bidirectional network flow, and parsers that produce it.

Flows can come from three places, all normalized into this one shape:
  * a CSV using Sentivra's own column names (the demo generator writes these),
  * a CSV exported by CICFlowMeter (the format of CIC-IDS2017), mapped by
    column name,
  * a PCAP, aggregated packet-by-packet in app.detectors.network.pcap.

"fwd" is the direction of the flow's first packet (the initiator), "bwd" is
the responder, the same convention CICFlowMeter uses.
"""

from __future__ import annotations

import csv
import io
import math
from dataclasses import asdict, dataclass, field


@dataclass
class FlowRecord:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"          # "tcp" | "udp" | "icmp" | "other"
    start_time: float = 0.0        # seconds since epoch (or since capture start)
    duration_s: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    ack_count: int = 0
    dns_query: str = ""
    label: str = ""                # ground truth when known (demo/CIC data); never used as a feature
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("extra")
        return d


_SENTIVRA_COLUMNS = {f for f in FlowRecord.__dataclass_fields__ if f != "extra"}

# CICFlowMeter / CIC-IDS2017 column names -> FlowRecord fields. The CIC CSVs
# pad some headers with a leading space, so names are stripped before lookup.
_CIC_COLUMNS = {
    "Source IP": "src_ip",
    "Src IP": "src_ip",
    "Destination IP": "dst_ip",
    "Dst IP": "dst_ip",
    "Source Port": "src_port",
    "Src Port": "src_port",
    "Destination Port": "dst_port",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Flow Duration": "duration_s",          # microseconds in CIC; converted below
    "Total Fwd Packets": "fwd_packets",
    "Tot Fwd Pkts": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Tot Bwd Pkts": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "TotLen Fwd Pkts": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "TotLen Bwd Pkts": "bwd_bytes",
    "SYN Flag Count": "syn_count",
    "SYN Flag Cnt": "syn_count",
    "RST Flag Count": "rst_count",
    "RST Flag Cnt": "rst_count",
    "FIN Flag Count": "fin_count",
    "FIN Flag Cnt": "fin_count",
    "ACK Flag Count": "ack_count",
    "ACK Flag Cnt": "ack_count",
    "Label": "label",
}
_IANA_PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp"}
_INT_FIELDS = {"src_port", "dst_port", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
               "syn_count", "rst_count", "fin_count", "ack_count"}
_FLOAT_FIELDS = {"start_time", "duration_s"}


class FlowParseError(ValueError):
    pass


def _coerce(field_name: str, value: str) -> object:
    value = value.strip()
    if field_name in _INT_FIELDS:
        try:
            return max(0, int(float(value)))
        except ValueError:
            return 0
    if field_name in _FLOAT_FIELDS:
        try:
            v = float(value)
        except ValueError:
            return 0.0
        return v if math.isfinite(v) else 0.0  # CIC-IDS2017 CSVs contain NaN and Infinity
    if field_name == "protocol":
        return _IANA_PROTOCOLS.get(value, value.lower() or "other")
    return value


def parse_flow_csv(data: bytes, *, max_rows: int) -> tuple[list[FlowRecord], str]:
    """Parse a flow CSV. Returns (flows, detected_format). Rows beyond
    `max_rows` are ignored, so an upload can't create unbounded work."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FlowParseError("CSV must be UTF-8 text") from exc

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise FlowParseError("CSV has no header row")
    headers = [h.strip() for h in reader.fieldnames]

    if {"fwd_packets", "fwd_bytes"} <= set(headers):
        mapping, fmt = {h: h for h in headers if h in _SENTIVRA_COLUMNS}, "sentivra"
    elif any(h in _CIC_COLUMNS for h in headers):
        mapping, fmt = {h: _CIC_COLUMNS[h] for h in headers if h in _CIC_COLUMNS}, "cicflowmeter"
    else:
        raise FlowParseError("Unrecognized CSV columns: expected Sentivra flow columns or CICFlowMeter columns")

    flows: list[FlowRecord] = []
    for row in reader:
        if len(flows) >= max_rows:
            break
        record = FlowRecord()
        for raw_header, value in row.items():
            if raw_header is None or value is None:
                continue
            target = mapping.get(raw_header.strip())
            if target:
                setattr(record, target, _coerce(target, value))
        if fmt == "cicflowmeter":
            record.duration_s = record.duration_s / 1_000_000  # CIC reports microseconds
        flows.append(record)
    return flows, fmt


def flows_to_csv(flows: list[FlowRecord]) -> str:
    columns = [f for f in FlowRecord.__dataclass_fields__ if f != "extra"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns)
    writer.writeheader()
    for f in flows:
        writer.writerow(f.to_dict())
    return buf.getvalue()
