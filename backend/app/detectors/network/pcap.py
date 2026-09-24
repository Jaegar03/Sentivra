"""PCAP / PCAPNG -> FlowRecords, using scapy as a parsing library.

Packets are aggregated into bidirectional flows keyed by protocol and the
unordered endpoint pair. As in CICFlowMeter, a flow is closed after 120 s
of inactivity and the next packet starts a new one. The initiator (first
packet's sender) defines the "fwd" direction.

Parsing is read-only and bounded: a capped number of packets is read and a
malformed packet is skipped, not fatal. Parsing untrusted captures is itself
an attack surface (docs/threat-model.md), so this runs only on uploads that
already passed the size limit, and nothing is ever sent onto a network.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

from app.detectors.network.flow import FlowRecord

PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
IDLE_TIMEOUT_S = 120.0


def looks_like_capture(data: bytes) -> bool:
    return data[:4] in PCAP_MAGICS or data[:4] == PCAPNG_MAGIC


@dataclass
class PcapStats:
    packets_read: int = 0
    packets_skipped: int = 0     # non-IP or unparseable
    truncated: bool = False


def parse_pcap(data: bytes, *, max_packets: int) -> tuple[list[FlowRecord], PcapStats]:
    # Imported lazily: scapy is slow to import and only this path needs it.
    from scapy.layers.dns import DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapNgReader, PcapReader

    stats = PcapStats()
    active: dict[tuple, FlowRecord] = {}
    last_seen: dict[tuple, float] = {}
    initiator: dict[tuple, str] = {}
    finished: list[FlowRecord] = []

    reader_cls = PcapNgReader if data[:4] == PCAPNG_MAGIC else PcapReader
    with reader_cls(io.BytesIO(data)) as reader:
        for pkt in reader:
            if stats.packets_read >= max_packets:
                stats.truncated = True
                break
            stats.packets_read += 1
            try:
                ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if ip is None:
                    stats.packets_skipped += 1
                    continue
                ts = float(pkt.time)
                if TCP in pkt:
                    proto, l4 = "tcp", pkt[TCP]
                    sport, dport = int(l4.sport), int(l4.dport)
                elif UDP in pkt:
                    proto, l4 = "udp", pkt[UDP]
                    sport, dport = int(l4.sport), int(l4.dport)
                elif ICMP in pkt:
                    proto, l4, sport, dport = "icmp", None, 0, 0
                else:
                    proto, l4, sport, dport = "other", None, 0, 0
                a, b = (str(ip.src), sport), (str(ip.dst), dport)
                key = (proto, *sorted((a, b)))
                size = len(ip)
            except Exception:  # noqa: BLE001 — malformed packet: skip it, keep parsing
                stats.packets_skipped += 1
                continue

            if key in active and ts - last_seen[key] > IDLE_TIMEOUT_S:
                finished.append(active.pop(key))
            flow = active.get(key)
            if flow is None:
                flow = FlowRecord(src_ip=a[0], dst_ip=b[0], src_port=a[1], dst_port=b[1],
                                  protocol=proto, start_time=ts)
                active[key] = flow
                initiator[key] = a[0]
            last_seen[key] = ts
            flow.duration_s = ts - flow.start_time

            if str(ip.src) == initiator[key]:
                flow.fwd_packets += 1
                flow.fwd_bytes += size
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += size

            if proto == "tcp":
                flags = int(l4.flags)
                flow.syn_count += bool(flags & 0x02)
                flow.rst_count += bool(flags & 0x04)
                flow.fin_count += bool(flags & 0x01)
                flow.ack_count += bool(flags & 0x10)
            if proto == "udp" and 53 in (sport, dport) and not flow.dns_query and DNSQR in pkt:
                qname = getattr(pkt[DNSQR], "qname", None)
                if isinstance(qname, bytes):  # malformed questions can leave it unset
                    flow.dns_query = qname.decode("ascii", errors="replace").rstrip(".")[:253]

    finished.extend(active.values())
    finished.sort(key=lambda f: f.start_time)
    return finished, stats
