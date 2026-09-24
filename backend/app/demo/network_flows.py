"""Synthetic network-flow generator for the demo and for training the
network models when no real capture is available.

What this data is and isn't:
  * Flows are statistical shapes (packet counts, byte counts, timing), not
    packets. Nothing here can be replayed onto a network.
  * "Internal" hosts are 10.0.0.0/16. Every "external" address comes from
    the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) and every DNS name is under the reserved `.example`
    TLD, so demo data never refers to a real host.
  * Anomalies are labeled by behavior category. The generator is
    deterministic for a given seed, which is what makes the train /
    calibration / test splits in the model card reproducible.
  * Models trained on this data are evaluated on this data. Those metrics
    show the pipeline works; they say nothing about performance on real
    traffic (docs/model-card.md repeats this next to every number).

The backend tags anything produced here as SourceType.DEMO_DATA.
"""

from __future__ import annotations

import string
from dataclasses import dataclass

import numpy as np

from app.detectors.network.flow import FlowRecord

INTERNAL_PREFIX = "10.0"
RESOLVER = "10.0.0.2"
MAIL_SERVER = "10.0.0.25"
FILE_SERVER = "10.0.0.10"
EXTERNAL_RANGES = ("192.0.2", "198.51.100", "203.0.113")
BENIGN_DOMAINS = (
    "www.example", "cdn.example", "api.example", "mail.example", "news.example",
    "docs.example", "static.example", "updates.example", "login.example", "video.example",
)

CATEGORIES = ("port_scan", "host_sweep", "brute_force", "flood", "bulk_outbound", "dns_tunneling", "beaconing")


@dataclass
class ScenarioConfig:
    hosts: int = 60
    hours: float = 8.0
    benign_flows_per_host_hour: int = 40
    episodes: dict[str, int] | None = None  # category -> number of episodes
    seed: int = 7

    def resolved_episodes(self) -> dict[str, int]:
        return self.episodes if self.episodes is not None else {c: 2 for c in CATEGORIES}


class _Gen:
    def __init__(self, cfg: ScenarioConfig) -> None:
        self.cfg = cfg
        self.rng = np.random.default_rng(cfg.seed)
        self.span = cfg.hours * 3600.0
        self.hosts = [f"{INTERNAL_PREFIX}.{1 + i // 200}.{10 + i % 200}" for i in range(cfg.hosts)]

    # -- helpers -------------------------------------------------------------
    def external_ip(self) -> str:
        return f"{self.rng.choice(EXTERNAL_RANGES)}.{self.rng.integers(1, 255)}"

    def ephemeral(self) -> int:
        return int(self.rng.integers(49152, 65535))

    def lognormal_int(self, median: float, sigma: float, low: int = 1) -> int:
        return max(low, int(self.rng.lognormal(np.log(median), sigma)))

    def t(self) -> float:
        return float(self.rng.uniform(0, self.span))

    # -- benign traffic --------------------------------------------------------
    def benign(self) -> list[FlowRecord]:
        flows: list[FlowRecord] = []
        total = int(self.cfg.hosts * self.cfg.hours * self.cfg.benign_flows_per_host_hour)
        kinds = self.rng.choice(
            ["web", "dns", "mail", "ssh_admin", "file_share", "cloud_upload"],
            size=total,
            p=[0.52, 0.30, 0.08, 0.03, 0.05, 0.02],
        )
        for kind in kinds:
            host = str(self.rng.choice(self.hosts))
            flows.append(getattr(self, f"_benign_{kind}")(host))
        return flows

    def _benign_web(self, host: str) -> FlowRecord:
        fwd_p = self.lognormal_int(12, 0.7, 3)
        bwd_p = self.lognormal_int(20, 0.9, 2)
        return FlowRecord(
            src_ip=host, dst_ip=self.external_ip(), src_port=self.ephemeral(),
            dst_port=int(self.rng.choice([443, 443, 443, 80])), protocol="tcp", start_time=self.t(),
            duration_s=float(self.rng.lognormal(np.log(1.5), 1.0)),
            fwd_packets=fwd_p, bwd_packets=bwd_p,
            fwd_bytes=fwd_p * self.lognormal_int(110, 0.4, 60),
            bwd_bytes=bwd_p * self.lognormal_int(900, 0.5, 60),
            syn_count=1, fin_count=2, ack_count=fwd_p + bwd_p - 1, label="benign",
        )

    def _benign_dns(self, host: str) -> FlowRecord:
        return FlowRecord(
            src_ip=host, dst_ip=RESOLVER, src_port=self.ephemeral(), dst_port=53, protocol="udp",
            start_time=self.t(), duration_s=float(self.rng.uniform(0.002, 0.08)),
            fwd_packets=1, bwd_packets=1,
            fwd_bytes=int(self.rng.integers(55, 90)), bwd_bytes=int(self.rng.integers(90, 320)),
            dns_query=str(self.rng.choice(BENIGN_DOMAINS)), label="benign",
        )

    def _benign_mail(self, host: str) -> FlowRecord:
        fwd_p = self.lognormal_int(15, 0.6, 4)
        return FlowRecord(
            src_ip=host, dst_ip=MAIL_SERVER, src_port=self.ephemeral(),
            dst_port=int(self.rng.choice([993, 587])), protocol="tcp", start_time=self.t(),
            duration_s=float(self.rng.lognormal(np.log(3.0), 0.8)),
            fwd_packets=fwd_p, bwd_packets=fwd_p + int(self.rng.integers(0, 10)),
            fwd_bytes=fwd_p * self.lognormal_int(300, 0.6, 60),
            bwd_bytes=fwd_p * self.lognormal_int(700, 0.7, 60),
            syn_count=1, fin_count=2, ack_count=2 * fwd_p, label="benign",
        )

    def _benign_ssh_admin(self, host: str) -> FlowRecord:
        fwd_p = self.lognormal_int(300, 0.8, 20)
        return FlowRecord(
            src_ip=host, dst_ip=FILE_SERVER, src_port=self.ephemeral(), dst_port=22, protocol="tcp",
            start_time=self.t(), duration_s=float(self.rng.lognormal(np.log(600), 0.8)),
            fwd_packets=fwd_p, bwd_packets=int(fwd_p * 1.2),
            fwd_bytes=fwd_p * self.lognormal_int(90, 0.3, 60), bwd_bytes=fwd_p * self.lognormal_int(160, 0.4, 60),
            syn_count=1, fin_count=2, ack_count=2 * fwd_p, label="benign",
        )

    def _benign_file_share(self, host: str) -> FlowRecord:
        fwd_p = self.lognormal_int(400, 1.0, 10)
        return FlowRecord(
            src_ip=host, dst_ip=FILE_SERVER, src_port=self.ephemeral(), dst_port=445, protocol="tcp",
            start_time=self.t(), duration_s=float(self.rng.lognormal(np.log(20), 1.0)),
            fwd_packets=fwd_p, bwd_packets=int(fwd_p * 1.5),
            fwd_bytes=fwd_p * self.lognormal_int(400, 0.8, 60), bwd_bytes=fwd_p * self.lognormal_int(1200, 0.6, 60),
            syn_count=1, fin_count=2, ack_count=2 * fwd_p, label="benign",
        )

    def _benign_cloud_upload(self, host: str) -> FlowRecord:
        # Legitimate large uploads (backups, sync). These make "big outbound"
        # alone insufficient to call something exfiltration.
        fwd_bytes = self.lognormal_int(8_000_000, 0.9, 500_000)
        fwd_p = fwd_bytes // 1400
        return FlowRecord(
            src_ip=host, dst_ip=self.external_ip(), src_port=self.ephemeral(), dst_port=443, protocol="tcp",
            start_time=self.t(), duration_s=fwd_bytes / float(self.rng.uniform(1e6, 8e6)),
            fwd_packets=fwd_p, bwd_packets=fwd_p // 2, fwd_bytes=fwd_bytes, bwd_bytes=(fwd_p // 2) * 60,
            syn_count=1, fin_count=2, ack_count=fwd_p, label="benign",
        )

    # -- anomaly episodes ------------------------------------------------------
    def episode(self, category: str) -> list[FlowRecord]:
        return getattr(self, f"_episode_{category}")(self.t())

    def _episode_port_scan(self, t0: float) -> list[FlowRecord]:
        src, dst = self.external_ip(), str(self.rng.choice(self.hosts))
        ports = self.rng.choice(np.arange(1, 10000), size=int(self.rng.integers(300, 900)), replace=False)
        return [
            FlowRecord(src_ip=src, dst_ip=dst, src_port=self.ephemeral(), dst_port=int(p), protocol="tcp",
                       start_time=t0 + i * 0.01, duration_s=float(self.rng.uniform(0, 0.002)),
                       fwd_packets=1, bwd_packets=int(self.rng.integers(0, 2)), fwd_bytes=60,
                       bwd_bytes=0, syn_count=1, rst_count=1, label="port_scan")
            for i, p in enumerate(ports)
        ]

    def _episode_host_sweep(self, t0: float) -> list[FlowRecord]:
        src = str(self.rng.choice(self.hosts))
        port = int(self.rng.choice([445, 22, 3389]))
        targets = [f"{INTERNAL_PREFIX}.{self.rng.integers(1, 5)}.{h}" for h in range(1, int(self.rng.integers(80, 200)))]
        return [
            FlowRecord(src_ip=src, dst_ip=dst, src_port=self.ephemeral(), dst_port=port, protocol="tcp",
                       start_time=t0 + i * 0.05, duration_s=float(self.rng.uniform(0, 0.01)),
                       fwd_packets=int(self.rng.integers(1, 3)), bwd_packets=int(self.rng.integers(0, 2)),
                       fwd_bytes=60, bwd_bytes=int(self.rng.choice([0, 54])), syn_count=1, rst_count=1,
                       label="host_sweep")
            for i, dst in enumerate(targets)
        ]

    def _episode_brute_force(self, t0: float) -> list[FlowRecord]:
        src, dst = self.external_ip(), FILE_SERVER
        port = int(self.rng.choice([22, 3389]))
        out = []
        for i in range(int(self.rng.integers(60, 250))):
            fwd_p = int(self.rng.integers(10, 16))
            out.append(FlowRecord(
                src_ip=src, dst_ip=dst, src_port=self.ephemeral(), dst_port=port, protocol="tcp",
                start_time=t0 + i * float(self.rng.uniform(1.0, 3.0)), duration_s=float(self.rng.uniform(0.8, 2.5)),
                fwd_packets=fwd_p, bwd_packets=fwd_p - 1, fwd_bytes=fwd_p * int(self.rng.integers(95, 130)),
                bwd_bytes=(fwd_p - 1) * int(self.rng.integers(90, 140)), syn_count=1, fin_count=2,
                ack_count=2 * fwd_p, label="brute_force"))
        return out

    def _episode_flood(self, t0: float) -> list[FlowRecord]:
        dst = str(self.rng.choice(self.hosts))
        out = []
        for _ in range(int(self.rng.integers(60, 180))):
            packets = int(self.rng.integers(20_000, 120_000))
            duration = float(self.rng.uniform(5, 15))
            out.append(FlowRecord(
                src_ip=self.external_ip(), dst_ip=dst, src_port=self.ephemeral(), dst_port=80, protocol="tcp",
                start_time=t0 + float(self.rng.uniform(0, 5)), duration_s=duration, fwd_packets=packets,
                bwd_packets=int(packets * self.rng.uniform(0, 0.02)), fwd_bytes=packets * 60,
                bwd_bytes=int(packets * 0.01) * 54, syn_count=packets, label="flood"))
        return out

    def _episode_bulk_outbound(self, t0: float) -> list[FlowRecord]:
        src, dst = str(self.rng.choice(self.hosts)), self.external_ip()
        out = []
        for i in range(int(self.rng.integers(1, 4))):
            fwd_bytes = int(self.rng.uniform(250e6, 1.5e9))
            fwd_p = fwd_bytes // 1400
            out.append(FlowRecord(
                src_ip=src, dst_ip=dst, src_port=self.ephemeral(), dst_port=443, protocol="tcp",
                start_time=t0 + i * 900, duration_s=fwd_bytes / float(self.rng.uniform(2e6, 1e7)),
                fwd_packets=fwd_p, bwd_packets=fwd_p // 3, fwd_bytes=fwd_bytes, bwd_bytes=(fwd_p // 3) * 60,
                syn_count=1, fin_count=2, ack_count=fwd_p, label="bulk_outbound"))
        return out

    def _episode_dns_tunneling(self, t0: float) -> list[FlowRecord]:
        src = str(self.rng.choice(self.hosts))
        alphabet = np.array(list(string.ascii_lowercase + string.digits))
        out = []
        for i in range(int(self.rng.integers(200, 600))):
            label = "".join(self.rng.choice(alphabet, size=int(self.rng.integers(40, 60))))
            out.append(FlowRecord(
                src_ip=src, dst_ip=RESOLVER, src_port=self.ephemeral(), dst_port=53, protocol="udp",
                start_time=t0 + i * float(self.rng.uniform(0.2, 1.0)), duration_s=float(self.rng.uniform(0.01, 0.1)),
                fwd_packets=1, bwd_packets=1, fwd_bytes=int(self.rng.integers(120, 200)),
                bwd_bytes=int(self.rng.integers(150, 260)), dns_query=f"{label}.t.tunnel-demo.example",
                label="dns_tunneling"))
        return out

    def _episode_beaconing(self, t0: float) -> list[FlowRecord]:
        src, dst = str(self.rng.choice(self.hosts)), self.external_ip()
        interval = float(self.rng.choice([30.0, 60.0, 120.0]))
        out = []
        for i in range(int(self.rng.integers(30, 120))):
            out.append(FlowRecord(
                src_ip=src, dst_ip=dst, src_port=self.ephemeral(), dst_port=443, protocol="tcp",
                start_time=t0 + i * interval + float(self.rng.normal(0, interval * 0.02)),
                duration_s=float(self.rng.uniform(0.2, 0.4)), fwd_packets=6, bwd_packets=5,
                fwd_bytes=int(self.rng.integers(330, 360)), bwd_bytes=int(self.rng.integers(480, 520)),
                syn_count=1, fin_count=2, ack_count=10, label="beaconing"))
        return out


def generate(cfg: ScenarioConfig | None = None) -> list[FlowRecord]:
    """Benign background plus the configured anomaly episodes, sorted by time."""
    cfg = cfg or ScenarioConfig()
    gen = _Gen(cfg)
    flows = gen.benign()
    for category, count in cfg.resolved_episodes().items():
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category {category!r}; choose from {CATEGORIES}")
        for _ in range(count):
            flows.extend(gen.episode(category))
    flows.sort(key=lambda f: f.start_time)
    return flows


def demo_batch(seed: int = 2026) -> list[FlowRecord]:
    """A small batch for the UI's "use sample data" button: two hours of
    traffic, one episode of each category."""
    return generate(ScenarioConfig(hosts=30, hours=2.0, benign_flows_per_host_hour=30,
                                   episodes={c: 1 for c in CATEGORIES}, seed=seed))
