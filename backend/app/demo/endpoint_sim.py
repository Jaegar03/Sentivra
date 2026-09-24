"""Simulated endpoint telemetry, emitted as osquery result-log objects.

The output has the same shape osquery's loggers produce for the queries in
endpoint-agent/osquery/sentivra-pack.conf, so the demo goes through the
same normalizer (app.events.osquery) that real osquery telemetry would.

What this is and isn't:
  * Benign activity includes the legitimate cases that trip naive rules:
    signed apps that live in AppData (Teams, VS Code, OneDrive), installers
    run from Downloads, users opening shells, occasional mistyped passwords.
  * Anomaly episodes are behavioral shapes: which process started which,
    from where, what it connected to, how many files it touched. Command
    lines are neutral placeholders marked [SIMULATED]; there are no real
    attack strings or payloads here.
  * Ground truth rides in osquery's standard `decorations` field as
    `sentivra_demo_label`. No detector reads it; it's only there so
    evaluation and the UI can compare verdicts against the truth.
  * External addresses come from the RFC 5737 documentation ranges;
    hostnames are under `.example`.

The backend tags everything produced here as SourceType.SIMULATED.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass, field

import numpy as np

EXTERNAL_RANGES = ("192.0.2", "198.51.100", "203.0.113")
USERS = ("alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj")
OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"

SCENARIOS = (
    "office_spawns_interpreter",
    "unsigned_from_user_writable",
    "new_persistence_user_writable",
    "auth_password_guessing",
    "auth_password_spraying",
    "mass_file_modification",
    "event_log_cleared",
    "new_listener_user_writable",
    "linux_exec_from_tmp",
)


@dataclass
class FleetConfig:
    windows_hosts: int = 12
    linux_hosts: int = 3
    hours: float = 8.0
    episodes: dict[str, int] | None = None
    seed: int = 7

    def resolved_episodes(self) -> dict[str, int]:
        return self.episodes if self.episodes is not None else {s: 1 for s in SCENARIOS}


@dataclass
class _Host:
    name: str
    os: str
    user: str
    next_pid: int = 1000
    pids: dict[str, int] = field(default_factory=dict)  # process path -> a running pid


class _Sim:
    def __init__(self, cfg: FleetConfig) -> None:
        self.cfg = cfg
        self.rng = np.random.default_rng(cfg.seed)
        self.t0 = 1_790_000_000  # a fixed epoch so runs are reproducible
        self.span = int(cfg.hours * 3600)
        self.rows: list[dict] = []
        self.hosts = [
            _Host(f"demo-ws-{i + 1:02d}.example", "windows", USERS[i % len(USERS)]) for i in range(cfg.windows_hosts)
        ] + [_Host(f"demo-srv-{i + 1:02d}.example", "linux", "svc") for i in range(cfg.linux_hosts)]

    # ---- emit osquery rows ---------------------------------------------------
    def emit(self, host: _Host, query: str, t: int, columns: dict, label: str | None = None) -> None:
        decorations = {"hostname": host.name, "os": host.os}
        if label:
            decorations["sentivra_demo_label"] = label
        self.rows.append({
            "name": f"pack_sentivra_{query}",
            "hostIdentifier": host.name,
            "unixTime": t,
            "decorations": decorations,
            "columns": {k: "" if v is None else str(v) for k, v in {**columns, "time": t}.items()},
            "action": "added",
        })

    def ext_ip(self) -> str:
        return f"{self.rng.choice(EXTERNAL_RANGES)}.{self.rng.integers(1, 255)}"

    def rand_name(self, n: int = 8) -> str:
        return "".join(self.rng.choice(list(string.ascii_lowercase + string.digits), size=n))

    def t(self) -> int:
        return self.t0 + int(self.rng.integers(0, self.span))

    def start(self, host: _Host, t: int, path: str, parent_path: str, cmdline: str,
              signed: bool | None, label: str | None = None) -> int:
        pid = host.next_pid
        host.next_pid += int(self.rng.integers(4, 40))
        parent_pid = host.pids.get(parent_path, 4)
        host.pids[path] = pid
        sep = "\\" if host.os == "windows" else "/"
        if host.os == "windows":
            cols = {"pid": pid, "parent": parent_pid, "path": path, "cmdline": cmdline, "username": host.user,
                    "parent_name": parent_path.rsplit(sep, 1)[-1], "parent_path": parent_path,
                    "signature_result": {True: "trusted", False: "nosignature", None: None}[signed]}
            self.emit(host, "process_etw_events", t, cols, label)
        else:
            cols = {"pid": pid, "parent": parent_pid, "path": path, "cmdline": cmdline, "uid": 1000,
                    "parent_name": parent_path.rsplit(sep, 1)[-1], "parent_path": parent_path}
            self.emit(host, "process_events", t, cols, label)
        return pid

    def connect(self, host: _Host, t: int, pid: int, path: str, ip: str, port: int, label: str | None = None) -> None:
        query = "process_open_sockets" if host.os == "windows" else "socket_events"
        self.emit(host, query, t, {"pid": pid, "path": path, "action": "connect", "remote_address": ip,
                                   "remote_port": port, "local_port": int(self.rng.integers(49152, 65535)),
                                   "protocol": 6}, label)

    def file(self, host: _Host, t: int, path: str, action: str, label: str | None = None) -> None:
        self.emit(host, "file_events", t, {"target_path": path, "action": action, "sha256": "", "uid": 1000}, label)

    # ---- benign activity -------------------------------------------------------
    def benign(self) -> None:
        for host in self.hosts:
            if host.os == "windows":
                self._benign_windows(host)
            else:
                self._benign_linux(host)

    def _benign_windows(self, host: _Host) -> None:
        u = host.user
        home = rf"C:\Users\{u}"
        # Boot/logon baseline
        self.start(host, self.t0, r"C:\Windows\System32\services.exe", r"C:\Windows\System32\wininit.exe",
                   "services.exe", True)
        self.start(host, self.t0 + 1, r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe",
                   "svchost.exe -k netsvcs", True)
        self.start(host, self.t0 + 5, r"C:\Windows\explorer.exe", r"C:\Windows\System32\userinit.exe",
                   "explorer.exe", True)
        for port in (135, 445):
            self.emit(host, "listening_ports", self.t0 + 2, {"pid": host.pids[r"C:\Windows\System32\svchost.exe"],
                                                             # bandit B104: simulated osquery row; nothing binds
                                                             "port": port, "protocol": 6, "address": "0.0.0.0",  # nosec B104
                                                             "path": r"C:\Windows\System32\svchost.exe"})
        # Legitimate autostart entries, several of them in AppData
        for name, path in (("OneDrive", rf"{home}\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
                           ("Teams", rf"{home}\AppData\Local\Microsoft\Teams\Update.exe"),
                           ("SecurityHealth", r"C:\Windows\System32\SecurityHealthSystray.exe")):
            self.emit(host, "startup_items", self.t0 + 3, {"name": name, "path": path, "args": "", "type": "Startup Item",
                                                           "source": r"HKEY_CURRENT_USER\...\Run", "status": "enabled",
                                                           "username": u})
        self.emit(host, "scheduled_tasks", self.t0 + 3, {"name": r"\GoogleUpdateTaskMachineUA",
                                                         "action": r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
                                                         "path": r"\GoogleUpdateTaskMachineUA", "enabled": 1})
        self.emit(host, "windows_security_log", self.t0 + 6, {"eventid": 4624, "datetime": "", "data": json.dumps(
            {"EventData": {"TargetUserName": u, "IpAddress": "-", "LogonType": "2"}})})

        apps = [
            (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe", True, 443, 0.30),
            (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge.exe", True, 443, 0.10),
            (rf"{OFFICE}\WINWORD.EXE", r'WINWORD.EXE /n "C:\Users\{u}\Documents\report.docx"', True, 443, 0.10),
            (rf"{OFFICE}\EXCEL.EXE", "EXCEL.EXE", True, 443, 0.08),
            (rf"{OFFICE}\OUTLOOK.EXE", "OUTLOOK.EXE", True, 443, 0.08),
            (rf"{home}\AppData\Local\Microsoft\Teams\current\Teams.exe", "Teams.exe", True, 443, 0.10),
            (rf"{home}\AppData\Local\Programs\Microsoft VS Code\Code.exe", "Code.exe", True, 443, 0.08),
            (r"C:\Windows\System32\cmd.exe", "cmd.exe", True, None, 0.06),
            (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoLogo", True, None, 0.05),
            (rf"{home}\Downloads\setup_{self.rand_name(4)}.exe", "setup.exe /S", True, 443, 0.05),
        ]
        weights = np.array([a[4] for a in apps]) / sum(a[4] for a in apps)
        for _ in range(int(self.cfg.hours * 12)):
            path, cmd, signed, port, _w = apps[int(self.rng.choice(len(apps), p=weights))]
            t = self.t()
            pid = self.start(host, t, path, r"C:\Windows\explorer.exe", cmd.replace("{u}", u), signed)
            if port:
                for _ in range(int(self.rng.integers(1, 6))):
                    self.connect(host, t + int(self.rng.integers(1, 300)), pid, path, self.ext_ip(), port)
            if "WINWORD" in path or "EXCEL" in path:
                self.file(host, t + 30, rf"{home}\Documents\{self.rand_name(6)}.docx", "UPDATED")
            if "chrome" in path and self.rng.random() < 0.3:
                self.file(host, t + 20, rf"{home}\Downloads\{self.rand_name(6)}.pdf", "CREATED")
        # Occasional mistyped password: one or two failures, then success
        if self.rng.random() < 0.5:
            t = self.t()
            for i in range(int(self.rng.integers(1, 3))):
                self.emit(host, "windows_security_log", t + i * 5, {"eventid": 4625, "datetime": "", "data": json.dumps(
                    {"EventData": {"TargetUserName": u, "IpAddress": "-", "LogonType": "2"}})})
            self.emit(host, "windows_security_log", t + 20, {"eventid": 4624, "datetime": "", "data": json.dumps(
                {"EventData": {"TargetUserName": u, "IpAddress": "-", "LogonType": "2"}})})

    def _benign_linux(self, host: _Host) -> None:
        self.start(host, self.t0, "/usr/sbin/sshd", "/usr/lib/systemd/systemd", "/usr/sbin/sshd -D", None)
        self.start(host, self.t0, "/usr/sbin/cron", "/usr/lib/systemd/systemd", "/usr/sbin/cron -f", None)
        self.emit(host, "listening_ports", self.t0 + 1, {"pid": host.pids["/usr/sbin/sshd"], "port": 22, "protocol": 6,
                                                         # bandit B104: simulated osquery row; nothing binds
                                                         "address": "0.0.0.0", "path": "/usr/sbin/sshd"})  # nosec B104
        self.emit(host, "crontab", self.t0 + 1, {"event": "", "minute": "0", "hour": "2",
                                                 "command": "/usr/local/bin/backup.sh", "path": "/etc/crontab"})
        for _ in range(int(self.cfg.hours * 6)):
            t = self.t()
            self.start(host, t, "/usr/bin/bash", "/usr/sbin/sshd", "-bash", None)
            tool = self.rng.choice(["/usr/bin/python3", "/usr/bin/git", "/usr/bin/curl", "/usr/bin/ls"])
            pid = self.start(host, t + 3, str(tool), "/usr/bin/bash", f"{str(tool).rsplit('/', 1)[-1]} [routine]", None)
            if tool in ("/usr/bin/curl", "/usr/bin/git"):
                self.connect(host, t + 4, pid, str(tool), self.ext_ip(), 443)
            self.emit(host, "last", t, {"username": "svc", "tty": "pts/0", "type": 7, "host": "10.0.5.20"})
        cron_t = self.t()
        self.start(host, cron_t, "/bin/sh", "/usr/sbin/cron", "/bin/sh -c /usr/local/bin/backup.sh", None)
        self.start(host, cron_t + 1, "/usr/local/bin/backup.sh", "/bin/sh", "backup.sh", None)

    # ---- anomaly episodes ------------------------------------------------------
    def episode(self, scenario: str) -> None:
        windows = [h for h in self.hosts if h.os == "windows"]
        linux = [h for h in self.hosts if h.os == "linux"]
        host = self.rng.choice(linux if scenario.startswith("linux") else windows)
        getattr(self, f"_ep_{scenario}")(host, self.t(), scenario)

    def _ep_office_spawns_interpreter(self, h: _Host, t: int, label: str) -> None:
        word = rf"{OFFICE}\WINWORD.EXE"
        self.start(h, t, word, r"C:\Windows\explorer.exe", "WINWORD.EXE", True, label)
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        pid = self.start(h, t + 4, ps, word, "powershell.exe [SIMULATED interpreter launched by document]", True, label)
        self.connect(h, t + 6, pid, ps, self.ext_ip(), 443, label)

    def _ep_unsigned_from_user_writable(self, h: _Host, t: int, label: str) -> None:
        path = rf"C:\Users\{h.user}\AppData\Local\Temp\{self.rand_name()}.exe"
        parent = rf"{OFFICE}\OUTLOOK.EXE"
        self.start(h, t, parent, r"C:\Windows\explorer.exe", "OUTLOOK.EXE", True)
        pid = self.start(h, t + 3, path, parent, f"{path} [SIMULATED]", False, label)
        for i in range(int(self.rng.integers(3, 8))):
            self.connect(h, t + 5 + i * 30, pid, path, self.ext_ip(), int(self.rng.choice([443, 8080])), label)
        for _ in range(int(self.rng.integers(5, 15))):
            self.file(h, t + 10, rf"C:\Users\{h.user}\AppData\Local\Temp\{self.rand_name(6)}.dat", "CREATED", label)

    def _ep_new_persistence_user_writable(self, h: _Host, t: int, label: str) -> None:
        target = rf"C:\Users\{h.user}\AppData\Roaming\{self.rand_name(6)}\{self.rand_name()}.exe"
        if self.rng.random() < 0.5:
            self.emit(h, "scheduled_tasks", t, {"name": rf"\{self.rand_name(10)}", "action": target,
                                                "path": rf"\{self.rand_name(10)}", "enabled": 1}, label)
        else:
            self.emit(h, "startup_items", t, {"name": self.rand_name(8), "path": target, "args": "", "type": "Startup Item",
                                              "source": r"HKEY_CURRENT_USER\...\Run", "status": "enabled",
                                              "username": h.user}, label)

    def _ep_auth_password_guessing(self, h: _Host, t: int, label: str) -> None:
        src = self.ext_ip()
        for i in range(int(self.rng.integers(25, 80))):
            self.emit(h, "windows_security_log", t + i * 2, {"eventid": 4625, "datetime": "", "data": json.dumps(
                {"EventData": {"TargetUserName": "administrator", "IpAddress": src, "LogonType": "10"}})}, label)
        if self.rng.random() < 0.6:
            self.emit(h, "windows_security_log", t + 200, {"eventid": 4624, "datetime": "", "data": json.dumps(
                {"EventData": {"TargetUserName": "administrator", "IpAddress": src, "LogonType": "10"}})}, label)

    def _ep_auth_password_spraying(self, h: _Host, t: int, label: str) -> None:
        src = self.ext_ip()
        for i, user in enumerate(list(USERS) + [f"user{n:02d}" for n in range(10)]):
            self.emit(h, "windows_security_log", t + i * 3, {"eventid": 4625, "datetime": "", "data": json.dumps(
                {"EventData": {"TargetUserName": user, "IpAddress": src, "LogonType": "3"}})}, label)

    def _ep_mass_file_modification(self, h: _Host, t: int, label: str) -> None:
        folders = ["Documents", "Desktop", "Pictures", "Documents\\Projects", "Documents\\Finance"]
        for i in range(int(self.rng.integers(250, 600))):
            folder = folders[i % len(folders)]
            self.file(h, t + i // 10, rf"C:\Users\{h.user}\{folder}\{self.rand_name(6)}.docx.sentivra-demo",
                      "UPDATED", label)

    def _ep_event_log_cleared(self, h: _Host, t: int, label: str) -> None:
        self.emit(h, "windows_security_log", t, {"eventid": 1102, "datetime": "", "data": json.dumps(
            {"UserData": {"LogFileCleared": {"SubjectUserName": h.user}}})}, label)

    def _ep_new_listener_user_writable(self, h: _Host, t: int, label: str) -> None:
        path = rf"C:\Users\Public\{self.rand_name()}.exe"
        pid = self.start(h, t, path, r"C:\Windows\explorer.exe", f"{path} [SIMULATED]", False, label)
        self.emit(h, "listening_ports", t + 2, {"pid": pid, "port": int(self.rng.integers(20000, 40000)), "protocol": 6,
                                                # bandit B104: simulated osquery row; nothing binds
                                                "address": "0.0.0.0", "path": path}, label)  # nosec B104

    def _ep_linux_exec_from_tmp(self, h: _Host, t: int, label: str) -> None:
        # bandit B108: simulated path string; no file is created
        path = f"/tmp/.{self.rand_name(5)}/{self.rand_name(6)}"  # nosec B108
        self.start(h, t, "/usr/bin/bash", "/usr/sbin/sshd", "-bash", None)
        pid = self.start(h, t + 2, path, "/usr/bin/bash", f"{path} [SIMULATED]", None, label)
        for i in range(int(self.rng.integers(2, 6))):
            self.connect(h, t + 4 + i * 60, pid, path, self.ext_ip(), 443, label)


def simulate(cfg: FleetConfig | None = None) -> list[dict]:
    """osquery result-log objects for a simulated fleet, sorted by time."""
    cfg = cfg or FleetConfig()
    sim = _Sim(cfg)
    sim.benign()
    for scenario, count in cfg.resolved_episodes().items():
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario {scenario!r}; choose from {SCENARIOS}")
        for _ in range(count):
            sim.episode(scenario)
    sim.rows.sort(key=lambda r: r["unixTime"])
    return sim.rows


def demo_telemetry(seed: int = 2026) -> list[dict]:
    """A small fleet for the UI's endpoint demo: two hours, one episode of each scenario."""
    return simulate(FleetConfig(windows_hosts=8, linux_hosts=2, hours=2.0, seed=seed))
