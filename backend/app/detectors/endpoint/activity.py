"""Per-process activity summaries built from a batch of endpoint events, and
the path/lineage helpers the behavior rules and the Isolation Forest share.

A process's activity is everything in the batch attributable to it by
(host, pid): outbound connections, listening sockets and child processes.
osquery's file_events have no pid, so file activity is judged per host by
the rules, not per process.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field

import numpy as np

from app.events.schema import SecurityEvent, SecurityEventType

OFFICE_APPS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"})
BROWSERS = frozenset({"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"})
INTERPRETERS = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                          "bash", "sh", "zsh", "dash", "python", "python3", "perl", "ruby", "node"})
SYSTEM_PARENTS = frozenset({"services.exe", "wininit.exe", "userinit.exe", "svchost.exe", "systemd", "cron", "init",
                            "launchd", "sshd"})

_USER_WRITABLE = (
    re.compile(r"^[a-z]:\\users\\[^\\]+\\(appdata|downloads|desktop)\\", re.IGNORECASE),
    re.compile(r"^[a-z]:\\users\\public\\", re.IGNORECASE),
    re.compile(r"^[a-z]:\\(windows\\temp|programdata|temp)\\", re.IGNORECASE),
    re.compile(r"^/(tmp|var/tmp|dev/shm)/"),
    re.compile(r"^/home/[^/]+/"),
    re.compile(r"^/users/[^/]+/(downloads|desktop|library/caches)/", re.IGNORECASE),
)
_SYSTEM = (
    re.compile(r"^[a-z]:\\windows\\", re.IGNORECASE),
    re.compile(r"^/(usr/)?(s?bin|lib|libexec)/"),
    re.compile(r"^/(system|usr/libexec)/", re.IGNORECASE),
)
_PROGRAM_FILES = (re.compile(r"^[a-z]:\\program files( \(x86\))?\\", re.IGNORECASE), re.compile(r"^/(opt|applications)/", re.IGNORECASE))
_USER_SEGMENT = (re.compile(r"(\\users\\)[^\\]+(\\)", re.IGNORECASE), re.compile(r"(/home/)[^/]+(/)"),
                 re.compile(r"(/users/)[^/]+(/)", re.IGNORECASE))


def path_class(path: str | None) -> str:
    if not path:
        return "unknown"
    if any(p.search(path) for p in _USER_WRITABLE):
        return "user_writable"
    if any(p.search(path) for p in _SYSTEM):
        return "system"
    if any(p.search(path) for p in _PROGRAM_FILES):
        return "program_files"
    return "other"


def normalize_path(path: str | None) -> str:
    """Lowercase, with the user-name segment replaced, so a baseline learned
    on alice's machine recognizes the same program on bob's."""
    if not path:
        return ""
    out = path.lower()
    for pattern in _USER_SEGMENT:
        out = pattern.sub(r"\1<user>\2", out)
    return out


def basename(path: str | None) -> str:
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def is_external(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    internal = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                "::1/128", "fc00::/7", "fe80::/10")
    return not any(addr in ipaddress.ip_network(n) for n in internal if ipaddress.ip_network(n).version == addr.version)


@dataclass
class ProcessActivity:
    event: SecurityEvent
    host: str
    pid: int | None
    connections: list[SecurityEvent] = field(default_factory=list)
    listeners: list[SecurityEvent] = field(default_factory=list)
    children: int = 0

    @property
    def name(self) -> str:
        return basename(self.event.process.executable_path) or (self.event.process.name or "").lower()

    @property
    def parent_name(self) -> str:
        p = self.event.process
        return (p.parent_name or basename(p.parent_executable_path)).lower()

    @property
    def external_connections(self) -> int:
        return sum(1 for c in self.connections if is_external(c.network.dst_ip if c.network else None))

    @property
    def distinct_remote(self) -> int:
        return len({c.network.dst_ip for c in self.connections if c.network})


def summarize(events: list[SecurityEvent]) -> list[ProcessActivity]:
    """One ProcessActivity per process start, with later activity attributed
    by (host, pid). A pid reused later in the batch starts a new process."""
    current: dict[tuple[str, int], ProcessActivity] = {}
    out: list[ProcessActivity] = []
    for e in events:
        host = e.metadata.get("host") or "?"
        pid = e.process.pid if e.process else None
        if e.event_type == SecurityEventType.PROCESS_STARTED and e.process:
            act = ProcessActivity(event=e, host=host, pid=pid)
            out.append(act)
            if pid is not None:
                current[(host, pid)] = act
            parent = current.get((host, e.process.parent_pid)) if e.process.parent_pid is not None else None
            if parent is not None:
                parent.children += 1
        elif pid is not None and (host, pid) in current:
            if e.event_type == SecurityEventType.PROCESS_NETWORK_CONNECTION:
                current[(host, pid)].connections.append(e)
            elif e.event_type == SecurityEventType.LISTENING_PORT:
                current[(host, pid)].listeners.append(e)
    return out


FEATURE_NAMES: tuple[str, ...] = (
    "path_system", "path_program_files", "path_user_writable", "path_other",
    "signed_true", "signed_false", "signed_unknown",
    "parent_office", "parent_browser", "parent_interpreter", "parent_system",
    "is_interpreter",
    "log_connections", "log_distinct_remote", "log_external_connections", "log_children", "listening_ports",
    "log_cmdline_length",
)


def features(act: ProcessActivity) -> np.ndarray:
    p = act.event.process
    cls = path_class(p.executable_path)
    parent = act.parent_name
    return np.array([
        cls == "system", cls == "program_files", cls == "user_writable", cls in ("other", "unknown"),
        p.signed is True, p.signed is False, p.signed is None,
        parent in OFFICE_APPS, parent in BROWSERS, parent in INTERPRETERS, parent in SYSTEM_PARENTS,
        act.name in INTERPRETERS,
        math.log1p(len(act.connections)), math.log1p(act.distinct_remote), math.log1p(act.external_connections),
        math.log1p(act.children), float(len(act.listeners)),
        math.log1p(len(p.command_line or "")),
    ], dtype=np.float64)


def feature_matrix(acts: list[ProcessActivity]) -> np.ndarray:
    if not acts:
        return np.zeros((0, len(FEATURE_NAMES)))
    return np.vstack([features(a) for a in acts])


@dataclass
class Baseline:
    """What normal looks like, learned from benign training telemetry."""

    lineage: set[tuple[str, str]] = field(default_factory=set)      # (parent name, child name)
    persistence_targets: set[str] = field(default_factory=set)      # normalized paths
    listeners: set[tuple[str, int]] = field(default_factory=set)    # (process name, port)
    file_extensions: set[str] = field(default_factory=set)

    @classmethod
    def learn(cls, events: list[SecurityEvent]) -> Baseline:
        b = cls()
        for act in summarize(events):
            b.lineage.add((act.parent_name, act.name))
        for e in events:
            if e.event_type == SecurityEventType.PERSISTENCE_ITEM:
                b.persistence_targets.add(normalize_path(e.metadata["persistence"].get("target")))
            elif e.event_type == SecurityEventType.LISTENING_PORT and e.process:
                b.listeners.add((basename(e.process.executable_path), int(e.metadata["listening"]["port"] or 0)))
            elif e.event_type in (SecurityEventType.FILE_CREATED, SecurityEventType.FILE_MODIFIED):
                b.file_extensions.add(file_extension(e.metadata["file"].get("target_path")))
        return b

    def to_dict(self) -> dict:
        return {"lineage": sorted(list(x) for x in self.lineage),
                "persistence_targets": sorted(self.persistence_targets),
                "listeners": sorted(list(x) for x in self.listeners),
                "file_extensions": sorted(self.file_extensions)}

    @classmethod
    def from_dict(cls, d: dict) -> Baseline:
        return cls({tuple(x) for x in d["lineage"]}, set(d["persistence_targets"]),
                   {(x[0], int(x[1])) for x in d["listeners"]}, set(d["file_extensions"]))


def file_extension(path: str | None) -> str:
    name = basename(path)
    return name.rsplit(".", 1)[-1] if "." in name else ""
