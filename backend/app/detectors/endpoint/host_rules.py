"""Host behavior rules over an endpoint batch. Thresholds are in
detection-rules/custom/endpoint_rules.yaml; baseline-dependent rules need a
Baseline and are skipped (and reported as such) without one."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache

from app.core.rules import load_yaml, rules_path
from app.detectors.endpoint.activity import (
    INTERPRETERS,
    Baseline,
    ProcessActivity,
    basename,
    file_extension,
    normalize_path,
    path_class,
)
from app.events.schema import SecurityEvent, SecurityEventType


@dataclass
class HostFinding:
    rule: str
    category: str
    description: str
    weight: float
    mitre_key: str | None
    host: str
    subject: str
    details: dict = field(default_factory=dict)
    events: list[SecurityEvent] = field(default_factory=list, repr=False)


@lru_cache
def load_endpoint_rules() -> dict:
    return (load_yaml(rules_path("custom", "endpoint_rules.yaml")) or {}).get("rules", {})


def _finding(rule_name: str, rule: dict, host: str, subject: str, events: list[SecurityEvent], /, *,
             weight: float | None = None, mitre_key: str | None = None, **details) -> HostFinding:
    # Positional-only parameters, so a detail such as name=... can't collide with them.
    return HostFinding(rule_name, rule["category"], rule["description"],
                       weight if weight is not None else rule["weight"], mitre_key, host, subject, details, events)


def evaluate(events: list[SecurityEvent], acts: list[ProcessActivity], baseline: Baseline | None
             ) -> tuple[list[HostFinding], list[str]]:
    """Returns (findings, names of rules skipped because no baseline is available)."""
    rules = load_endpoint_rules()
    findings: list[HostFinding] = []
    skipped = [n for n, r in rules.items() if r.get("needs_baseline") and baseline is None]

    if (rule := rules.get("unsigned_user_writable_network")):
        for act in acts:
            p = act.event.process
            if path_class(p.executable_path) == "user_writable" and p.signed is not True \
                    and act.external_connections >= rule["min_external_connections"]:
                findings.append(_finding(
                    "unsigned_user_writable_network", rule, act.host, p.executable_path,
                    [act.event, *act.connections], signed={True: "trusted", False: "untrusted/none", None: "unknown"}[p.signed],
                    external_connections=act.external_connections, distinct_remote=act.distinct_remote,
                    parent=act.parent_name))

    if baseline is not None and (rule := rules.get("new_persistence_user_writable")):
        for e in events:
            if e.event_type != SecurityEventType.PERSISTENCE_ITEM:
                continue
            item = e.metadata["persistence"]
            target = item.get("target") or ""
            if path_class(target) == "user_writable" and normalize_path(target) not in baseline.persistence_targets:
                findings.append(_finding(
                    "new_persistence_user_writable", rule, e.metadata.get("host", "?"), f"{item['kind']}: {target}",
                    [e], mitre_key=rule["mitre_by_kind"].get(item["kind"]), kind=item["kind"], name=item.get("name")))

    if baseline is not None and (rule := rules.get("new_listener_untrusted")):
        for act in acts:
            for listener in act.listeners:
                port = int(listener.metadata["listening"].get("port") or 0)
                untrusted = path_class(act.event.process.executable_path) == "user_writable" or act.event.process.signed is False
                if untrusted and (act.name, port) not in baseline.listeners:
                    findings.append(_finding(
                        "new_listener_untrusted", rule, act.host, f"{act.event.process.executable_path} :{port}",
                        [act.event, listener], port=port, signed=act.event.process.signed))

    if (rule := rules.get("mass_file_modification")):
        by_host: dict[str, list[SecurityEvent]] = defaultdict(list)
        for e in events:
            if e.event_type in (SecurityEventType.FILE_CREATED, SecurityEventType.FILE_MODIFIED):
                by_host[e.metadata.get("host", "?")].append(e)
        for host, file_events in by_host.items():
            file_events.sort(key=lambda e: e.timestamp)
            j, best = 0, (0, 0)
            for i in range(len(file_events)):
                while (file_events[i].timestamp - file_events[j].timestamp).total_seconds() > rule["window_s"]:
                    j += 1
                if i - j + 1 > best[1] - best[0]:
                    best = (j, i + 1)
            window = file_events[best[0]:best[1]]
            if len(window) < rule["min_files"]:
                continue
            paths = [e.metadata["file"].get("target_path") or "" for e in window]
            directories = {p.replace("\\", "/").rsplit("/", 1)[0] for p in paths}
            if len(directories) < rule["min_directories"]:
                continue
            novel = (sum(1 for p in paths if file_extension(p) not in baseline.file_extensions) / len(paths)
                     if baseline is not None else 0.0)
            strong = baseline is not None and novel >= rule["novel_extension_fraction"]
            findings.append(_finding(
                "mass_file_modification", rule, host, f"{len(window)} files in {rule['window_s']}s", window,
                weight=rule["weight_with_novel_extensions"] if strong else rule["weight"],
                files=len(window), directories=len(directories),
                novel_extension_fraction=round(novel, 2) if baseline is not None else "no baseline",
                sample_extensions=sorted({file_extension(p) for p in paths})[:5]))

    if baseline is not None and (rule := rules.get("rare_process_lineage")):
        for act in acts:
            pair = (act.parent_name, act.name)
            # Exact-name baselines can't handle per-download names (setup_3f9a.exe),
            # so a user-writable child only counts when it also lacks a trusted
            # signature. Signed installers run from Downloads all day.
            untrusted_user_writable = (path_class(act.event.process.executable_path) == "user_writable"
                                       and act.event.process.signed is not True)
            notable = act.name in INTERPRETERS or untrusted_user_writable
            if notable and pair not in baseline.lineage:
                findings.append(_finding(
                    "rare_process_lineage", rule, act.host, f"{pair[0]} -> {pair[1]}", [act.event],
                    parent=pair[0], child=basename(act.event.process.executable_path)))
    return findings, skipped
