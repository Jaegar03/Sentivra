"""Mapping between Sigma's field taxonomy and Sentivra's SecurityEvent.

Only fields Sentivra genuinely has are mapped. A Sigma field with no
Sentivra equivalent (for example OriginalFileName, which comes from PE
version info that osquery's process tables don't carry) is absent, so a
rule that depends on it doesn't match. It is never approximated with a
similar-looking field.

Two Sentivra extensions, documented here and in detection-rules/sigma/README.md:
  * `Signed` ("true"/"false") on process_creation, from osquery's
    authenticode/signature tables. Absent when the status is unknown.
  * logsource category `persistence_item` for autostart entries, scheduled
    tasks, services and cron entries, with fields Kind, Name and TargetPath.
"""

from __future__ import annotations

from typing import Any

from app.events.schema import SecurityEvent, SecurityEventType

# Sigma logsource category -> the event types it applies to.
CATEGORY_EVENT_TYPES: dict[str, frozenset[SecurityEventType]] = {
    "process_creation": frozenset({SecurityEventType.PROCESS_STARTED}),
    "network_connection": frozenset({SecurityEventType.PROCESS_NETWORK_CONNECTION}),
    "file_event": frozenset({SecurityEventType.FILE_CREATED, SecurityEventType.FILE_MODIFIED}),
    "file_change": frozenset({SecurityEventType.FILE_MODIFIED}),
    "persistence_item": frozenset({SecurityEventType.PERSISTENCE_ITEM}),
}
# Windows service logs (logsource: product windows, service security) carry an EventID.
SERVICE_EVENT_TYPES = frozenset({SecurityEventType.SYSTEM_LOG, SecurityEventType.AUTHENTICATION_EVENT})


def applies(logsource: dict[str, str], event: SecurityEvent) -> bool:
    category = logsource.get("category")
    product = logsource.get("product")
    service = logsource.get("service")
    os_name = (event.metadata.get("os") or "").lower()
    if product and os_name and product != os_name:
        return False
    if category:
        return event.event_type in CATEGORY_EVENT_TYPES.get(category, frozenset())
    if service == "security" and product == "windows":
        return event.event_type in SERVICE_EVENT_TYPES and "windows_event" in event.metadata
    if service in ("auth", "sshd") and product == "linux":
        return event.event_type == SecurityEventType.AUTHENTICATION_EVENT and event.metadata.get("os") == "linux"
    return False


def to_fields(event: SecurityEvent) -> dict[str, Any]:
    """Flatten an event into Sigma field names."""
    f: dict[str, Any] = {}
    p = event.process
    if p is not None:
        f.update({
            "Image": p.executable_path,
            "ParentImage": p.parent_executable_path,
            "CommandLine": p.command_line,
            "User": p.user,
            "ProcessId": p.pid,
            "ParentProcessId": p.parent_pid,
        })
        if p.executable_sha256:
            f["Hashes"] = f"SHA256={p.executable_sha256}"
            f["sha256"] = p.executable_sha256
        if p.signed is not None:
            f["Signed"] = "true" if p.signed else "false"
    n = event.network
    if n is not None:
        f.update({
            "DestinationIp": n.dst_ip,
            "DestinationPort": n.dst_port,
            "SourceIp": n.src_ip,
            "SourcePort": n.src_port,
            "Protocol": n.protocol,
        })
        if event.event_type == SecurityEventType.PROCESS_NETWORK_CONNECTION:
            f["Initiated"] = "true"
    md = event.metadata
    if "file" in md:
        f["TargetFilename"] = md["file"].get("target_path")
    if "persistence" in md:
        f.update({"Kind": md["persistence"].get("kind"), "Name": md["persistence"].get("name"),
                  "TargetPath": md["persistence"].get("target")})
    if "windows_event" in md:
        we = md["windows_event"]
        f["EventID"] = we.get("event_id")
        f["Channel"] = we.get("channel")
        f.update({k: v for k, v in we.items() if k not in ("event_id", "channel") and not isinstance(v, (dict, list))})
    if "auth" in md:
        auth = md["auth"]
        f.update({"TargetUserName": f.get("TargetUserName", auth.get("username")),
                  "IpAddress": f.get("IpAddress", auth.get("source_ip")),
                  "Outcome": auth.get("outcome")})
    if event.content and event.content.body:
        f["Message"] = event.content.body
    return {k: v for k, v in f.items() if v is not None}
