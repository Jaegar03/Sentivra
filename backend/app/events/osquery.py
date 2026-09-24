"""osquery result logs -> SecurityEvents.

Accepts the three shapes osquery's loggers emit:
  * event format:     {"name", "hostIdentifier", "unixTime", "columns": {...}, "action": "added"}
  * batch format:     {"name", ..., "diffResults": {"added": [...], "removed": [...]}}
  * snapshot format:  {"name", ..., "snapshot": [...]}

Which table a row came from isn't in the log itself; osquery only records the
query name. The normalizer recognizes the query names used in
endpoint-agent/osquery/sentivra-pack.conf (they contain the table name), so
deploying that pack is what makes real telemetry and the simulator share one
code path. Only "added" rows and snapshot rows become events; a "removed"
row just means something stopped existing (a process exited).

`decorations` is osquery's standard way to attach host metadata to every
row. `hostname` and `os` are read from it, and so is `sentivra_demo_label`,
which only the simulator sets (ground truth, never used by any detector).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from app.events.schema import (
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SecurityEventType,
    SourceType,
)

# Checked in order: more specific names first ("process_etw_events" before "processes").
_QUERY_KINDS = (
    ("process_etw_events", "process"),
    ("process_events", "process"),
    ("processes", "process"),
    ("socket_events", "connection"),
    ("process_open_sockets", "connection"),
    ("listening_ports", "listening"),
    ("file_events", "file"),
    ("startup_items", "persistence:startup_item"),
    ("scheduled_tasks", "persistence:scheduled_task"),
    ("services", "persistence:service"),
    ("crontab", "persistence:cron"),
    ("windows_security_log", "windows_security"),
    ("windows_eventlog", "windows_security"),
    ("last", "login"),
)

_WINDOWS_AUTH_EVENTS = {4624: "success", 4625: "failure"}


class OsqueryParseError(ValueError):
    pass


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _kind_for(query_name: str) -> str | None:
    name = query_name.lower()
    return next((kind for marker, kind in _QUERY_KINDS if marker in name), None)


def _signed(columns: dict) -> bool | None:
    if "signature_result" in columns:  # Windows authenticode
        return columns["signature_result"] == "trusted"
    if "signed" in columns:  # macOS signature table
        return str(columns["signed"]) == "1"
    return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1] or None


def _row_event(kind: str, row: dict, envelope: dict, source_type: SourceType) -> SecurityEvent | None:
    decorations = envelope.get("decorations") or {}
    host = decorations.get("hostname") or envelope.get("hostIdentifier") or "unknown-host"
    ts = _int(row.get("time")) or _int(envelope.get("unixTime")) or 0
    metadata: dict[str, Any] = {
        "host": host,
        "os": (decorations.get("os") or "").lower() or None,
        "osquery_query": envelope.get("name"),
    }
    if decorations.get("sentivra_demo_label"):
        metadata["demo_label"] = decorations["sentivra_demo_label"]

    def event(
        event_type: SecurityEventType,
        *,
        user_id: str | None = None,
        extra: dict | None = None,
        process: ProcessContext | None = None,
        network: NetworkContext | None = None,
    ) -> SecurityEvent:
        return SecurityEvent(
            event_type=event_type,
            timestamp=datetime.fromtimestamp(ts, tz=UTC),
            source="osquery",
            source_type=source_type,
            user_id=user_id,
            metadata={**metadata, **(extra or {})},
            process=process,
            network=network,
        )

    if kind == "process":
        user = row.get("username") or (f"uid:{row['uid']}" if row.get("uid") not in (None, "") else None)
        return event(
            SecurityEventType.PROCESS_STARTED,
            user_id=user,
            process=ProcessContext(
                pid=_int(row.get("pid")),
                parent_pid=_int(row.get("parent")),
                name=_basename(row.get("path")),
                executable_path=row.get("path") or None,
                command_line=row.get("cmdline") or None,
                executable_sha256=row.get("sha256") or None,
                user=user,
                parent_name=row.get("parent_name") or _basename(row.get("parent_path")),
                parent_executable_path=row.get("parent_path") or None,
                signed=_signed(row),
            ),
        )
    if kind == "connection":
        return event(
            SecurityEventType.PROCESS_NETWORK_CONNECTION,
            process=ProcessContext(pid=_int(row.get("pid")), name=_basename(row.get("path")),
                                   executable_path=row.get("path") or None),
            network=NetworkContext(dst_ip=row.get("remote_address") or None, dst_port=_int(row.get("remote_port")),
                                   src_port=_int(row.get("local_port")),
                                   protocol={"6": "tcp", "17": "udp"}.get(str(row.get("protocol")), None)),
        )
    if kind == "listening":
        return event(
            SecurityEventType.LISTENING_PORT,
            process=ProcessContext(pid=_int(row.get("pid")), name=_basename(row.get("path")),
                                   executable_path=row.get("path") or None),
            extra={"listening": {"port": _int(row.get("port")), "address": row.get("address"),
                                 "protocol": {"6": "tcp", "17": "udp"}.get(str(row.get("protocol")))}},
        )
    if kind == "file":
        action = (row.get("action") or "").upper()
        return event(
            SecurityEventType.FILE_CREATED if action == "CREATED" else SecurityEventType.FILE_MODIFIED,
            extra={"file": {"target_path": row.get("target_path"), "action": action or None,
                            "sha256": row.get("sha256") or None}},
        )
    if kind.startswith("persistence:"):
        target = row.get("path") or row.get("action") or row.get("command") or ""
        return event(
            SecurityEventType.PERSISTENCE_ITEM,
            extra={"persistence": {"kind": kind.split(":", 1)[1], "name": row.get("name") or row.get("event"),
                                   "target": target, "args": row.get("args"), "source": row.get("source"),
                                   "user": row.get("username") or row.get("user_account")}},
        )
    if kind == "login":
        return event(
            SecurityEventType.AUTHENTICATION_EVENT,
            user_id=row.get("username"),
            extra={"auth": {"outcome": "success", "username": row.get("username"),
                            "source_ip": row.get("host") or None, "method": "interactive_login"}},
        )
    if kind == "windows_security":
        event_id = _int(row.get("eventid"))
        try:
            data = json.loads(row.get("data") or "{}")
        except json.JSONDecodeError:
            data = {}
        fields = data.get("EventData", data) if isinstance(data, dict) else {}
        extra: dict[str, Any] = {"windows_event": {"event_id": event_id, "channel": "Security", **fields}}
        if event_id in _WINDOWS_AUTH_EVENTS:
            extra["auth"] = {
                "outcome": _WINDOWS_AUTH_EVENTS[event_id],
                "username": fields.get("TargetUserName"),
                "source_ip": fields.get("IpAddress") if fields.get("IpAddress") not in ("-", "") else None,
                "logon_type": _int(fields.get("LogonType")),
                "method": "windows_logon",
            }
            return event(SecurityEventType.AUTHENTICATION_EVENT, user_id=fields.get("TargetUserName"), extra=extra)
        return event(SecurityEventType.SYSTEM_LOG, extra=extra)
    return None


def normalize(results: Iterable[dict], *, source_type: SourceType) -> tuple[list[SecurityEvent], dict[str, int]]:
    """Normalize osquery result log objects. Returns (events, stats); rows
    from queries this normalizer doesn't recognize are counted, not guessed at."""
    events: list[SecurityEvent] = []
    stats = {"rows": 0, "events": 0, "unrecognized_query_rows": 0, "removed_rows_ignored": 0}
    for envelope in results:
        if not isinstance(envelope, dict) or "name" not in envelope:
            raise OsqueryParseError("Each result must be an osquery log object with a 'name'")
        kind = _kind_for(str(envelope["name"]))
        if "columns" in envelope:
            rows = [envelope["columns"]] if envelope.get("action", "added") == "added" else []
            stats["removed_rows_ignored"] += 0 if rows else 1
        elif "diffResults" in envelope:
            rows = envelope["diffResults"].get("added", [])
            stats["removed_rows_ignored"] += len(envelope["diffResults"].get("removed", []))
        elif "snapshot" in envelope:
            rows = envelope["snapshot"]
        else:
            raise OsqueryParseError(f"Unrecognized result shape for query {envelope['name']!r}")
        for row in rows:
            stats["rows"] += 1
            if kind is None:
                stats["unrecognized_query_rows"] += 1
                continue
            ev = _row_event(kind, row, envelope, source_type)
            if ev is not None:
                events.append(ev)
    stats["events"] = len(events)
    events.sort(key=lambda e: e.timestamp)
    return events, stats
