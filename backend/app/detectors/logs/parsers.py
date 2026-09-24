"""Log lines -> SecurityEvents.

Recognized per line:
  * Wazuh alerts.json lines (a JSON object with `rule` and `agent`)
  * Windows Security events as JSON (a JSON object with `EventID`, as
    exported by Get-WinEvent | ConvertTo-Json, Winlogbeat and similar)
  * Linux auth.log / secure lines from sshd (Failed / Accepted / Invalid
    user), in classic syslog or RFC 3339 timestamp form

Anything else becomes a generic `system_log` event with the line as its
body, so Sigma keyword rules can still see it. Nothing is dropped
silently; the parse stats say how many lines fell into each bucket.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from app.events.schema import EventContent, SecurityEvent, SecurityEventType, SourceType

_SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_RFC3339_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_SSHD_FAILED = re.compile(r"sshd\[\d+\]:\s+Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SSHD_ACCEPTED = re.compile(r"sshd\[\d+\]:\s+Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SSHD_INVALID = re.compile(r"sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")

_MAX_LINE = 16_384


def _syslog_time(ts: str, year: int) -> datetime:
    try:
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)


def _iso_time(ts: str | None) -> datetime:
    if not ts:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(ts)  # accepts a trailing "Z" since Python 3.11
    except ValueError:
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _auth_event(ts, host, os_name, outcome, user, ip, method, source_type, raw, source) -> SecurityEvent:
    return SecurityEvent(
        event_type=SecurityEventType.AUTHENTICATION_EVENT,
        timestamp=ts,
        source=source,
        source_type=source_type,
        user_id=user,
        content=EventContent(body=raw[:2000]),
        metadata={"host": host, "os": os_name,
                  "auth": {"outcome": outcome, "username": user, "source_ip": ip, "method": method}},
    )


def _parse_json(obj: dict, source_type: SourceType) -> tuple[SecurityEvent, str]:
    if "rule" in obj and "agent" in obj:  # Wazuh alert
        rule = obj.get("rule") or {}
        data = obj.get("data") or {}
        agent = obj.get("agent") or {}
        win = (data.get("win") or {}) if isinstance(data, dict) else {}
        metadata: dict[str, Any] = {
            "host": agent.get("name"),
            "wazuh": {"rule_id": str(rule.get("id", "")), "level": int(rule.get("level", 0) or 0),
                      "description": rule.get("description"), "groups": rule.get("groups") or [],
                      "mitre_ids": (rule.get("mitre") or {}).get("id") or []},
        }
        event_type = SecurityEventType.SYSTEM_LOG
        groups = set(rule.get("groups") or [])
        if win.get("system", {}).get("eventID"):
            metadata["os"] = "windows"
            metadata["windows_event"] = {"event_id": int(win["system"]["eventID"]), "channel": win["system"].get("channel"),
                                         **(win.get("eventdata") or {})}
        if groups & {"authentication_failed", "authentication_success", "authentication_failures"}:
            event_type = SecurityEventType.AUTHENTICATION_EVENT
            metadata["auth"] = {"outcome": "success" if "authentication_success" in groups else "failure",
                                "username": data.get("dstuser") or data.get("srcuser"),
                                "source_ip": data.get("srcip"), "method": "wazuh"}
        return SecurityEvent(event_type=event_type, timestamp=_iso_time(obj.get("timestamp")), source="wazuh",
                             source_type=source_type, content=EventContent(body=str(obj.get("full_log", ""))[:2000]),
                             metadata=metadata), "wazuh"

    if "EventID" in obj or "event_id" in obj:  # Windows event export
        event_id = int(obj.get("EventID", obj.get("event_id")))
        fields = obj.get("EventData") or {}
        metadata = {"host": obj.get("Computer") or obj.get("MachineName"), "os": "windows",
                    "windows_event": {"event_id": event_id, "channel": obj.get("Channel", "Security"), **fields}}
        ts = _iso_time(obj.get("TimeCreated"))
        if event_id in (4624, 4625):
            ip = fields.get("IpAddress")
            metadata["auth"] = {"outcome": "success" if event_id == 4624 else "failure",
                                "username": fields.get("TargetUserName"),
                                "source_ip": ip if ip not in ("-", "", None) else None,
                                "logon_type": fields.get("LogonType"), "method": "windows_logon"}
            return SecurityEvent(event_type=SecurityEventType.AUTHENTICATION_EVENT, timestamp=ts, source="log_upload",
                                 source_type=source_type, user_id=fields.get("TargetUserName"), metadata=metadata), "windows"
        return SecurityEvent(event_type=SecurityEventType.SYSTEM_LOG, timestamp=ts, source="log_upload",
                             source_type=source_type, metadata=metadata), "windows"
    raise ValueError("unrecognized JSON log object")


def parse_lines(text: str, *, source_type: SourceType, max_lines: int, year: int | None = None
                ) -> tuple[list[SecurityEvent], dict[str, int]]:
    year = year or datetime.now(UTC).year
    events: list[SecurityEvent] = []
    stats = {"lines": 0, "wazuh": 0, "windows": 0, "linux_auth": 0, "generic": 0, "truncated": 0}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if stats["lines"] >= max_lines:
            stats["truncated"] = 1
            break
        stats["lines"] += 1
        line = line[:_MAX_LINE]

        if line.startswith("{"):
            try:
                event, kind = _parse_json(json.loads(line), source_type)
                events.append(event)
                stats[kind] += 1
                continue
            except (ValueError, TypeError):
                pass  # not a log object we know: falls through to generic

        m = _SYSLOG_TS.match(line) or _RFC3339_TS.match(line)
        if m:
            ts = _syslog_time(m["ts"], year) if m.re is _SYSLOG_TS else _iso_time(m["ts"])
            rest = m["rest"]
            for pattern, outcome in ((_SSHD_FAILED, "failure"), (_SSHD_INVALID, "failure"), (_SSHD_ACCEPTED, "success")):
                hit = pattern.search(rest)
                if hit:
                    method = hit.groupdict().get("method", "invalid_user")
                    events.append(_auth_event(ts, m["host"], "linux", outcome, hit["user"], hit["ip"],
                                              f"sshd_{method}", source_type, line, "log_upload"))
                    stats["linux_auth"] += 1
                    break
            else:
                events.append(SecurityEvent(event_type=SecurityEventType.SYSTEM_LOG, timestamp=ts, source="log_upload",
                                            source_type=source_type, content=EventContent(body=line[:2000]),
                                            metadata={"host": m["host"]}))
                stats["generic"] += 1
            continue

        events.append(SecurityEvent(event_type=SecurityEventType.SYSTEM_LOG, source="log_upload",
                                    source_type=source_type, content=EventContent(body=line[:2000]), metadata={}))
        stats["generic"] += 1
    events.sort(key=lambda e: e.timestamp)
    return events, stats
