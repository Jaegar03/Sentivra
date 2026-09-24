"""osquery result-log normalization."""

from __future__ import annotations

import json

import pytest

from app.events.osquery import OsqueryParseError, normalize
from app.events.schema import SecurityEventType, SourceType


def row(query: str, columns: dict, **extra) -> dict:
    return {"name": f"pack_sentivra_{query}", "hostIdentifier": "h1", "unixTime": 1_790_000_000,
            "decorations": {"hostname": "host-1.example", "os": "windows"}, "columns": columns,
            "action": "added", **extra}


def one(result: dict):
    events, _ = normalize([result], source_type=SourceType.LIVE)
    assert len(events) == 1
    return events[0]


def test_process_event_carries_lineage_and_signature():
    e = one(row("process_etw_events", {"pid": "10", "parent": "4", "path": r"C:\Tools\app.exe", "cmdline": "app.exe",
                                       "username": "u1", "parent_path": r"C:\Windows\explorer.exe",
                                       "parent_name": "explorer.exe", "signature_result": "trusted"}))
    assert e.event_type == SecurityEventType.PROCESS_STARTED
    assert e.process.parent_name == "explorer.exe" and e.process.signed is True and e.process.name == "app.exe"
    assert e.metadata["host"] == "host-1.example" and e.metadata["os"] == "windows"


def test_unknown_signature_is_none_not_false():
    e = one(row("process_events", {"pid": "10", "path": "/usr/bin/tool"}))
    assert e.process.signed is None


def test_scheduled_task_target_is_the_action_not_the_task_path():
    # Regression: scheduled_tasks.path is the task's location in the Task
    # Scheduler library; the program that runs is in `action`.
    e = one(row("scheduled_tasks", {"name": r"\Updater", "path": r"\Updater", "action": r"C:\Apps\update.exe"}))
    assert e.event_type == SecurityEventType.PERSISTENCE_ITEM
    assert e.metadata["persistence"]["target"] == r"C:\Apps\update.exe"


def test_windows_logon_failure_becomes_auth_event():
    data = json.dumps({"EventData": {"TargetUserName": "u1", "IpAddress": "198.51.100.3", "LogonType": "3"}})
    e = one(row("windows_security_log", {"eventid": "4625", "data": data}))
    assert e.event_type == SecurityEventType.AUTHENTICATION_EVENT
    assert e.metadata["auth"] == {"outcome": "failure", "username": "u1", "source_ip": "198.51.100.3",
                                  "logon_type": 3, "method": "windows_logon"}


def test_batch_and_snapshot_formats():
    base = {"name": "pack_sentivra_listening_ports", "hostIdentifier": "h", "unixTime": 1}
    cols = {"pid": "5", "port": "22", "protocol": "6", "address": "0.0.0.0", "path": "/usr/sbin/sshd"}
    events, stats = normalize([{**base, "diffResults": {"added": [cols], "removed": [cols]}},
                               {**base, "snapshot": [cols, cols]}], source_type=SourceType.LIVE)
    assert len(events) == 3 and stats["removed_rows_ignored"] == 1


def test_unrecognized_queries_are_counted_not_guessed():
    events, stats = normalize([row("my_custom_query", {"x": "1"})], source_type=SourceType.LIVE)
    assert events == [] and stats["unrecognized_query_rows"] == 1


def test_malformed_input_rejected():
    with pytest.raises(OsqueryParseError):
        normalize([{"columns": {}}], source_type=SourceType.LIVE)
