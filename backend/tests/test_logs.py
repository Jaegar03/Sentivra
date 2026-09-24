"""Log parsing and authentication aggregation rules."""

from __future__ import annotations

import json

from app.detectors.logs import auth_rules
from app.detectors.logs.parsers import parse_lines
from app.events.schema import SecurityEventType, SourceType


def sshd_lines(n_failures: int, *, success: bool = False, user: str = "admin", ip: str = "203.0.113.9") -> str:
    lines = [f"Sep 24 10:00:{i:02d} srv01 sshd[42]: Failed password for {user} from {ip} port {50000 + i} ssh2"
             for i in range(n_failures)]
    if success:
        lines.append(f"2026-09-24T10:02:00+00:00 srv01 sshd[43]: Accepted password for {user} from {ip} port 51000 ssh2")
    return "\n".join(lines)


def parse(text: str):
    return parse_lines(text, source_type=SourceType.LIVE, max_lines=10_000, year=2026)


def test_sshd_lines_become_auth_events_in_both_timestamp_styles():
    events, stats = parse(sshd_lines(2, success=True))
    assert stats["linux_auth"] == 3
    assert [e.metadata["auth"]["outcome"] for e in events] == ["failure", "failure", "success"]
    assert all(e.event_type == SecurityEventType.AUTHENTICATION_EVENT for e in events)


def test_windows_json_and_wazuh_and_generic_lines():
    text = "\n".join([
        json.dumps({"EventID": 4624, "TimeCreated": "2026-09-24T09:00:00Z", "Computer": "ws1",
                    "EventData": {"TargetUserName": "bob", "IpAddress": "-"}}),
        json.dumps({"timestamp": "2026-09-24T09:05:00+00:00", "agent": {"name": "srv02"},
                    "rule": {"id": "100001", "level": 9, "description": "example alert", "groups": ["syslog"],
                             "mitre": {"id": ["T1110"]}}}),
        "kernel: eth0 link up",
    ])
    events, stats = parse(text)
    assert (stats["windows"], stats["wazuh"], stats["generic"]) == (1, 1, 1)
    windows = next(e for e in events if e.metadata.get("windows_event"))
    assert windows.metadata["auth"]["source_ip"] is None  # "-" means no address
    wazuh = next(e for e in events if "wazuh" in e.metadata)
    assert wazuh.metadata["wazuh"]["level"] == 9


def test_line_cap_is_enforced():
    _, stats = parse_lines(sshd_lines(20), source_type=SourceType.LIVE, max_lines=5, year=2026)
    assert stats["lines"] == 5 and stats["truncated"] == 1


def test_password_guessing_fires_above_threshold_only():
    assert [f.rule for f in auth_rules.evaluate(parse(sshd_lines(12))[0])] == ["password_guessing"]
    assert auth_rules.evaluate(parse(sshd_lines(3))[0]) == []  # a few mistypes are normal


def test_success_after_failures():
    rules = {f.rule for f in auth_rules.evaluate(parse(sshd_lines(12, success=True))[0])}
    assert rules == {"password_guessing", "success_after_failures"}


def test_password_spraying_across_accounts():
    text = "\n".join(sshd_lines(1, user=f"user{i}").replace("10:00:00", f"10:00:{i:02d}") for i in range(10))
    findings = auth_rules.evaluate(parse(text)[0])
    assert [f.rule for f in findings] == ["password_spraying"]
    assert findings[0].details["distinct_accounts"] == 10


def test_findings_carry_their_events():
    finding = auth_rules.evaluate(parse(sshd_lines(12))[0])[0]
    assert finding.event_count == 12 and len(finding.members) == 12
