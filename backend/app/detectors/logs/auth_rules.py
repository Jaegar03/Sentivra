"""Authentication aggregation rules over a batch of events. Thresholds come
from detection-rules/custom/auth_rules.yaml."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache

from app.core.rules import load_yaml, rules_path
from app.events.schema import SecurityEvent, SecurityEventType


@dataclass
class AuthFinding:
    rule: str
    description: str
    weight: float
    mitre_key: str | None
    subject: str
    details: dict = field(default_factory=dict)
    members: list[SecurityEvent] = field(default_factory=list, repr=False)  # the events this finding covers

    @property
    def event_count(self) -> int:
        return len(self.members)


@dataclass(frozen=True)
class _Attempt:
    time: float
    outcome: str
    user: str
    source: str
    host: str
    event: SecurityEvent


@lru_cache
def load_auth_rules() -> dict:
    return (load_yaml(rules_path("custom", "auth_rules.yaml")) or {}).get("rules", {})


def _attempts(events: list[SecurityEvent]) -> list[_Attempt]:
    out = []
    for e in events:
        auth = e.metadata.get("auth") if e.event_type == SecurityEventType.AUTHENTICATION_EVENT else None
        if not auth or auth.get("outcome") not in ("success", "failure"):
            continue
        source = auth.get("source_ip") or f"local@{e.metadata.get('host') or '?'}"
        out.append(_Attempt(e.timestamp.timestamp(), auth["outcome"], str(auth.get("username") or "?").lower(),
                            source, e.metadata.get("host") or "?", e))
    return sorted(out, key=lambda a: a.time)


def _densest_window(attempts: list[_Attempt], window: float) -> list[_Attempt]:
    """The largest run of attempts that fits inside `window` seconds."""
    best, j = (0, 0), 0
    for i, a in enumerate(attempts):
        while a.time - attempts[j].time > window:
            j += 1
        if i + 1 - j > best[1] - best[0]:
            best = (j, i + 1)
    return attempts[best[0]:best[1]]


def evaluate(events: list[SecurityEvent]) -> list[AuthFinding]:
    rules = load_auth_rules()
    attempts = _attempts(events)
    findings: list[AuthFinding] = []

    failures_by_pair: dict[tuple[str, str], list[_Attempt]] = defaultdict(list)
    failures_by_source: dict[str, list[_Attempt]] = defaultdict(list)
    for a in attempts:
        if a.outcome == "failure":
            failures_by_pair[(a.user, a.source)].append(a)
            failures_by_source[a.source].append(a)

    if (rule := rules.get("password_guessing")):
        for (user, source), fails in failures_by_pair.items():
            window = _densest_window(fails, rule["window_s"])
            if len(window) >= rule["min_failures"]:
                findings.append(AuthFinding(
                    "password_guessing", rule["description"], rule["weight"], rule.get("mitre"),
                    f"{source} -> account '{user}'",
                    {"failures_in_window": len(window), "window_s": rule["window_s"]},
                    [a.event for a in window]))

    if (rule := rules.get("password_spraying")):
        for source, fails in failures_by_source.items():
            best: list[_Attempt] = []
            j = 0
            for i, a in enumerate(fails):
                while a.time - fails[j].time > rule["window_s"]:
                    j += 1
                if len({x.user for x in fails[j:i + 1]}) > len({x.user for x in best}):
                    best = fails[j:i + 1]
            accounts = sorted({a.user for a in best})
            if len(accounts) >= rule["min_distinct_accounts"]:
                findings.append(AuthFinding(
                    "password_spraying", rule["description"], rule["weight"], rule.get("mitre"),
                    f"{source} -> {len(accounts)} accounts",
                    {"distinct_accounts": len(accounts), "window_s": rule["window_s"], "accounts_sample": accounts[:5]},
                    [a.event for a in best]))

    if (rule := rules.get("success_after_failures")):
        reported: set[tuple[str, str]] = set()
        for a in attempts:
            if a.outcome != "success" or a.source.startswith("local@") or (a.user, a.source) in reported:
                continue
            prior = [f for f in failures_by_pair.get((a.user, a.source), [])
                     if a.time - rule["window_s"] <= f.time < a.time]
            if len(prior) >= rule["min_prior_failures"]:
                reported.add((a.user, a.source))
                findings.append(AuthFinding(
                    "success_after_failures", rule["description"], rule["weight"], rule.get("mitre"),
                    f"{a.source} -> account '{a.user}' on {a.host}",
                    {"failures_before_success": len(prior), "window_s": rule["window_s"]},
                    [f.event for f in prior] + [a.event]))
    return findings
