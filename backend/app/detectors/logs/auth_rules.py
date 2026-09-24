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
    event_count: int = 0


@lru_cache
def load_auth_rules() -> dict:
    return (load_yaml(rules_path("custom", "auth_rules.yaml")) or {}).get("rules", {})


def _attempts(events: list[SecurityEvent]) -> list[tuple[float, str, str, str, str]]:
    """(time, outcome, username, source, host) for every authentication event."""
    out = []
    for e in events:
        auth = e.metadata.get("auth") if e.event_type == SecurityEventType.AUTHENTICATION_EVENT else None
        if not auth or auth.get("outcome") not in ("success", "failure"):
            continue
        source = auth.get("source_ip") or f"local@{e.metadata.get('host') or '?'}"
        out.append((e.timestamp.timestamp(), auth["outcome"], str(auth.get("username") or "?").lower(),
                    source, e.metadata.get("host") or "?"))
    return sorted(out)


def _max_in_window(times: list[float], window: float) -> tuple[int, float]:
    """Largest number of events inside any window of `window` seconds, and where it starts."""
    best, best_start, j = 0, 0.0, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        if i - j + 1 > best:
            best, best_start = i - j + 1, times[j]
    return best, best_start


def evaluate(events: list[SecurityEvent]) -> list[AuthFinding]:
    rules = load_auth_rules()
    attempts = _attempts(events)
    findings: list[AuthFinding] = []

    failures_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    failures_by_source: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for t, outcome, user, source, _host in attempts:
        if outcome == "failure":
            failures_by_pair[(user, source)].append(t)
            failures_by_source[source].append((t, user))

    if (rule := rules.get("password_guessing")):
        for (user, source), times in failures_by_pair.items():
            count, _ = _max_in_window(times, rule["window_s"])
            if count >= rule["min_failures"]:
                findings.append(AuthFinding("password_guessing", rule["description"], rule["weight"], rule.get("mitre"),
                                            f"{source} -> account '{user}'",
                                            {"failures_in_window": count, "window_s": rule["window_s"]}, len(times)))

    if (rule := rules.get("password_spraying")):
        for source, items in failures_by_source.items():
            items.sort()
            best, j = set(), 0
            for i in range(len(items)):
                while items[i][0] - items[j][0] > rule["window_s"]:
                    j += 1
                accounts = {u for _, u in items[j:i + 1]}
                if len(accounts) > len(best):
                    best = accounts
            if len(best) >= rule["min_distinct_accounts"]:
                findings.append(AuthFinding("password_spraying", rule["description"], rule["weight"], rule.get("mitre"),
                                            f"{source} -> {len(best)} accounts",
                                            {"distinct_accounts": len(best), "window_s": rule["window_s"],
                                             "accounts_sample": sorted(best)[:5]}, len(items)))

    if (rule := rules.get("success_after_failures")):
        reported: set[tuple[str, str]] = set()
        for t, outcome, user, source, host in attempts:
            if outcome != "success" or source.startswith("local@") or (user, source) in reported:
                continue
            prior = [ft for ft in failures_by_pair.get((user, source), []) if t - rule["window_s"] <= ft < t]
            if len(prior) >= rule["min_prior_failures"]:
                reported.add((user, source))
                findings.append(AuthFinding("success_after_failures", rule["description"], rule["weight"],
                                            rule.get("mitre"), f"{source} -> account '{user}' on {host}",
                                            {"failures_before_success": len(prior), "window_s": rule["window_s"]},
                                            len(prior) + 1))
    return findings
