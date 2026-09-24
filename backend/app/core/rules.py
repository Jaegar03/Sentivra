"""Loading and running rule packs from detection-rules/.

Rules live outside application code (brief §11), so they're treated as
data that might be edited by an operator:

  * YAML is parsed with yaml.safe_load, never yaml.load. A rule file can't
    instantiate Python objects.
  * Patterns are compiled with the third-party `regex` module and every
    search runs with a timeout. The detectors run these patterns against
    attacker-controlled text, so a badly written rule must fail closed
    (reported as a timeout) instead of hanging the request (ReDoS).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import regex
import yaml

from app.core.config import get_settings
from app.schemas.detection import MitreAttackMapping

logger = logging.getLogger("sentivra.rules")

_FLAGS = regex.IGNORECASE | regex.UNICODE | regex.VERSION1


class RuleTimeout(Exception):
    """A rule's regex exceeded its time budget on this input."""


@dataclass(frozen=True)
class PatternRule:
    id: str
    category: str
    description: str
    pattern: regex.Pattern
    weight: float
    mitre_key: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def search(self, text: str) -> regex.Match | None:
        try:
            return self.pattern.search(text, timeout=get_settings().regex_timeout_s)
        except TimeoutError as exc:
            raise RuleTimeout(self.id) from exc


def rules_path(*parts: str) -> Path:
    return get_settings().rules_dir.joinpath(*parts)


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def compile_pattern_rules(entries: list[dict]) -> list[PatternRule]:
    """Compile a list of `{id, category, description, pattern, weight, mitre}`
    entries. A rule that fails to compile is skipped and logged, not fatal;
    the rest of the pack still loads."""
    rules: list[PatternRule] = []
    for entry in entries:
        try:
            compiled = regex.compile(entry["pattern"], _FLAGS)
        except (regex.error, KeyError) as exc:
            logger.error("Skipping rule %s: %s", entry.get("id", "<no id>"), exc)
            continue
        known = {"id", "category", "description", "pattern", "weight", "mitre"}
        rules.append(
            PatternRule(
                id=entry["id"],
                category=entry["category"],
                description=entry.get("description", entry["id"]),
                pattern=compiled,
                weight=float(entry.get("weight", 0.5)),
                mitre_key=entry.get("mitre"),
                extra={k: v for k, v in entry.items() if k not in known},
            )
        )
    return rules


@lru_cache
def _mitre_table() -> dict[str, list[MitreAttackMapping]]:
    path = rules_path("custom", "mitre_mappings.yaml")
    if not path.exists():
        return {}
    raw = load_yaml(path) or {}
    return {key: [MitreAttackMapping(**m) for m in items] for key, items in raw.items()}


def mitre_for(*keys: str | None) -> list[MitreAttackMapping]:
    """Mappings for the given keys, de-duplicated by technique ID. Unknown
    keys return nothing; a mapping never gets made up to fill a gap."""
    table = _mitre_table()
    seen: dict[str, MitreAttackMapping] = {}
    for key in keys:
        for mapping in table.get(key or "", []):
            seen.setdefault(mapping.technique_id, mapping)
    return list(seen.values())
