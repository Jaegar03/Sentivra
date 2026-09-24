"""Every rule file under detection-rules/ must parse, and every pattern in
the custom packs must compile. A broken rule file otherwise only shows up
when some code path first loads it."""

from __future__ import annotations

import pytest
import regex
import yaml

from app.core.config import get_settings
from app.core.rules import load_yaml, rules_path

RULES_DIR = get_settings().rules_dir
YAML_FILES = sorted(p for p in RULES_DIR.rglob("*") if p.suffix in (".yml", ".yaml"))


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda p: str(p.relative_to(RULES_DIR)))
def test_rule_file_parses(path):
    with path.open(encoding="utf-8") as f:
        assert yaml.safe_load(f) is not None


def test_every_custom_pattern_compiles():
    data = load_yaml(rules_path("custom", "sql_injection.yaml"))
    for rule in data["rules"]:
        regex.compile(rule["pattern"], regex.IGNORECASE | regex.VERSION1)


def test_all_sigma_rules_load_as_supported():
    from app.detectors.sigma.engine import load_rules

    report = load_rules(RULES_DIR / "sigma")
    assert report.loaded and report.unsupported == []
