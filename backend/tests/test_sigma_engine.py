"""Sigma engine semantics: value matching, modifiers, conditions, and
unsupported features being reported rather than half-evaluated."""

from __future__ import annotations

import pytest

from app.detectors.sigma.engine import UnsupportedRule, compile_detection, load_rules

EVENT = {
    "Image": r"C:\Program Files\Editor\notepad.exe",
    "ParentImage": r"C:\Windows\explorer.exe",
    "CommandLine": "notepad.exe /A report.txt",
    "DestinationIp": "10.1.2.3",
    "DestinationPort": 8080,
}


def match(detection: dict, fields: dict = EVENT) -> bool:
    return compile_detection(detection)(fields)


def test_default_match_is_case_insensitive_equality_with_wildcards():
    assert match({"sel": {"Image": r"c:\program files\editor\NOTEPAD.EXE"}, "condition": "sel"})
    assert match({"sel": {"Image": r"*\notepad.exe"}, "condition": "sel"})
    assert match({"sel": {"Image": r"C:\Program Files\Edit?r\notepad.exe"}, "condition": "sel"})
    assert not match({"sel": {"Image": "notepad.exe"}, "condition": "sel"})  # equality, not substring


@pytest.mark.parametrize(("key", "value", "expected"), [
    ("Image|endswith", r"\notepad.exe", True),
    ("Image|startswith", r"C:\Program Files", True),
    ("CommandLine|contains", "report", True),
    ("CommandLine|contains|all", ["notepad", "report"], True),
    ("CommandLine|contains|all", ["notepad", "missing"], False),
    ("CommandLine|re", r"/A\s+\w+\.txt$", True),
    ("CommandLine|cased", "NOTEPAD.EXE /A report.txt", False),
    ("DestinationIp|cidr", "10.0.0.0/8", True),
    ("DestinationIp|cidr", "192.168.0.0/16", False),
    ("DestinationPort|gte", 8000, True),
    ("DestinationPort|lt", 1024, False),
    ("CommandLine|windash|contains", "-A", True),  # "-A" also matches "/A"
    ("User|exists", False, True),
])
def test_modifiers(key, value, expected):
    assert match({"sel": {key: value}, "condition": "sel"}) is expected


def test_list_of_values_is_or_and_map_is_and():
    assert match({"sel": {"Image|endswith": [r"\calc.exe", r"\notepad.exe"]}, "condition": "sel"})
    assert not match({"sel": {"Image|endswith": r"\notepad.exe", "ParentImage|endswith": r"\cmd.exe"},
                      "condition": "sel"})


def test_list_of_maps_is_or():
    assert match({"sel": [{"Image|endswith": r"\calc.exe"}, {"CommandLine|contains": "report"}],
                  "condition": "sel"})


def test_null_matches_missing_field():
    assert match({"sel": {"User": None}, "condition": "sel"})


def test_keyword_search_matches_any_field():
    assert match({"keywords": ["report.txt"], "condition": "keywords"})
    assert not match({"keywords": ["absent-term"], "condition": "keywords"})


@pytest.mark.parametrize(("condition", "expected"), [
    ("sel_a and not sel_b", True),
    ("sel_a and sel_b", False),
    ("sel_b or sel_a", True),
    ("not (sel_a or sel_b)", False),
    ("1 of sel_*", True),
    ("all of sel_*", False),
    ("1 of them", True),
    ("all of them", False),
])
def test_conditions(condition, expected):
    detection = {"sel_a": {"Image|endswith": r"\notepad.exe"}, "sel_b": {"Image|endswith": r"\calc.exe"},
                 "condition": condition}
    assert match(detection) is expected


def test_condition_list_is_or():
    detection = {"sel_a": {"Image|endswith": r"\calc.exe"}, "sel_b": {"CommandLine|contains": "report"},
                 "condition": ["sel_a", "sel_b"]}
    assert match(detection)


@pytest.mark.parametrize("detection", [
    {"sel": {"Image": "x"}, "condition": "sel | count() by Image > 5"},  # aggregation
    {"sel": {"CommandLine|base64offset|contains": "x"}, "condition": "sel"},  # unsupported modifier
    {"sel": {"Image": "x"}, "condition": "sel and missing"},  # unknown identifier
    {"sel": {"Image": "x"}},  # no condition
])
def test_unsupported_features_raise(detection):
    with pytest.raises(UnsupportedRule):
        compile_detection(detection)


def test_loader_reports_unsupported_rules_with_reason(tmp_path):
    (tmp_path / "good.yml").write_text(
        "title: Good\nid: g1\nlogsource: {category: process_creation}\n"
        "detection: {sel: {Image|endswith: '\\\\notepad.exe'}, condition: sel}\nlevel: low\n", encoding="utf-8")
    (tmp_path / "agg.yml").write_text(
        "title: Aggregating\nid: a1\nlogsource: {category: process_creation}\n"
        "detection: {sel: {Image: x}, condition: 'sel | count() > 3'}\n", encoding="utf-8")
    report = load_rules(tmp_path)
    assert [r.id for r in report.loaded] == ["g1"]
    assert report.unsupported[0]["path"] == "agg.yml" and "aggregation" in report.unsupported[0]["reason"]
