"""Brief §31, "do not invent mappings", enforced as a test: every ATT&CK
technique Sentivra can emit must exist, unrevoked, in MITRE's official data."""

from __future__ import annotations

import pytest

from app.core.rules import (
    UnknownTechnique,
    _mitre_table,
    attack_index,
    attack_mapping,
    load_yaml,
    rules_path,
)


def test_attack_index_is_present_and_carries_mitre_notice():
    index = attack_index()
    assert index["attack_version"]
    assert len(index["techniques"]) > 500
    assert "The MITRE Corporation" in index["notice"]


def test_every_curated_attack_id_exists_and_is_not_revoked():
    raw = load_yaml(rules_path("custom", "mitre_mappings.yaml"))
    techniques = attack_index()["techniques"]
    for key, items in raw.items():
        for item in items:
            if isinstance(item, str):
                assert item in techniques, f"{key}: {item} is not an ATT&CK technique"
                assert not techniques[item].get("revoked_by"), f"{key}: {item} has been revoked"
                assert not techniques[item].get("deprecated"), f"{key}: {item} is deprecated"


def test_atlas_entries_are_labeled_as_atlas_not_attack():
    for mappings in _mitre_table().values():
        for m in mappings:
            if m.technique_id.startswith("AML."):
                assert m.source.startswith("MITRE ATLAS")
            else:
                assert m.source.startswith("MITRE ATT&CK")


def test_revoked_id_is_remapped_to_its_replacement():
    mapping = attack_mapping("T1070.001", via="Sigma rule tag")
    assert mapping.technique_id == "T1685.005"
    assert "revoked" in mapping.source and "Sigma rule tag" in mapping.source


def test_unknown_id_raises_instead_of_inventing_a_name():
    with pytest.raises(UnknownTechnique):
        attack_mapping("T9999.999")


def test_names_come_from_official_data():
    assert attack_mapping("T1053.005").technique_name == "Scheduled Task/Job: Scheduled Task"
