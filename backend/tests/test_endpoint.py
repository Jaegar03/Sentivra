"""Endpoint behavior: host rules against the fleet baseline, and Sigma rules
over simulated telemetry. Each rule must fire on its own scenario and stay
quiet on benign-only fleets."""

from __future__ import annotations

from collections import Counter

import pytest

from app.demo.endpoint_sim import SCENARIOS, FleetConfig, simulate
from app.detectors.behavioral_anomaly_detector import load_baseline
from app.detectors.endpoint import host_rules
from app.detectors.endpoint.activity import Baseline, normalize_path, path_class, summarize
from app.detectors.sigma_detector import SigmaDetector, rule_mitre
from app.events.osquery import normalize
from app.events.schema import SourceType


def events_for(**cfg):
    return normalize(simulate(FleetConfig(**cfg)), source_type=SourceType.SIMULATED)[0]


@pytest.fixture(scope="module")
def baseline() -> Baseline:
    loaded, status = load_baseline()
    assert loaded is not None, status
    return loaded


@pytest.fixture(scope="module")
def sigma() -> SigmaDetector:
    return SigmaDetector()


def test_path_classification():
    assert path_class(r"C:\Users\u1\AppData\Local\Temp\x.exe") == "user_writable"
    assert path_class(r"C:\Windows\System32\svchost.exe") == "system"
    assert path_class(r"C:\Program Files\App\app.exe") == "program_files"
    assert path_class("/tmp/x") == "user_writable"
    assert normalize_path(r"C:\Users\alice\AppData\x.exe") == r"c:\users\<user>\appdata\x.exe"


def test_host_rules_quiet_on_benign_fleets(baseline):
    for seed in (600, 601, 602):
        events = events_for(windows_hosts=8, linux_hosts=2, hours=4.0, seed=seed, episodes={})
        assert host_rules.evaluate(events, summarize(events), baseline)[0] == []


@pytest.fixture(scope="module")
def demo_events():
    return events_for(windows_hosts=8, linux_hosts=2, hours=2.0, seed=77, episodes={s: 1 for s in SCENARIOS})


def labels_hit(findings) -> set[str]:
    return {e.metadata.get("demo_label") for f in findings for e in f.events} - {None}


def test_host_rules_catch_their_scenarios(baseline, demo_events):
    findings, skipped = host_rules.evaluate(demo_events, summarize(demo_events), baseline)
    assert skipped == []
    assert {"unsigned_from_user_writable", "new_persistence_user_writable", "new_listener_user_writable",
            "mass_file_modification", "linux_exec_from_tmp"} <= labels_hit(findings)


def test_baseline_rules_are_skipped_without_a_baseline(demo_events):
    findings, skipped = host_rules.evaluate(demo_events, summarize(demo_events), None)
    assert set(skipped) == {"new_persistence_user_writable", "new_listener_untrusted", "rare_process_lineage"}
    assert {f.rule for f in findings} <= {"unsigned_user_writable_network", "mass_file_modification"}


def test_signed_installers_from_downloads_are_not_rare_lineage(baseline):
    events = events_for(windows_hosts=8, linux_hosts=0, hours=8.0, seed=610, episodes={})
    findings, _ = host_rules.evaluate(events, summarize(events), baseline)
    assert not [f for f in findings if f.rule == "rare_process_lineage"]


def test_sigma_rules_match_their_scenarios_and_map_attack(sigma, demo_events):
    rules = {r.id: r for r in sigma.report.loaded}
    hits = sigma.match_events(demo_events)
    hit_labels = {e.metadata.get("demo_label") for evts in hits.values() for e in evts}
    assert {"office_spawns_interpreter", "event_log_cleared", "linux_exec_from_tmp"} <= hit_labels
    log_cleared = next(r for r in rules.values() if "Audit Log Cleared" in r.title)
    assert [m.technique_id for m in rule_mitre(log_cleared)] == ["T1685.005"]


def test_sigma_quiet_on_benign_fleets(sigma):
    counts = Counter()
    for seed in (620, 621, 622):
        counts.update(sigma.match_events(events_for(windows_hosts=8, linux_hosts=2, hours=4.0, seed=seed, episodes={})))
    assert counts == Counter()
