"""Learn the endpoint fleet baseline and evaluate the endpoint rule layers.

    backend/.venv/Scripts/python research/experiments/learn_endpoint_baseline.py

The baseline (normal parent/child process pairs, autostart targets, listeners
and file extensions) is learned from a benign simulated fleet and written to
models/endpoint/fleet_baseline/ with its SHA-256 pinned in metadata.json.

Evaluation, all on simulated telemetry (app.demo.endpoint_sim):
  * Detection: 5 independent test fleets (seeds 403–443), one episode of
    each scenario per fleet, so each scenario has 5 episodes. For every
    layer (host rules, Sigma, authentication rules), an episode counts as
    detected when a finding covers at least one of its events.
  * False positives: 10 benign-only fleets (seeds 500–509), counting every
    finding each layer raises.
The baseline is learned from seed 401, which no evaluation fleet shares.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import MODELS_DIR, environment, write_model, write_report

from app.demo.endpoint_sim import SCENARIOS, FleetConfig, simulate
from app.detectors.endpoint import host_rules
from app.detectors.endpoint.activity import Baseline, summarize
from app.detectors.logs import auth_rules
from app.detectors.sigma_detector import SigmaDetector
from app.events.osquery import normalize
from app.events.schema import SourceType

VERSION = "0.1.0"
BASELINE_FLEET = {"windows_hosts": 40, "linux_hosts": 8, "hours": 8.0, "seed": 401}
TEST_SEEDS = (403, 413, 423, 433, 443)
BENIGN_SEEDS = tuple(range(500, 510))


def events_for(**cfg):
    return normalize(simulate(FleetConfig(**cfg)), source_type=SourceType.SIMULATED)[0]


def layer_findings(events, baseline, sigma):
    """{layer: [(rule name, set of ground-truth labels its events carry)]}"""
    acts = summarize(events)
    host, _ = host_rules.evaluate(events, acts, baseline)
    rules = {r.id: r for r in sigma.report.loaded}

    def labels(evts):
        return {e.metadata.get("demo_label", "benign") for e in evts}

    return {
        "host_rules": [(f.rule, labels(f.events)) for f in host],
        "sigma": [(rules[rid].title, labels(evts)) for rid, evts in sigma.match_events(events).items()],
        "auth_rules": [(f.rule, labels(f.members)) for f in auth_rules.evaluate(events)],
    }


def main() -> None:
    baseline = Baseline.learn(events_for(**BASELINE_FLEET, episodes={}))
    model_dir = MODELS_DIR / "endpoint" / "fleet_baseline"
    model_dir.mkdir(parents=True, exist_ok=True)
    artifact = model_dir / "baseline.json"
    artifact.write_text(json.dumps(baseline.to_dict(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    sigma = SigmaDetector()

    layers = ("host_rules", "sigma", "auth_rules")
    detected = {layer: Counter() for layer in (*layers, "any_layer")}
    for seed in TEST_SEEDS:
        findings = layer_findings(events_for(windows_hosts=12, linux_hosts=3, hours=4.0, seed=seed,
                                             episodes={s: 1 for s in SCENARIOS}), baseline, sigma)
        caught_any = set()
        for layer in layers:
            caught = set().union(*(lbls for _, lbls in findings[layer])) & set(SCENARIOS)
            detected[layer].update(caught)
            caught_any |= caught
        detected["any_layer"].update(caught_any)

    false_positives = {layer: Counter() for layer in layers}
    for seed in BENIGN_SEEDS:
        findings = layer_findings(events_for(windows_hosts=12, linux_hosts=3, hours=8.0, seed=seed, episodes={}),
                                  baseline, sigma)
        for layer in layers:
            false_positives[layer].update(rule for rule, _ in findings[layer])

    episodes = len(TEST_SEEDS)
    detection = {
        scenario: {layer: f"{detected[layer][scenario]}/{episodes}" for layer in (*layers, "any_layer")}
        for scenario in SCENARIOS
    }
    report = {
        "version": VERSION,
        "baseline": {"learned_from": {**BASELINE_FLEET, "episodes": "none (benign only)"},
                     "sizes": {k: len(v) for k, v in baseline.to_dict().items()}},
        "detection_per_scenario": detection,
        "false_positive_findings_on_benign_fleets": {
            "fleets": len(BENIGN_SEEDS),
            "by_layer": {layer: dict(counts) for layer, counts in false_positives.items()},
        },
        "sigma_rules_loaded": len(sigma.report.loaded),
        "sigma_rules_unsupported": sigma.report.unsupported,
        "environment": environment(),
    }
    write_report("endpoint", report)

    per_layer_totals = defaultdict(int)
    for scenario in SCENARIOS:
        per_layer_totals["any_layer"] += detected["any_layer"][scenario]
    write_model("endpoint", "fleet_baseline", artifact, {
        "version": VERSION,
        "artifact_format": "json_baseline",
        "training_dataset": "SENTIVRA simulated endpoint fleet (benign only), not real telemetry",
        "datasets": [{"name": "SENTIVRA simulated endpoint telemetry", "role": "baseline (benign only)",
                      "license": "Apache-2.0 (generated by this repository)",
                      "source": "backend/app/demo/endpoint_sim.py", "notes": f"FleetConfig {BASELINE_FLEET}"}],
        "splits": {"baseline_fleet_hosts": BASELINE_FLEET["windows_hosts"] + BASELINE_FLEET["linux_hosts"],
                   "test_fleets": len(TEST_SEEDS), "benign_fp_fleets": len(BENIGN_SEEDS)},
        "split_method": "baseline and every evaluation fleet use different simulator seeds",
        "preprocessing": {"normalization": "paths lowercased, user-name path segment replaced with <user>"},
        "feature_schema": sorted(baseline.to_dict()),
        "evaluation_metrics": {
            "episodes_detected_any_layer": per_layer_totals["any_layer"] / (episodes * len(SCENARIOS)),
            "false_positive_findings_all_layers": float(sum(sum(c.values()) for c in false_positives.values())),
        },
        "evaluation": {"detection_per_scenario": detection,
                       "false_positives": {k: dict(v) for k, v in false_positives.items()},
                       "report": "research/evaluation/endpoint/report.json"},
        "limitations": [
            ("Learned from, and evaluated on, Sentivra's own simulator. A real deployment must learn its own "
             "baseline from its own fleet; this one describes simulated hosts."),
            ("The simulator defines both normal and anomalous behavior, so these detection and false-positive "
             "numbers are optimistic."),
            ("Exact-name baselines can't generalize over per-download file names; the lineage rule relies on "
             "code signatures to avoid flagging signed installers."),
            "No endpoint ML model in this version; the brief's behavioral Isolation Forest is not implemented.",
        ],
    })

    print("detection per scenario (episodes detected / 5):")
    print(f"  {'scenario':32} " + " ".join(f"{layer:>11}" for layer in (*layers, "any_layer")))
    for scenario, row in detection.items():
        print(f"  {scenario:32} " + " ".join(f"{row[layer]:>11}" for layer in (*layers, "any_layer")))
    print("false-positive findings on 10 benign fleets:", {k: dict(v) for k, v in false_positives.items()})


if __name__ == "__main__":
    main()
