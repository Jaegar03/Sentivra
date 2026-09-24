"""Loads the network scoring layers from the model registry and runs a batch
of flows through every available layer plus the behavior rules.

Each layer is optional. A layer whose model isn't trained (or fails its
SHA-256 check) is reported as unavailable with the reason, and the
remaining layers still run. Nothing is silently skipped or faked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np

from app.detectors.network import batch_rules
from app.detectors.network.features import feature_matrix
from app.detectors.network.flow import FlowRecord
from app.detectors.network.scoring import (
    ClassifierLayer,
    EmpiricalTail,
    LayerResult,
    OnnxAnomalyLayer,
    RobustScaling,
    StatisticalLayer,
    fuse,
)
from app.ml.loader import ModelIntegrityError, loader
from app.ml.registry import registry

logger = logging.getLogger("sentivra.network")

DEFAULT_FUSION_CUT = 0.615  # used only if the isolation_forest metadata (which carries it) is missing
# Without a measured benign flag rate, assume the worst the cut allows (its FPR budget).
DEFAULT_BENIGN_FLAG_RATE = 0.01


@dataclass
class FlowVerdict:
    index: int
    flow: FlowRecord
    fused_score: float
    layers: list[LayerResult]
    rules: list[str] = field(default_factory=list)

    @property
    def fired_layers(self) -> list[str]:
        return [r.layer for r in self.layers if r.fired]


@dataclass
class BatchAnalysis:
    flow_count: int
    flagged_total: int                          # every flow flagged by the models or covered by a rule
    flagged: list[FlowVerdict]                  # the highest-scoring of those, capped for the response
    behavior: list[batch_rules.BehaviorFinding]
    layer_status: dict[str, str]
    fusion_cut: float
    layer_fire_counts: dict[str, int]
    model_flagged_total: int                    # flows at or above the fusion cut
    benign_flag_rate: float                     # share of benign calibration flows at or above the cut


class NetworkModelSuite:
    def __init__(self) -> None:
        self.layers: dict[str, object] = {}
        self.status: dict[str, str] = {}
        self.fusion_cut = DEFAULT_FUSION_CUT
        self.benign_flag_rate = DEFAULT_BENIGN_FLAG_RATE
        self._load()

    def _load(self) -> None:
        def entry(name):
            e = registry.get("network", name)
            if e is None or not e.trained:
                self.status[name] = "Not trained (run research/experiments/train_network_models.py)"
                return None
            return e

        if (e := entry("isolation_forest")) is not None:
            try:
                session = loader.load(e)
                pre = e.metadata.preprocessing
                scaling = RobustScaling.from_dict(pre["scaling"])
                self.layers["statistical"] = StatisticalLayer(
                    scaling, EmpiricalTail.from_dict(pre["statistical_baseline"]["tail"]),
                    pre["statistical_baseline"]["alpha"])
                self.layers["isolation_forest"] = OnnxAnomalyLayer(
                    "isolation_forest", session, scaling, EmpiricalTail.from_dict(pre["tail"]), pre["alpha"])
                fusion = pre.get("fusion", {})
                self.fusion_cut = float(fusion.get("cut", DEFAULT_FUSION_CUT))
                self.benign_flag_rate = float(fusion.get("benign_flag_rate", DEFAULT_BENIGN_FLAG_RATE))
                self.status["statistical"] = self.status["isolation_forest"] = "Available"
            except (ModelIntegrityError, KeyError) as exc:
                self.status["isolation_forest"] = self.status["statistical"] = f"Error: {exc}"
        else:
            self.status["statistical"] = self.status["isolation_forest"]

        if (e := entry("autoencoder")) is not None:
            try:
                pre = e.metadata.preprocessing
                self.layers["autoencoder"] = OnnxAnomalyLayer(
                    "autoencoder", loader.load(e), RobustScaling.from_dict(pre["scaling"]),
                    EmpiricalTail.from_dict(pre["tail"]), pre["alpha"])
                self.status["autoencoder"] = "Available"
            except (ModelIntegrityError, KeyError) as exc:
                self.status["autoencoder"] = f"Error: {exc}"

        if (e := entry("classifier")) is not None:
            try:
                cal = e.metadata.calibration or {}
                self.layers["classifier"] = ClassifierLayer(
                    loader.load(e), float(cal["a"]), float(cal["b"]), float(e.metadata.threshold))
                self.status["classifier"] = "Available"
            except (ModelIntegrityError, KeyError, TypeError) as exc:
                self.status["classifier"] = f"Error: {exc}"

        self.status["behavior_rules"] = "Available"
        for name, state in self.status.items():
            if state != "Available":
                logger.warning("Network layer %s: %s", name, state)

    def analyze(self, flows: list[FlowRecord], *, max_flagged: int = 200) -> BatchAnalysis:
        x = feature_matrix(flows)
        per_layer = {name: layer.score(x) for name, layer in self.layers.items()} if len(flows) else {}
        behavior = batch_rules.evaluate(flows)

        rules_for: dict[int, list[str]] = {}
        index = {id(f): i for i, f in enumerate(flows)}
        for finding in behavior:
            for member in finding.members:
                rules_for.setdefault(index[id(member)], []).append(finding.rule)

        verdicts: list[FlowVerdict] = []
        for i, flow in enumerate(flows):
            layers = [per_layer[name][i] for name in per_layer]
            score = fuse(layers)
            if score >= self.fusion_cut or i in rules_for:
                verdicts.append(FlowVerdict(i, flow, score, layers, rules_for.get(i, [])))
        verdicts.sort(key=lambda v: (v.fused_score, len(v.rules)), reverse=True)

        fire_counts = {name: int(np.sum([r.fired for r in results])) for name, results in per_layer.items()}
        return BatchAnalysis(
            flow_count=len(flows),
            flagged_total=len(verdicts),
            flagged=verdicts[:max_flagged],
            behavior=behavior,
            layer_status=dict(self.status),
            fusion_cut=self.fusion_cut,
            layer_fire_counts=fire_counts,
            model_flagged_total=sum(1 for v in verdicts if v.fused_score >= self.fusion_cut),
            benign_flag_rate=self.benign_flag_rate,
        )


_suite: NetworkModelSuite | None = None


def get_suite() -> NetworkModelSuite:
    global _suite
    if _suite is None:
        _suite = NetworkModelSuite()
    return _suite
