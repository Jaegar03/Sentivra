"""Per-flow scoring layers and how they are fused.

Four layers score each flow independently:
  * statistical    max robust z-score of any feature against the benign baseline
  * isolation_forest  anomaly score from an Isolation Forest (ONNX)
  * autoencoder    reconstruction error of an autoencoder trained on benign flows (ONNX)
  * classifier     calibrated probability from a supervised LightGBM model

The three unsupervised layers produce raw scores on incomparable scales. Each
is turned into an empirical p-value against benign *calibration* traffic
(the fraction of benign calibration flows that scored at least as high). A
layer fires when p <= alpha. That makes the layers comparable, and it
makes each one explainable ("higher than 99.8% of benign calibration
flows"). The classifier fires when its calibrated probability passes the
threshold chosen on the calibration split.

The training script (research/experiments/train_network_models.py)
evaluates this module loaded from the exported artifacts, so the metrics
in the model card describe the code path that actually runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from app.detectors.common import noisy_or
from app.detectors.network.features import FEATURE_NAMES
from app.ml.anomaly import EmpiricalTail, RobustScaling

# How much each layer contributes when it fires. Unsupervised layers only
# say "unusual", which is weaker evidence than a supervised model trained
# on labeled attacks; the statistical layer is the bluntest of all.
LAYER_WEIGHTS = {"statistical": 0.3, "isolation_forest": 0.45, "autoencoder": 0.45, "classifier": 0.6}


@dataclass
class LayerResult:
    layer: str
    fired: bool
    score: float                 # raw score (units depend on the layer)
    p_value: float | None = None  # unsupervised layers
    probability: float | None = None  # classifier
    top_features: list[tuple[str, float]] = field(default_factory=list)

    def explanation(self) -> str:
        feats = ", ".join(f"{name} ({value:+.1f})" for name, value in self.top_features[:3])
        if self.p_value is not None:
            rarer_than = (1.0 - self.p_value) * 100
            return f"{self.layer}: higher than {rarer_than:.1f}% of benign calibration flows; driven by {feats}"
        return f"{self.layer}: attack probability {self.probability:.2f}; driven by {feats}"


class StatisticalLayer:
    name = "statistical"

    def __init__(self, scaling: RobustScaling, tail: EmpiricalTail, alpha: float) -> None:
        self.scaling, self.tail, self.alpha = scaling, tail, alpha

    def raw_scores(self, x: np.ndarray) -> np.ndarray:
        return np.abs(self.scaling.robust_z(x)).max(axis=1)

    def score(self, x: np.ndarray) -> list[LayerResult]:
        z = self.scaling.robust_z(x)
        raw = np.abs(z).max(axis=1)
        p = self.tail.p_value(raw)
        return [
            LayerResult(self.name, bool(p[i] <= self.alpha), float(raw[i]), p_value=float(p[i]),
                        top_features=_top(z[i]))
            for i in range(len(x))
        ]


class OnnxAnomalyLayer:
    """Isolation Forest or autoencoder served through ONNX Runtime."""

    def __init__(self, name: str, session, scaling: RobustScaling, tail: EmpiricalTail, alpha: float) -> None:
        self.name, self.session, self.scaling, self.tail, self.alpha = name, session, scaling, tail, alpha
        self._input = session.get_inputs()[0].name

    def _run(self, xs: np.ndarray) -> list[np.ndarray]:
        return self.session.run(None, {self._input: xs.astype(np.float32)})

    def _reconstruct(self, xs: np.ndarray) -> np.ndarray:
        # skl2onnx's MLPRegressor graph emits shape (N * n_outputs, 1) for
        # multi-output models; the values are row-major, so reshape recovers
        # (N, n_outputs). The training script checks parity after this.
        return np.asarray(self._run(xs)[0], dtype=float).reshape(len(xs), -1)

    def raw_scores(self, x: np.ndarray) -> np.ndarray:
        xs = self.scaling.transform(x)
        if self.name == "isolation_forest":
            # skl2onnx's IsolationForest graph returns (label, decision_function);
            # negate so that higher means more anomalous, like the other layers.
            return -np.asarray(self._run(xs)[1], dtype=float).ravel()
        return ((self._reconstruct(xs) - xs) ** 2).mean(axis=1)

    def score(self, x: np.ndarray) -> list[LayerResult]:
        raw = self.raw_scores(x)
        p = self.tail.p_value(raw)
        xs = self.scaling.transform(x)
        if self.name == "autoencoder":
            attributions = (self._reconstruct(xs) - xs) ** 2
        else:
            attributions = self.scaling.robust_z(x)
        return [
            LayerResult(self.name, bool(p[i] <= self.alpha), float(raw[i]), p_value=float(p[i]),
                        top_features=_top(attributions[i]))
            for i in range(len(x))
        ]


class ClassifierLayer:
    name = "classifier"

    def __init__(self, booster, platt_a: float, platt_b: float, threshold: float) -> None:
        self.booster, self.platt_a, self.platt_b, self.threshold = booster, platt_a, platt_b, threshold

    def probabilities(self, x: np.ndarray) -> np.ndarray:
        raw = self.booster.predict(x, raw_score=True)
        return 1.0 / (1.0 + np.exp(-(self.platt_a * raw + self.platt_b)))

    def score(self, x: np.ndarray) -> list[LayerResult]:
        prob = self.probabilities(x)
        # LightGBM's built-in TreeSHAP: per-feature contributions to the raw
        # score (log-odds), last column is the expected value.
        contrib = self.booster.predict(x, pred_contrib=True)[:, :-1]
        return [
            LayerResult(self.name, bool(prob[i] >= self.threshold), float(prob[i]), probability=float(prob[i]),
                        top_features=_top(contrib[i], positive_only=True))
            for i in range(len(x))
        ]


def _top(values: np.ndarray, k: int = 3, positive_only: bool = False) -> list[tuple[str, float]]:
    order = np.argsort(values if positive_only else np.abs(values))[::-1][:k]
    return [(FEATURE_NAMES[i], float(values[i])) for i in order if not positive_only or values[i] > 0]


def fuse(layer_results: list[LayerResult]) -> float:
    """Flow-level score in [0, 1] from whichever layers fired."""
    return noisy_or(LAYER_WEIGHTS[r.layer] for r in layer_results if r.fired)
