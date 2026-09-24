"""Helpers shared by the unsupervised anomaly layers (network flows, endpoint
processes): robust scaling fit on benign data, and empirical p-values
against benign calibration scores."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

_IQR_TO_SIGMA = 1.349  # IQR of a normal distribution in standard deviations


@dataclass
class EmpiricalTail:
    """Benign calibration scores summarized by quantiles, for p-values."""

    quantiles: np.ndarray       # ascending, at probabilities linspace(0, 1, len)
    n_calibration: int

    def p_value(self, scores: np.ndarray) -> np.ndarray:
        probs = np.linspace(0.0, 1.0, len(self.quantiles))
        cdf = np.interp(scores, self.quantiles, probs, left=0.0, right=1.0)
        floor = 1.0 / (self.n_calibration + 1)  # can't claim rarer than the calibration set can show
        return np.maximum(1.0 - cdf, floor)

    @classmethod
    def fit(cls, benign_scores: np.ndarray, points: int = 1001) -> EmpiricalTail:
        return cls(np.quantile(benign_scores, np.linspace(0.0, 1.0, points)), len(benign_scores))

    def to_dict(self) -> dict:
        return {"quantiles": [round(float(q), 6) for q in self.quantiles], "n_calibration": self.n_calibration}

    @classmethod
    def from_dict(cls, d: dict) -> EmpiricalTail:
        return cls(np.asarray(d["quantiles"], dtype=float), int(d["n_calibration"]))


@dataclass
class RobustScaling:
    center: np.ndarray
    scale: np.ndarray           # IQR per feature (1.0 where the IQR is zero)

    def transform(self, x: np.ndarray) -> np.ndarray:
        return (x - self.center) / self.scale

    def robust_z(self, x: np.ndarray) -> np.ndarray:
        return (x - self.center) / (self.scale / _IQR_TO_SIGMA)

    def to_dict(self) -> dict:
        return {"center": self.center.tolist(), "scale": self.scale.tolist()}

    @classmethod
    def from_dict(cls, d: dict) -> RobustScaling:
        return cls(np.asarray(d["center"], dtype=float), np.asarray(d["scale"], dtype=float))
