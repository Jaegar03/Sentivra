"""Evaluation metrics for binary detectors (brief §27): precision, recall,
F1, PR-AUC, ROC-AUC, false-positive and false-negative rates, bootstrap
confidence intervals, and latency. Used by the training scripts and tested
directly, so the numbers in model cards come from one implementation.

Accuracy is deliberately not reported. On imbalanced security data a model
that flags nothing can score very high accuracy.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


@dataclass
class BinaryMetrics:
    n: int
    positives: int
    negatives: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_rate: float
    pr_auc: float | None
    roc_auc: float | None

    def to_dict(self) -> dict:
        return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in asdict(self).items()}


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def binary_metrics(y_true: Sequence[int], y_pred: Sequence[int], scores: Sequence[float] | None = None) -> BinaryMetrics:
    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_pred, dtype=int)
    tp = int(((yt == 1) & (yp == 1)).sum())
    fp = int(((yt == 0) & (yp == 1)).sum())
    tn = int(((yt == 0) & (yp == 0)).sum())
    fn = int(((yt == 1) & (yp == 0)).sum())
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    pr_auc = roc_auc = None
    if scores is not None and 0 < yt.sum() < len(yt):
        s = np.asarray(scores, dtype=float)
        pr_auc = float(average_precision_score(yt, s))
        roc_auc = float(roc_auc_score(yt, s))

    return BinaryMetrics(
        n=len(yt),
        positives=int(yt.sum()),
        negatives=int(len(yt) - yt.sum()),
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=_safe_div(fp, fp + tn),
        false_negative_rate=_safe_div(fn, fn + tp),
        pr_auc=pr_auc,
        roc_auc=roc_auc,
    )


def threshold_for_max_fpr(y_true: Sequence[int], probs: Sequence[float], max_fpr: float) -> float:
    """Lowest threshold whose false-positive rate on the given data is at
    most `max_fpr`. That maximizes recall subject to the FP budget. Call
    this on the calibration split only, never on test data (brief §28)."""
    yt = np.asarray(y_true, dtype=int)
    p = np.asarray(probs, dtype=float)
    negatives = max(1, int((yt == 0).sum()))
    for t in np.unique(p):  # ascending
        fpr = ((p >= t) & (yt == 0)).sum() / negatives
        if fpr <= max_fpr:
            return float(t)
    return float(p.max()) + 1e-9


def bootstrap_ci(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    *,
    n_resamples: int = 1000,
    seed: int = 0,
) -> dict[str, list[float]]:
    """95% percentile-bootstrap intervals for precision, recall, F1 and FPR.
    Small test sets (like the 116-row prompt-injection test split) get wide
    intervals, and the model card should show that rather than hide it."""
    rng = np.random.default_rng(seed)
    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_pred, dtype=int)
    stats: dict[str, list[float]] = {"precision": [], "recall": [], "f1": [], "false_positive_rate": []}
    for _ in range(n_resamples):
        idx = rng.integers(0, len(yt), len(yt))
        m = binary_metrics(yt[idx], yp[idx])
        for key, values in stats.items():
            values.append(getattr(m, key))
    return {
        k: [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]
        for k, v in stats.items()
    }


def latency_ms(fn: Callable[[str], object], samples: Sequence[str], *, warmup: int = 5) -> dict[str, float]:
    """Single-input wall-clock latency (p50/p95/max) in milliseconds."""
    for s in samples[:warmup]:
        fn(s)
    timings = []
    for s in samples:
        start = time.perf_counter()
        fn(s)
        timings.append((time.perf_counter() - start) * 1000)
    arr = np.asarray(timings)
    return {
        "n": len(arr),
        "p50_ms": round(float(np.percentile(arr, 50)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "max_ms": round(float(arr.max()), 3),
    }
