"""Scoring helpers shared by the text/URL detectors, so every detector maps
scores to severities and actions the same way the RiskEngine does."""

from __future__ import annotations

from collections.abc import Iterable

from app.schemas.detection import (
    DetectionResult,
    DetectorCategory,
    RecommendedAction,
    Severity,
)

# Same cut points as app.risk.engine, so a detector's own severity label
# and the aggregate label never disagree about what a score means.
_SEVERITY_CUTS = (
    (0.90, Severity.CRITICAL),
    (0.70, Severity.HIGH),
    (0.40, Severity.MEDIUM),
    (0.15, Severity.LOW),
)


def severity_from_score(score: float) -> Severity:
    for cut, severity in _SEVERITY_CUTS:
        if score >= cut:
            return severity
    return Severity.SAFE


def action_for(severity: Severity) -> RecommendedAction:
    if severity.rank >= Severity.HIGH.rank:
        return RecommendedAction.BLOCK
    if severity == Severity.MEDIUM:
        return RecommendedAction.REVIEW
    if severity == Severity.LOW:
        return RecommendedAction.MONITOR
    return RecommendedAction.ALLOW


def noisy_or(strengths: Iterable[float]) -> float:
    """Combine independent signal strengths in [0, 1]: 1 - prod(1 - s).
    Two moderate signals add up to more than either alone, but the result
    never exceeds 1 and a single weak signal stays weak."""
    remaining = 1.0
    for s in strengths:
        remaining *= 1.0 - max(0.0, min(1.0, s))
    return 1.0 - remaining


def safe_result(
    detector: str,
    category: DetectorCategory,
    *,
    confidence: float = 0.0,
    model_version: str | None = None,
) -> DetectionResult:
    return DetectionResult(
        detector=detector,
        category=category,
        severity=Severity.SAFE,
        score=0.0,
        confidence=confidence,
        evidence=[],
        recommended_action=RecommendedAction.ALLOW,
        model_version=model_version,
    )
