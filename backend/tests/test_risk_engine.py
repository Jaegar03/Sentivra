"""RiskEngine is the one place a bug silently changes every alert in the
system (docs/architecture.md §7) — tested directly with fixed input/output
pairs, independent of any real detector."""

from __future__ import annotations

from app.risk.engine import RiskEngine
from app.schemas.detection import (
    DetectionResult,
    DetectorCategory,
    Evidence,
    RecommendedAction,
    Severity,
)


def _finding(category: DetectorCategory, severity: Severity, score: float, confidence: float) -> DetectionResult:
    evidence = [Evidence(type="test", detail="synthetic evidence")] if severity.rank > 1 else []
    return DetectionResult(
        detector=f"Test{category.value}",
        category=category,
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=evidence,
        recommended_action=RecommendedAction.REVIEW,
        model_version="test-v0",
    )


def test_no_findings_is_safe():
    engine = RiskEngine()
    assessment = engine.assess("evt-1", [])
    assert assessment.severity == Severity.SAFE
    assert assessment.risk_score == 0


def test_single_low_confidence_finding_cannot_reach_critical():
    engine = RiskEngine()
    finding = _finding(DetectorCategory.PHISHING, Severity.HIGH, score=0.95, confidence=0.55)
    assessment = engine.assess("evt-2", [finding])
    assert assessment.severity != Severity.CRITICAL


def test_single_very_high_confidence_finding_can_reach_critical():
    engine = RiskEngine()
    finding = _finding(DetectorCategory.MALWARE, Severity.CRITICAL, score=0.99, confidence=0.98)
    assessment = engine.assess("evt-3", [finding])
    assert assessment.severity == Severity.CRITICAL


def test_corroboration_across_categories_boosts_score_above_single_detector():
    engine = RiskEngine()
    single = engine.assess(
        "evt-4a", [_finding(DetectorCategory.PROMPT_INJECTION, Severity.MEDIUM, score=0.55, confidence=0.7)]
    )
    corroborated = engine.assess(
        "evt-4b",
        [
            _finding(DetectorCategory.PROMPT_INJECTION, Severity.MEDIUM, score=0.55, confidence=0.7),
            _finding(DetectorCategory.PHISHING, Severity.MEDIUM, score=0.5, confidence=0.7),
        ],
    )
    assert corroborated.risk_score > single.risk_score


def test_risk_assessment_never_claims_calibrated_probability():
    engine = RiskEngine()
    assessment = engine.assess("evt-5", [_finding(DetectorCategory.SQL_INJECTION, Severity.HIGH, 0.8, 0.8)])
    assert assessment.is_calibrated_probability is False


def test_evidence_required_above_low_severity_is_enforced_by_schema():
    import pytest

    with pytest.raises(ValueError):
        DetectionResult(
            detector="BrokenDetector",
            category=DetectorCategory.MALWARE,
            severity=Severity.HIGH,
            score=0.9,
            confidence=0.9,
            evidence=[],  # invalid: HIGH severity requires evidence
            recommended_action=RecommendedAction.BLOCK,
        )
