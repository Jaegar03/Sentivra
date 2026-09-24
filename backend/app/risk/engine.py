"""RiskEngine — aggregates DetectionResult[] into one RiskAssessment.

No single detector's output is ever forwarded as the final decision
(brief §18). The scoring policy:

1. Each finding contributes `score * confidence * reliability_weight`.
2. Findings from *independent* detector categories that agree (both fire
   with severity >= MEDIUM) receive a corroboration boost — the
   "veto/corroboration" pattern documented in docs/repository-analysis.md §1.
3. CRITICAL is reachable two ways only: one detector at very high
   confidence+score (>=0.9 each), or corroboration across >=2 independent
   categories. A single mediocre-confidence detector cannot alone produce
   CRITICAL — this is deliberate and unit-tested (backend/tests/test_risk_engine.py).

`risk_score` is a weighted heuristic aggregate in [0, 100], not a
statistically calibrated probability (brief §18) — see
RiskAssessment.is_calibrated_probability, always False in this phase.
"""

from __future__ import annotations

from app.schemas.detection import DetectionResult, RiskAssessment, Severity

# Per-category reliability weights: how much to trust a category's score
# relative to others, based on how deterministic/well-validated the
# detection method is. Signature/rule-based categories (SQLi regex layer,
# YARA/Sigma) are weighted slightly higher than pure-ML categories, per the
# brief's "never let one ML model decide" principle. Tune via evaluation,
# not vibes — see docs/model-card.md for what's actually been measured.
DEFAULT_RELIABILITY_WEIGHTS: dict[str, float] = {
    "network_anomaly": 0.85,
    "prompt_injection": 0.85,
    "sql_injection": 0.9,
    "phishing": 0.85,
    "malicious_url": 0.85,
    "malware": 0.95,
    "behavioral_anomaly": 0.75,
    "log_anomaly": 0.8,
    "sigma_rule": 0.95,
}

_SCORE_TO_SEVERITY = (
    (0.90, Severity.CRITICAL),
    (0.70, Severity.HIGH),
    (0.40, Severity.MEDIUM),
    (0.15, Severity.LOW),
)


def _severity_for_risk_score(risk_score: int) -> Severity:
    normalized = risk_score / 100
    for threshold, severity in _SCORE_TO_SEVERITY:
        if normalized >= threshold:
            return severity
    return Severity.SAFE


def _classification_for(findings: list[DetectionResult]) -> str:
    if not findings:
        return "NO_FINDINGS"
    top = max(findings, key=lambda f: f.score * f.confidence)
    return top.category.value.upper()


class RiskEngine:
    def __init__(self, reliability_weights: dict[str, float] | None = None) -> None:
        self._weights = reliability_weights or DEFAULT_RELIABILITY_WEIGHTS

    def assess(self, event_id: str, findings: list[DetectionResult]) -> RiskAssessment:
        if not findings:
            return RiskAssessment(
                event_id=event_id,
                risk_score=0,
                severity=Severity.SAFE,
                classification="NO_FINDINGS",
                confidence=1.0,
                findings=[],
            )

        weighted_contributions: list[float] = []
        for f in findings:
            weight = self._weights.get(f.category.value, 0.7)
            weighted_contributions.append(f.score * f.confidence * weight)

        base = max(weighted_contributions)

        # Corroboration: independent categories that both raised >= MEDIUM.
        corroborating_categories = {
            f.category for f in findings if f.severity.rank >= Severity.MEDIUM.rank
        }
        corroboration_boost = 0.0
        if len(corroborating_categories) >= 2:
            corroboration_boost = 0.12 * (len(corroborating_categories) - 1)

        aggregate = min(1.0, base + corroboration_boost)
        risk_score = round(aggregate * 100)

        # CRITICAL gate: require either a single very-high-confidence
        # finding, or genuine multi-category corroboration — never a lone
        # mediocre detector.
        has_strong_single_finding = any(
            f.score >= 0.9 and f.confidence >= 0.9 for f in findings
        )
        severity = _severity_for_risk_score(risk_score)
        if severity == Severity.CRITICAL and not (
            has_strong_single_finding or len(corroborating_categories) >= 2
        ):
            severity = Severity.HIGH
            risk_score = min(risk_score, 89)

        overall_confidence = round(
            sum(f.confidence for f in findings) / len(findings), 2
        )

        return RiskAssessment(
            event_id=event_id,
            risk_score=risk_score,
            severity=severity,
            classification=_classification_for(findings),
            confidence=overall_confidence,
            findings=findings,
        )
