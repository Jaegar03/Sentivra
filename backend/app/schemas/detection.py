"""The detector output contract (brief §17) and risk assessment contract
(brief §18). Every detector returns exactly `DetectionResult`; the risk
engine consumes a list of them and returns exactly `RiskAssessment`.

`evidence` is enforced non-empty once severity passes LOW — see the
validator below. A detector claiming MEDIUM+ severity with no evidence is
treated as a bug, not a valid result (docs/architecture.md §1).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


class RecommendedAction(StrEnum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class DetectorCategory(StrEnum):
    NETWORK_ANOMALY = "network_anomaly"
    PROMPT_INJECTION = "prompt_injection"
    SQL_INJECTION = "sql_injection"
    PHISHING = "phishing"
    MALICIOUS_URL = "malicious_url"
    MALWARE = "malware"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    LOG_ANOMALY = "log_anomaly"
    SIGMA_RULE = "sigma_rule"


class MitreAttackMapping(BaseModel):
    """Brief §31: never invented — only populated when a detector has a
    documented, defensible mapping to a real ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str
    source: str  # e.g. "MITRE ATT&CK v15, ic sub-technique lookup"


class Evidence(BaseModel):
    type: str
    detail: str
    excerpt: str | None = None
    weight: float | None = None


class DetectionResult(BaseModel):
    detector: str
    category: DetectorCategory
    severity: Severity
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_action: RecommendedAction
    model_version: str | None = None
    mitre_attack: list[MitreAttackMapping] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _evidence_required_above_low(self) -> DetectionResult:
        if self.severity.rank > Severity.LOW.rank and not self.evidence:
            raise ValueError(
                f"{self.detector}: severity={self.severity} requires non-empty evidence"
            )
        return self


class RiskAssessment(BaseModel):
    assessment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[DetectionResult] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_calibrated_probability(self) -> bool:
        # risk_score is a weighted heuristic aggregate, never a calibrated
        # probability unless a detector's own score has been calibrated
        # and documented as such (brief §18) — always False in this phase.
        return False
