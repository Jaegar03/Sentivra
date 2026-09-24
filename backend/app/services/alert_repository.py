"""AlertRepository — persists RiskAssessment results as queryable alerts."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.orm import AlertORM
from app.schemas.detection import RiskAssessment


class AlertRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, assessment: RiskAssessment) -> AlertORM:
        row = AlertORM(
            alert_id=assessment.assessment_id,
            event_id=assessment.event_id,
            risk_score=assessment.risk_score,
            severity=assessment.severity.value,
            classification=assessment.classification,
            confidence=assessment.confidence,
            assessment_json=assessment.model_dump_json(),
        )
        self._db.add(row)
        self._db.commit()
        self._db.refresh(row)
        return row

    def get(self, alert_id: str) -> AlertORM | None:
        return self._db.get(AlertORM, alert_id)

    def list_recent(
        self, limit: int = 50, offset: int = 0, min_severity_rank: int = 0
    ) -> list[AlertORM]:
        stmt = select(AlertORM).order_by(AlertORM.created_at.desc()).offset(offset).limit(limit)
        rows = list(self._db.execute(stmt).scalars())
        if min_severity_rank <= 0:
            return rows
        from app.schemas.detection import Severity

        return [r for r in rows if Severity(r.severity).rank >= min_severity_rank]

    def to_domain(self, row: AlertORM) -> RiskAssessment:
        return RiskAssessment.model_validate_json(row.assessment_json)
