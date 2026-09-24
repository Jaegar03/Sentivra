"""The shared analysis pipeline: SecurityEvent -> applicable detectors ->
RiskEngine -> persistence -> audit log. Used by every ingestion path
(POST /analyze/file today; POST /events and the remaining /analyze/*
endpoints in later phases) so there is exactly one place this flow is
implemented (docs/architecture.md §3).
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.audit import service as audit_service
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent
from app.risk.engine import RiskEngine
from app.schemas.detection import DetectionResult, RiskAssessment
from app.security.auth import current_actor
from app.services.alert_repository import AlertRepository
from app.services.event_repository import EventRepository

logger = logging.getLogger("sentivra.pipeline")

_risk_engine = RiskEngine()


async def run_pipeline(
    event: SecurityEvent,
    *,
    db: Session,
    registry: DetectorRegistry,
    actor: str | None = None,
) -> tuple[list[DetectionResult], RiskAssessment]:
    detectors = registry.applicable_to(event)

    async def _run_one(detector) -> DetectionResult | None:
        try:
            return await detector.analyze(event)
        except Exception:
            logger.exception("Detector %s failed on event %s", detector.name, event.event_id)
            return None

    results = await asyncio.gather(*(_run_one(d) for d in detectors))
    findings = [r for r in results if r is not None and r.severity.value != "SAFE"]

    assessment = _risk_engine.assess(event.event_id, findings)

    EventRepository(db).create_if_absent(event)
    if assessment.severity.rank > 0:  # only persist an alert when there's something to alert on
        AlertRepository(db).create(assessment)
    audit_service.record(
        db,
        actor=actor or current_actor(),
        action="analyze",
        resource=f"event:{event.event_id}",
        detail={"severity": assessment.severity.value, "risk_score": assessment.risk_score},
    )

    return findings, assessment
