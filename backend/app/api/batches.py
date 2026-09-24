"""Shared plumbing for endpoints that analyze a batch of events together
(endpoint telemetry, log files): park the events in the transient store, run
the pipeline on one batch event, return what each detector found."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from app.services.pipeline import run_pipeline
from app.services.transient_store import event_batches


async def analyze_batch(
    events: list[SecurityEvent],
    *,
    batch_type: SecurityEventType,
    source: str,
    source_type: SourceType,
    metadata: dict,
    db: Session,
    registry: DetectorRegistry,
) -> dict:
    if not events:
        raise HTTPException(status_code=400, detail="No events found in the input")
    entry: dict = {"events": events, "analysis": {}}
    batch_id = event_batches.put(entry)
    try:
        hosts = sorted({e.metadata.get("host") for e in events if e.metadata.get("host")})
        event = SecurityEvent(
            event_type=batch_type,
            source=source,
            source_type=source_type,
            metadata={**metadata, "event_batch_id": batch_id, "event_count": len(events), "hosts": hosts[:50]},
        )
        findings, assessment = await run_pipeline(event, db=db, registry=registry)
    finally:
        event_batches.discard(batch_id)
    return {
        "event_id": event.event_id,
        "source_type": source_type.value,
        "event_count": len(events),
        "hosts": hosts,
        **metadata,
        "analysis": entry["analysis"],
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }
