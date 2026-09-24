"""GET /api/v1/metrics — operational counters and dashboard aggregates.

These are counts of what Sentivra has seen, never model accuracy. Model
evaluation metrics live in GET /api/v1/models and docs/model-card.md, each
tied to a dataset, split and evaluation date (brief §33).

The security score is a transparent heuristic over *open* alerts in the
window, not a probability or a risk rating of the organization. Its formula
is returned with its value so no view can show the number without it.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.orm import AlertORM, EventORM
from app.security.auth import require_scopes
from app.services.alert_repository import AlertRepository
from app.services.event_repository import EventRepository

router = APIRouter(prefix="/api/v1", tags=["system"], dependencies=[Depends(require_scopes("read"))])

SCORE_PENALTIES = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
SEVERITY_ORDER = ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
# Detection domains shown on the dashboard, by the detectors that serve them.
# Domains whose detectors don't exist yet (URLs, prompts) are absent, not zero.
DOMAINS = {
    "network": {"NetworkAnomalyDetector"},
    "files": {"MalwareDetector", "YaraDetector", "ClamAVDetector"},
    "endpoint": {"BehavioralAnomalyDetector", "SigmaDetector", "LogDetector"},
}


def _as_utc(dt: datetime) -> datetime:
    # SQLite hands back naive datetimes; everything Sentivra stores is UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@router.get("/metrics")
async def metrics(window_hours: int = Query(24, ge=1, le=24 * 30), db: Session = Depends(get_db)) -> dict:
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=window_hours)
    rows = AlertRepository(db).since(cutoff)
    sources = EventRepository(db).summaries([r.event_id for r in rows])

    by_detector: Counter[str] = Counter()
    by_domain: Counter[str] = Counter({d: 0 for d in DOMAINS})
    for r in rows:
        detectors = {f["detector"] for f in json.loads(r.assessment_json).get("findings", [])}
        by_detector.update(detectors)
        by_domain.update(d for d, members in DOMAINS.items() if detectors & members)

    bucket = timedelta(hours=1) if window_hours <= 72 else timedelta(days=1)
    buckets = int(timedelta(hours=window_hours) / bucket)
    start = now - bucket * buckets
    timeline = [0] * buckets
    for r in rows:
        index = int((_as_utc(r.created_at) - start) / bucket)
        if 0 <= index < buckets:
            timeline[index] += 1

    open_by_severity = Counter(r.severity for r in rows if r.status == "OPEN")
    penalty = sum(SCORE_PENALTIES.get(sev, 0) * n for sev, n in open_by_severity.items())

    return {
        "window_hours": window_hours,
        "generated_at": now.isoformat(),
        "totals": {
            "events": db.execute(select(func.count()).select_from(EventORM)).scalar_one(),
            "alerts": db.execute(select(func.count()).select_from(AlertORM)).scalar_one(),
        },
        "window": {
            "alerts": len(rows),
            "open_alerts": sum(1 for r in rows if r.status == "OPEN"),
            "by_severity": {s: sum(1 for r in rows if r.severity == s) for s in SEVERITY_ORDER},
            "open_by_severity": {s: open_by_severity.get(s, 0) for s in SEVERITY_ORDER},
            "by_status": dict(Counter(r.status for r in rows)),
            "by_classification": dict(Counter(r.classification for r in rows).most_common()),
            "by_detector": dict(by_detector.most_common()),
            "by_domain": dict(by_domain),
            "by_source_type": dict(Counter((sources.get(r.event_id) or {}).get("source_type") or "UNKNOWN"
                                           for r in rows)),
            "timeline": {
                "bucket": "hour" if bucket == timedelta(hours=1) else "day",
                "start": start.isoformat(),
                "counts": timeline,
            },
        },
        "security_score": {
            "value": max(0, 100 - penalty),
            "formula": ("100 − (25 × open CRITICAL + 10 × open HIGH + 4 × open MEDIUM + 1 × open LOW), "
                        f"over alerts raised in the last {window_hours} h, floored at 0"),
            "penalty": penalty,
            "note": ("A transparent heuristic over open alerts, not a probability and not a rating of the "
                     "organization's overall security."),
        },
        "note": ("Counts of what Sentivra has seen. Model evaluation metrics are reported per model via "
                 "GET /api/v1/models, each tied to a dataset and evaluation date."),
    }
