"""POST /api/v1/logs/analyze — upload a log file: Linux auth.log / secure,
Windows Security events exported as JSON lines, or Wazuh alerts.json.

Lines are parsed by app.detectors.logs.parsers; unrecognized lines become
generic system_log events (so Sigma keyword rules still see them) and are
counted in `parse_stats`.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.batches import analyze_batch
from app.api.deps import get_db, get_detector_registry
from app.core.config import get_settings
from app.detectors.logs.parsers import parse_lines
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEventType, SourceType
from app.security.uploads import UploadTooLarge, validate_upload_size

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])


@router.post("/analyze")
async def analyze_logs(
    file: UploadFile,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    data = await file.read()
    try:
        validate_upload_size(len(data))
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Log files must be UTF-8 text") from exc
    events, stats = await run_in_threadpool(
        lambda: parse_lines(text, source_type=SourceType.LIVE, max_lines=get_settings().max_log_lines))
    return await analyze_batch(
        events, batch_type=SecurityEventType.LOG_BATCH, source="log_upload", source_type=SourceType.LIVE,
        metadata={"parse_stats": stats, "filename": (file.filename or "upload")[:200],
                  "sha256": hashlib.sha256(data).hexdigest()},
        db=db, registry=registry,
    )
