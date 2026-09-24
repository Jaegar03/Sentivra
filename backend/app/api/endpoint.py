"""Endpoint telemetry endpoints (brief §12).

POST /api/v1/endpoint/osquery   upload osquery result logs: the NDJSON file
                                osquery's filesystem logger writes
                                (osqueryd.results.log), or a JSON array
POST /api/v1/endpoint/demo      analyze a simulated fleet (SIMULATED)

Results are normalized by app.events.osquery. Queries it recognizes are the
ones in endpoint-agent/osquery/sentivra-pack.conf; rows from other queries
are counted in `normalizer_stats`, not guessed at.
"""

from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.batches import analyze_batch
from app.api.deps import get_db, get_detector_registry
from app.core.config import get_settings
from app.demo.endpoint_sim import demo_telemetry
from app.detectors.registry import DetectorRegistry
from app.events.osquery import OsqueryParseError, normalize
from app.events.schema import SecurityEventType, SourceType
from app.security.auth import require_scopes
from app.security.uploads import UploadTooLarge, validate_upload_size

router = APIRouter(prefix="/api/v1/endpoint", tags=["endpoint"])


def _parse_results(data: bytes, max_rows: int) -> tuple[list[dict], bool]:
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise OsqueryParseError("osquery results must be UTF-8 JSON") from exc
    if text.startswith("["):
        rows = json.loads(text)
        if not isinstance(rows, list):
            raise OsqueryParseError("expected a JSON array of osquery result objects")
    else:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return rows[:max_rows], len(rows) > max_rows


@router.post("/osquery", dependencies=[Depends(require_scopes("ingest"))])
async def ingest_osquery(
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
        rows, truncated = await run_in_threadpool(_parse_results, data, get_settings().max_endpoint_rows)
        events, stats = await run_in_threadpool(lambda: normalize(rows, source_type=SourceType.LIVE))
    except (OsqueryParseError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse osquery results: {exc}") from exc
    return await analyze_batch(
        events, batch_type=SecurityEventType.ENDPOINT_BATCH, source="osquery_upload", source_type=SourceType.LIVE,
        metadata={"normalizer_stats": stats, "truncated": truncated, "filename": (file.filename or "upload")[:200],
                  "sha256": hashlib.sha256(data).hexdigest()},
        db=db, registry=registry,
    )


@router.post("/demo", dependencies=[Depends(require_scopes("analyze"))])
async def endpoint_demo(
    seed: int = Query(2026, ge=0, le=10_000),
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    rows = await run_in_threadpool(demo_telemetry, seed)
    events, stats = normalize(rows, source_type=SourceType.SIMULATED)
    return await analyze_batch(
        events, batch_type=SecurityEventType.ENDPOINT_BATCH, source="endpoint_simulator",
        source_type=SourceType.SIMULATED, metadata={"normalizer_stats": stats, "simulator_seed": seed},
        db=db, registry=registry,
    )
