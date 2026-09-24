"""POST /api/v1/analyze/{text,url,file,prompt,sql} (brief §25).

Only `file` is implemented in this phase (Phase 3). The remaining four
analyze endpoints depend on detectors landing in Phase 4
(SQLInjectionDetector, PhishingDetector/URLDetector, PromptInjectionDetector)
and return HTTP 501 with an explicit message in the meantime — a route
that silently 404s would be harder to distinguish from a typo than one
that honestly reports "not implemented yet" (brief §32's "no fake
features" principle applied to API surface, not just detection results).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.detectors.file.metadata import analyze_file
from app.detectors.registry import DetectorRegistry
from app.events.schema import AttachmentRef, SecurityEvent, SecurityEventType, SourceType
from app.security.uploads import (
    ArchiveBombSuspected,
    UploadTooLarge,
    inspect_zip_bomb_safe,
    validate_upload_size,
)
from app.services.file_blob_store import blob_store
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api/v1/analyze", tags=["analyze"])

_NOT_YET_IMPLEMENTED = (
    "This endpoint is defined by the SENTIVRA API contract (docs/api.md) but its "
    "detector has not landed yet in this phased build — see docs/architecture.md "
    "§ Implementation Order. Returning 501 rather than a fake result."
)


@router.post("/file")
async def analyze_file_endpoint(
    file: UploadFile,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    data = await file.read()
    try:
        validate_upload_size(len(data))
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

    if (file.filename or "").lower().endswith(".zip"):
        try:
            inspect_zip_bomb_safe(data)
        except ArchiveBombSuspected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    meta = analyze_file(file.filename or "unnamed", data, declared_mime=file.content_type)

    blob_store.put(meta.sha256, data)
    try:
        event = SecurityEvent(
            event_type=SecurityEventType.FILE_ANALYSIS,
            source="api",
            source_type=SourceType.LIVE,
            attachments=[
                AttachmentRef(
                    filename=meta.filename,
                    declared_mime=meta.declared_mime,
                    size_bytes=meta.size_bytes,
                    sha256=meta.sha256,
                )
            ],
            metadata={"sha256": meta.sha256, "file_metadata": meta.__dict__},
        )
        findings, assessment = await run_pipeline(event, db=db, registry=registry, actor="analyze_file_api")
    finally:
        blob_store.discard(meta.sha256)  # never retained past this request (brief §30)

    return {
        "event_id": event.event_id,
        "file_metadata": {
            "filename": meta.filename,
            "sha256": meta.sha256,
            "size_bytes": meta.size_bytes,
            "entropy": round(meta.entropy, 3),
            "matched_magic_types": meta.matched_magic_types,
            "extension_mismatch": meta.extension_mismatch,
            "is_polyglot": meta.is_polyglot,
        },
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }


@router.post("/text")
async def analyze_text_endpoint() -> None:
    raise HTTPException(status_code=501, detail=_NOT_YET_IMPLEMENTED)


@router.post("/url")
async def analyze_url_endpoint() -> None:
    raise HTTPException(status_code=501, detail=_NOT_YET_IMPLEMENTED)


@router.post("/prompt")
async def analyze_prompt_endpoint() -> None:
    raise HTTPException(status_code=501, detail=_NOT_YET_IMPLEMENTED)


@router.post("/sql")
async def analyze_sql_endpoint() -> None:
    raise HTTPException(status_code=501, detail=_NOT_YET_IMPLEMENTED)
