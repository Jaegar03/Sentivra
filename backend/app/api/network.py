"""Network analysis endpoints (brief §26: "allow a sample PCAP/CSV
network-flow dataset to be uploaded").

POST /api/v1/network/analyze   upload a PCAP/PCAPNG or a flow CSV
                               (Sentivra columns or CICFlowMeter/CIC-IDS2017)
POST /api/v1/network/demo      analyze the bundled synthetic sample (DEMO_DATA)

Parsed flows live in memory only for the duration of the request and are
discarded afterwards. What gets persisted is the event summary and the
alert, not the traffic itself.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_db, get_detector_registry
from app.core.config import get_settings
from app.core.rules import mitre_for
from app.demo.network_flows import demo_batch
from app.detectors.network.flow import FlowParseError, FlowRecord, parse_flow_csv
from app.detectors.network.pcap import looks_like_capture, parse_pcap
from app.detectors.network.suite import BatchAnalysis
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from app.ml.batch_stats import excess_flags
from app.security.uploads import UploadTooLarge, validate_upload_size
from app.services.pipeline import run_pipeline
from app.services.transient_store import flow_batches

router = APIRouter(prefix="/api/v1/network", tags=["network"])


def _serialize(analysis: BatchAnalysis | None) -> dict:
    if analysis is None:
        return {"available": False}
    excess = excess_flags(analysis.flow_count, analysis.model_flagged_total, analysis.benign_flag_rate)
    return {
        "flow_count": analysis.flow_count,
        "fusion_cut": analysis.fusion_cut,
        "model_flagged_total": analysis.model_flagged_total,
        "model_flag_significance": {"expected_by_chance": round(excess.expected, 1), "p_value": excess.p_value,
                                    "significant": excess.significant, "summary": excess.describe()},
        "layer_status": analysis.layer_status,
        "layer_fire_counts": analysis.layer_fire_counts,
        "behavior_findings": [
            {
                "rule": f.rule,
                "category": f.category,
                "description": f.description,
                "subject": f.subject,
                "details": f.details,
                "flow_count": f.flow_count,
                "mitre_attack": [m.model_dump() for m in mitre_for(f.mitre_key)],
            }
            for f in analysis.behavior
        ],
        "flagged_flows_total": analysis.flagged_total,
        "flagged_flows": [
            {
                "flow": {k: v for k, v in v.flow.to_dict().items() if k != "label"},
                # Ground truth is only present for demo data or labeled CSVs;
                # it is shown for comparison and never used by any layer.
                "ground_truth_label": v.flow.label or None,
                "fused_score": round(v.fused_score, 4),
                "fired_layers": v.fired_layers,
                "explanations": [r.explanation() for r in v.layers if r.fired],
                "behavior_rules": v.rules,
            }
            for v in analysis.flagged
        ],
    }


async def _analyze(
    flows: list[FlowRecord],
    *,
    source: str,
    source_type: SourceType,
    metadata: dict,
    db: Session,
    registry: DetectorRegistry,
) -> dict:
    if not flows:
        raise HTTPException(status_code=400, detail="No flows found in the input")
    entry = {"flows": flows, "analysis": None}
    batch_id = flow_batches.put(entry)
    try:
        event = SecurityEvent(
            event_type=SecurityEventType.NETWORK_FLOW,
            source=source,
            source_type=source_type,
            metadata={**metadata, "flow_batch_id": batch_id, "flow_count": len(flows)},
        )
        findings, assessment = await run_pipeline(event, db=db, registry=registry, actor=f"{source}_api")
    finally:
        flow_batches.discard(batch_id)
    return {
        "event_id": event.event_id,
        "source_type": source_type.value,
        **{k: v for k, v in metadata.items() if k in ("input_format", "truncated", "filename", "sha256")},
        "network": _serialize(entry["analysis"]),
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }


@router.post("/analyze")
async def analyze_capture(
    file: UploadFile,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    settings = get_settings()
    data = await file.read()
    try:
        validate_upload_size(len(data))
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

    truncated = False
    if looks_like_capture(data):
        try:
            flows, stats = await run_in_threadpool(parse_pcap, data, max_packets=settings.max_pcap_packets)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not parse capture: {exc}") from exc
        input_format, truncated = "pcap", stats.truncated
    else:
        try:
            flows, input_format = await run_in_threadpool(parse_flow_csv, data, max_rows=settings.max_network_flows)
        except FlowParseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        truncated = len(flows) >= settings.max_network_flows

    return await _analyze(
        flows,
        source="network_upload",
        source_type=SourceType.LIVE,
        metadata={
            "input_format": input_format,
            "truncated": truncated,
            "filename": (file.filename or "upload")[:200],
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        db=db,
        registry=registry,
    )


@router.post("/demo")
async def analyze_demo(
    seed: int = Query(2026, ge=0, le=10_000),
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    flows = await run_in_threadpool(demo_batch, seed)
    return await _analyze(
        flows,
        source="network_demo",
        source_type=SourceType.DEMO_DATA,
        metadata={"input_format": "demo_generator", "truncated": False, "generator_seed": seed},
        db=db,
        registry=registry,
    )
