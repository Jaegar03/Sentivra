"""NetworkAnomalyDetector — signatures + telemetry + ML for network events
(brief §5–6).

For a batch of flows (an uploaded CSV/PCAP or the demo sample), it runs the
behavior rules and all four per-flow layers (statistical, Isolation Forest,
autoencoder, supervised classifier; see app.detectors.network.scoring). For
a single network_flow event it runs the per-flow layers only, since the
behavior rules need many flows to see a pattern.

Suricata and Zeek aren't replaced by this. They're separate engines;
when they aren't installed they are reported as Not Configured, and the
detector says what it is running instead.
"""

from __future__ import annotations

import asyncio

from app.core.config import get_settings
from app.core.rules import mitre_for
from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, noisy_or, safe_result, severity_from_score
from app.detectors.network.flow import FlowRecord
from app.detectors.network.suite import BatchAnalysis, get_suite
from app.events.schema import SecurityEvent, SecurityEventType
from app.ml.batch_stats import excess_flags
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence
from app.services.transient_store import flow_batches

_APPLICABLE = frozenset({SecurityEventType.NETWORK_FLOW, SecurityEventType.DNS_EVENT})
_MAX_EVIDENCE_FLOWS = 5


def flow_from_event(event: SecurityEvent) -> FlowRecord | None:
    net = event.network
    if net is None:
        return None
    return FlowRecord(
        src_ip=net.src_ip or "", dst_ip=net.dst_ip or "", src_port=net.src_port or 0,
        dst_port=net.dst_port or 0, protocol=(net.protocol or "tcp").lower(),
        start_time=event.timestamp.timestamp(), duration_s=(net.duration_ms or 0.0) / 1000.0,
        fwd_packets=net.packets_sent if net.packets_sent is not None else (net.packets or 0),
        bwd_packets=net.packets_received or 0,
        fwd_bytes=net.bytes_sent or 0, bwd_bytes=net.bytes_received or 0,
        dns_query=net.dns_query or "",
    )


def _engine_notes() -> list[str]:
    # Always said: neither engine's output is read in this version, whether
    # or not a path is configured, so no result may imply signature coverage.
    settings = get_settings()
    configured = " (a path is configured, but nothing reads it yet)"
    return [
        "Suricata: Not implemented; no signature alerts in this result"
        + (configured if settings.suricata_eve_log else ""),
        "Zeek: Not implemented; flows come from the upload, not Zeek telemetry"
        + (configured if settings.zeek_log_dir else ""),
    ]


class NetworkAnomalyDetector(BaseDetector):
    name = "NetworkAnomalyDetector"
    version = "0.1.0"
    category = DetectorCategory.NETWORK_ANOMALY
    applicable_event_types = _APPLICABLE

    async def is_available(self) -> DetectorAvailability:
        status = get_suite().status
        missing = {k: v for k, v in status.items() if v != "Available"}
        summary = ", ".join(f"{k}: {v}" for k, v in status.items())
        if not missing:
            return DetectorAvailability(status=AvailabilityStatus.AVAILABLE, detail=summary)
        if len(missing) < len(status):
            return DetectorAvailability(status=AvailabilityStatus.DEGRADED, detail=summary)
        return DetectorAvailability(status=AvailabilityStatus.NOT_CONFIGURED, detail=summary)

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        batch_id = event.metadata.get("flow_batch_id")
        entry = flow_batches.get(batch_id) if batch_id else None
        if entry is not None:
            flows = entry["flows"]
        else:
            flow = flow_from_event(event)
            if flow is None:
                return safe_result(self.name, self.category)
            flows = [flow]

        # CPU-bound (feature extraction, ONNX, LightGBM): keep it off the event loop.
        analysis = await asyncio.to_thread(get_suite().analyze, flows)
        if entry is not None:
            entry["analysis"] = analysis  # the API returns the detailed breakdown from here
        return self._result(analysis)

    def _result(self, analysis: BatchAnalysis) -> DetectionResult:
        evidence: list[Evidence] = []
        strengths: list[float] = []
        mitre_keys: list[str | None] = []

        for finding in analysis.behavior:
            strengths.append(finding.weight)
            mitre_keys.append(finding.mitre_key)
            details = ", ".join(f"{k}={v}" for k, v in finding.details.items())
            evidence.append(Evidence(
                type=f"behavior_rule:{finding.rule}",
                detail=f"{finding.description} [{finding.subject}; {details}]",
                weight=finding.weight,
            ))

        model_flagged = [v for v in analysis.flagged if v.fused_score >= analysis.fusion_cut]
        # Some benign flows pass the cut by construction (the calibrated flag
        # rate). Model evidence only counts toward the verdict when the batch
        # has significantly more flagged flows than that rate predicts.
        excess = excess_flags(analysis.flow_count, analysis.model_flagged_total, analysis.benign_flag_rate)
        if model_flagged and excess.significant:
            strengths.append(max(v.fused_score for v in model_flagged))
        elif model_flagged and analysis.flow_count == 1:
            strengths.append(0.2)  # a single flagged flow is a lead to look at, not an incident
        if model_flagged and (excess.significant or analysis.flow_count == 1):
            evidence.append(Evidence(
                type="model_consensus",
                detail=(f"Flows at or above the fusion cut {analysis.fusion_cut:.3f} (chosen on calibration "
                        f"data): {excess.describe()}"),
            ))
            for verdict in model_flagged[:_MAX_EVIDENCE_FLOWS]:
                f = verdict.flow
                explained = "; ".join(r.explanation() for r in verdict.layers if r.fired)
                evidence.append(Evidence(
                    type="anomalous_flow",
                    detail=f"{f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port}/{f.protocol}: {explained}",
                    weight=round(verdict.fused_score, 3),
                ))

        if not strengths:
            return safe_result(self.name, self.category, confidence=0.6, model_version=self._model_version())

        for note in _engine_notes():
            evidence.append(Evidence(type="engine_status", detail=note))

        score = noisy_or(strengths)
        severity = severity_from_score(score)
        # Confidence grows with independent kinds of evidence: behavior rules
        # and model consensus are different methods, so agreement between
        # them counts for more than several findings of one kind.
        kinds = {e.type.split(":")[0] for e in evidence} & {"behavior_rule", "model_consensus"}
        confidence = min(0.95, 0.55 + 0.2 * len(kinds) + 0.05 * min(len(analysis.behavior), 3))
        return DetectionResult(
            detector=self.name,
            category=self.category,
            severity=severity,
            score=round(score, 4),
            confidence=round(confidence, 2),
            evidence=evidence,
            recommended_action=action_for(severity),
            model_version=self._model_version(),
            mitre_attack=mitre_for(*mitre_keys),
        )

    @staticmethod
    def _model_version() -> str:
        return "network-suite-0.1.0 (synthetic-trained; see docs/model-card.md)"
