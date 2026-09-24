"""BehavioralAnomalyDetector — host behavior rules over endpoint telemetry,
compared against a learned fleet baseline.

The baseline (which parent/child process pairs, autostart targets,
listeners and file extensions are normal for this fleet) is a registered
artifact: models/endpoint/fleet_baseline/, SHA-256-pinned like every model.
Rules that need it report themselves unavailable when it's missing.

There is no endpoint ML model in this version. The brief's behavioral
Isolation Forest is listed as not implemented in docs/model-card.md. This
detector's findings come from rules plus the baseline, and it says so.
"""

from __future__ import annotations

import logging

from app.core.rules import mitre_for
from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, noisy_or, safe_result, severity_from_score
from app.detectors.endpoint import host_rules
from app.detectors.endpoint.activity import Baseline, summarize
from app.events.schema import SecurityEvent, SecurityEventType
from app.ml.loader import ModelIntegrityError, loader
from app.ml.registry import registry
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence
from app.services.transient_store import event_batches

logger = logging.getLogger("sentivra.endpoint")

_APPLICABLE = frozenset({
    SecurityEventType.ENDPOINT_BATCH, SecurityEventType.PROCESS_STARTED,
    SecurityEventType.PERSISTENCE_ITEM, SecurityEventType.LISTENING_PORT,
})


def load_baseline() -> tuple[Baseline | None, str]:
    entry = registry.get("endpoint", "fleet_baseline")
    if entry is None or not entry.trained:
        return None, "Not learned (run research/experiments/learn_endpoint_baseline.py)"
    try:
        return Baseline.from_dict(loader.load(entry)), f"Available (v{entry.metadata.version})"
    except (ModelIntegrityError, KeyError, ValueError) as exc:
        return None, f"Error: {exc}"


class BehavioralAnomalyDetector(BaseDetector):
    name = "BehavioralAnomalyDetector"
    version = "0.1.0"
    category = DetectorCategory.BEHAVIORAL_ANOMALY
    applicable_event_types = _APPLICABLE

    def __init__(self) -> None:
        self.baseline, self.baseline_status = load_baseline()
        if self.baseline is None:
            logger.warning("Endpoint fleet baseline: %s", self.baseline_status)

    async def is_available(self) -> DetectorAvailability:
        rules = host_rules.load_endpoint_rules()
        needs = [n for n, r in rules.items() if r.get("needs_baseline")]
        detail = f"{len(rules)} host rules; fleet baseline: {self.baseline_status}; no endpoint ML model in this version"
        if self.baseline is None:
            return DetectorAvailability(
                status=AvailabilityStatus.DEGRADED,
                detail=f"{detail}. Unavailable without a baseline: {', '.join(needs)}",
            )
        return DetectorAvailability(status=AvailabilityStatus.AVAILABLE, detail=detail)

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        batch_id = event.metadata.get("event_batch_id")
        entry = event_batches.get(batch_id) if batch_id else None
        events = entry["events"] if entry is not None else [event]

        findings, skipped = host_rules.evaluate(events, summarize(events), self.baseline)
        if entry is not None:
            entry.setdefault("analysis", {})["behavior"] = {
                "baseline": self.baseline_status,
                "rules_skipped_without_baseline": skipped,
                "findings": [
                    {"rule": f.rule, "category": f.category, "description": f.description, "host": f.host,
                     "subject": f.subject, "details": f.details, "event_count": len(f.events),
                     "mitre_attack": [m.model_dump() for m in mitre_for(f.mitre_key)],
                     "ground_truth_labels": sorted({e.metadata["demo_label"] for e in f.events
                                                   if e.metadata.get("demo_label")})}
                    for f in findings
                ],
            }
        if not findings:
            return safe_result(self.name, self.category, confidence=0.6, model_version=self._version())

        evidence = [
            Evidence(type=f"host_rule:{f.rule}",
                     detail=f"{f.description} [{f.host}: {f.subject}; "
                            + ", ".join(f"{k}={v}" for k, v in f.details.items()) + "]",
                     weight=f.weight)
            for f in sorted(findings, key=lambda f: f.weight, reverse=True)
        ]
        if skipped:
            evidence.append(Evidence(type="coverage_gap",
                                     detail=f"Not evaluated (no fleet baseline): {', '.join(skipped)}"))
        score = noisy_or(f.weight for f in findings)
        severity = severity_from_score(score)
        distinct_rules = {f.rule for f in findings}
        return DetectionResult(
            detector=self.name,
            category=self.category,
            severity=severity,
            score=round(score, 4),
            confidence=round(min(0.9, 0.6 + 0.08 * len(distinct_rules)), 2),
            evidence=evidence,
            recommended_action=action_for(severity),
            model_version=self._version(),
            mitre_attack=mitre_for(*(f.mitre_key for f in findings)),
        )

    def _version(self) -> str:
        return f"host-rules-0.1.0; baseline {self.baseline_status}"
