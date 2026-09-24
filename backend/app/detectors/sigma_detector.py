"""SigmaDetector — runs the Sigma rules in detection-rules/sigma/ against
endpoint and log events (brief §11).

Works on a single event (POST /events) or on a batch (endpoint telemetry or
log uploads), where matches are grouped per rule so one noisy rule produces
one finding with a count, not a thousand.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from app.core.config import get_settings
from app.core.rules import UnknownTechnique, attack_mapping
from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, noisy_or, safe_result, severity_from_score
from app.detectors.sigma.engine import RuleLoadReport, SigmaRule, load_rules
from app.detectors.sigma.fields import applies, to_fields
from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence, MitreAttackMapping
from app.services.transient_store import event_batches

logger = logging.getLogger("sentivra.sigma")

_APPLICABLE = frozenset({
    SecurityEventType.PROCESS_STARTED, SecurityEventType.PROCESS_NETWORK_CONNECTION,
    SecurityEventType.FILE_CREATED, SecurityEventType.FILE_MODIFIED, SecurityEventType.PERSISTENCE_ITEM,
    SecurityEventType.SYSTEM_LOG, SecurityEventType.AUTHENTICATION_EVENT,
    SecurityEventType.ENDPOINT_BATCH, SecurityEventType.LOG_BATCH,
})
# Sigma's `level` is the rule author's own judgement of severity.
_LEVEL_SCORE = {"informational": 0.15, "low": 0.3, "medium": 0.55, "high": 0.75, "critical": 0.92}
# Mature rules have been exercised against more real data than experimental ones.
_STATUS_CONFIDENCE = {"stable": 0.85, "test": 0.75, "experimental": 0.65}
_EVIDENCE_FIELDS = ("Image", "ParentImage", "CommandLine", "TargetFilename", "TargetPath", "EventID",
                    "TargetUserName", "IpAddress", "DestinationIp")


def rule_mitre(rule: SigmaRule) -> list[MitreAttackMapping]:
    mappings: dict[str, MitreAttackMapping] = {}
    for tag in rule.tags:
        if not tag.startswith("attack.t"):
            continue  # tactic tags (attack.execution) come from ATT&CK itself
        try:
            m = attack_mapping(tag.removeprefix("attack."), via=f"Sigma rule {rule.id}")
        except UnknownTechnique:
            logger.warning("Sigma rule %s tags unknown technique %s; dropped", rule.id, tag)
            continue
        mappings.setdefault(m.technique_id, m)
    return list(mappings.values())


class SigmaDetector(BaseDetector):
    name = "SigmaDetector"
    version = "0.1.0"
    category = DetectorCategory.SIGMA_RULE
    applicable_event_types = _APPLICABLE

    def __init__(self) -> None:
        self.report: RuleLoadReport = load_rules(get_settings().rules_dir / "sigma")
        for item in self.report.unsupported:
            logger.info("Sigma rule not loaded (%s): %s", item["path"], item["reason"])

    async def is_available(self) -> DetectorAvailability:
        loaded, skipped = len(self.report.loaded), len(self.report.unsupported)
        if not loaded:
            return DetectorAvailability(status=AvailabilityStatus.NOT_CONFIGURED,
                                        detail=f"No Sigma rules loaded ({skipped} unsupported)")
        return DetectorAvailability(status=AvailabilityStatus.AVAILABLE,
                                    detail=f"{loaded} Sigma rules loaded, {skipped} unsupported")

    def match_events(self, events: list[SecurityEvent]) -> dict[str, list[SecurityEvent]]:
        """rule id -> the events it matched."""
        hits: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in events:
            candidates = [r for r in self.report.loaded if applies(r.logsource, event)]
            if not candidates:
                continue
            fields = to_fields(event)
            for rule in candidates:
                try:
                    if rule.matcher(fields):
                        hits[rule.id].append(event)
                except TimeoutError:
                    logger.warning("Sigma rule %s timed out on event %s", rule.id, event.event_id)
        return hits

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        batch_id = event.metadata.get("event_batch_id")
        entry = event_batches.get(batch_id) if batch_id else None
        events = entry["events"] if entry is not None else [event]
        hits = self.match_events(events)
        rules = {r.id: r for r in self.report.loaded}
        if entry is not None:
            entry.setdefault("analysis", {})["sigma"] = [
                {"rule_id": rid, "title": rules[rid].title, "level": rules[rid].level, "matches": len(evts),
                 "hosts": sorted({e.metadata.get("host", "?") for e in evts}),
                 "mitre_attack": [m.model_dump() for m in rule_mitre(rules[rid])],
                 "examples": [to_fields(e) for e in evts[:3]]}
                for rid, evts in hits.items()
            ]
        if not hits:
            return safe_result(self.name, self.category, confidence=0.7, model_version=self._version())

        evidence, strengths, confidences, mitre = [], [], [], {}
        for rid, evts in sorted(hits.items(), key=lambda kv: _LEVEL_SCORE.get(rules[kv[0]].level, 0.5), reverse=True):
            rule = rules[rid]
            strengths.append(_LEVEL_SCORE.get(rule.level, 0.5))
            confidences.append(_STATUS_CONFIDENCE.get(rule.status, 0.65))
            example = to_fields(evts[0])
            shown = ", ".join(f"{k}={example[k]}" for k in _EVIDENCE_FIELDS if k in example)
            hosts = sorted({e.metadata.get("host", "?") for e in evts})
            evidence.append(Evidence(
                type=f"sigma:{rule.level}",
                detail=(f"Sigma rule '{rule.title}' ({rule.id}, status {rule.status}) matched {len(evts)} "
                        f"event(s) on {', '.join(hosts[:3])}{'…' if len(hosts) > 3 else ''}. Example: {shown}"),
                excerpt=(f"False positives noted by the rule: {'; '.join(rule.falsepositives)}"
                         if rule.falsepositives else None),
                weight=_LEVEL_SCORE.get(rule.level, 0.5),
            ))
            for m in rule_mitre(rule):
                mitre.setdefault(m.technique_id, m)

        score = noisy_or(strengths)
        severity = severity_from_score(score)
        confidence = min(0.95, max(confidences) + 0.05 * (len(hits) - 1))
        return DetectionResult(
            detector=self.name,
            category=self.category,
            severity=severity,
            score=round(score, 4),
            confidence=round(confidence, 2),
            evidence=evidence,
            recommended_action=action_for(severity),
            model_version=self._version(),
            mitre_attack=list(mitre.values()),
        )

    def _version(self) -> str:
        return f"sigma-engine-0.1.0 ({len(self.report.loaded)} rules)"
