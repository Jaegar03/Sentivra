"""LogDetector — authentication behavior over log and endpoint batches, plus
pass-through of alerts raised by a Wazuh manager.

Sigma rules over the same events run separately in SigmaDetector; this
detector covers what single-event rules can't express: counts over time
(password guessing, spraying, a success right after a run of failures).

Wazuh alerts are another engine's verdict, not Sentivra's. They're passed
through as evidence, labeled with Wazuh's own rule ID and level, the same
way Suricata alerts will be (docs/architecture.md §4).
"""

from __future__ import annotations

from app.core.rules import UnknownTechnique, attack_mapping, mitre_for
from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, noisy_or, safe_result, severity_from_score
from app.detectors.logs import auth_rules
from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence, MitreAttackMapping
from app.services.transient_store import event_batches

_APPLICABLE = frozenset({
    SecurityEventType.AUTHENTICATION_EVENT, SecurityEventType.SYSTEM_LOG,
    SecurityEventType.LOG_BATCH, SecurityEventType.ENDPOINT_BATCH,
})


def _wazuh_findings(events: list[SecurityEvent], rule: dict) -> tuple[list[Evidence], list[float], list[MitreAttackMapping]]:
    evidence, strengths, mitre = [], [], []
    grouped: dict[str, list[SecurityEvent]] = {}
    for e in events:
        w = e.metadata.get("wazuh")
        if w and w["level"] >= rule["min_level"]:
            grouped.setdefault(w["rule_id"], []).append(e)
    for rule_id, evts in grouped.items():
        w = evts[0].metadata["wazuh"]
        strengths.append(min(0.9, w["level"] * rule["weight_per_level"]))
        evidence.append(Evidence(
            type="wazuh_alert",
            detail=f"Wazuh rule {rule_id} (level {w['level']}): {w['description']}. {len(evts)} alert(s)",
            weight=strengths[-1],
        ))
        for tid in w["mitre_ids"]:
            try:
                mitre.append(attack_mapping(tid, via=f"Wazuh rule {rule_id}"))
            except UnknownTechnique:
                continue
    return evidence, strengths, mitre


class LogDetector(BaseDetector):
    name = "LogDetector"
    version = "0.1.0"
    category = DetectorCategory.LOG_ANOMALY
    applicable_event_types = _APPLICABLE

    async def is_available(self) -> DetectorAvailability:
        rules = auth_rules.load_auth_rules()
        return DetectorAvailability(status=AvailabilityStatus.AVAILABLE,
                                    detail=f"{len(rules)} authentication/log rules loaded")

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        batch_id = event.metadata.get("event_batch_id")
        entry = event_batches.get(batch_id) if batch_id else None
        events = entry["events"] if entry is not None else [event]

        findings = auth_rules.evaluate(events)
        rules = auth_rules.load_auth_rules()
        w_evidence, w_strengths, w_mitre = _wazuh_findings(events, rules.get("wazuh_alert", {"min_level": 99}))

        if entry is not None:
            entry.setdefault("analysis", {})["auth"] = [
                {"rule": f.rule, "description": f.description, "subject": f.subject, "details": f.details,
                 "event_count": f.event_count, "mitre_attack": [m.model_dump() for m in mitre_for(f.mitre_key)]}
                for f in findings
            ]
        if not findings and not w_strengths:
            return safe_result(self.name, self.category, confidence=0.7)

        evidence = [
            Evidence(type=f"auth_rule:{f.rule}",
                     detail=f"{f.description} [{f.subject}; " + ", ".join(f"{k}={v}" for k, v in f.details.items()) + "]",
                     weight=f.weight)
            for f in findings
        ] + w_evidence
        mitre: dict[str, MitreAttackMapping] = {}
        for m in [*mitre_for(*(f.mitre_key for f in findings)), *w_mitre]:
            mitre.setdefault(m.technique_id, m)

        score = noisy_or([f.weight for f in findings] + w_strengths)
        severity = severity_from_score(score)
        return DetectionResult(
            detector=self.name,
            category=self.category,
            severity=severity,
            score=round(score, 4),
            confidence=0.85 if findings else 0.7,  # own rules vs another engine's verdict
            evidence=evidence,
            recommended_action=action_for(severity),
            model_version="log-rules-0.1.0",
            mitre_attack=list(mitre.values()),
        )
