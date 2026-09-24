"""YaraDetector — wraps yara-python against the rule pack in
detection-rules/yara/ (brief §7, §11). Rules are compiled once and cached;
if yara-python isn't installed or no rules are present, is_available()
reports Not Configured honestly rather than pretending to have scanned.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings
from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import (
    DetectionResult,
    DetectorCategory,
    Evidence,
    RecommendedAction,
    Severity,
)
from app.services.file_blob_store import blob_store

_APPLICABLE = frozenset(
    {SecurityEventType.FILE_ANALYSIS, SecurityEventType.FILE_CREATED, SecurityEventType.FILE_DOWNLOADED}
)


class YaraDetector(BaseDetector):
    name = "YaraDetector"
    version = "0.1.0"
    category = DetectorCategory.MALWARE
    applicable_event_types = _APPLICABLE

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or get_settings().yara_rules_dir
        self._compiled = None
        self._compile_error: str | None = None
        self._try_compile()

    def _try_compile(self) -> None:
        try:
            import yara  # noqa: F401 — optional dependency
        except ImportError:
            self._compile_error = "yara-python is not installed"
            return

        import yara as yara_mod

        rule_files = sorted(self._rules_dir.glob("*.yar")) + sorted(self._rules_dir.glob("*.yara"))
        if not rule_files:
            self._compile_error = f"No .yar/.yara files found under {self._rules_dir}"
            return

        try:
            filepaths = {f"rule_{i}": str(p) for i, p in enumerate(rule_files)}
            self._compiled = yara_mod.compile(filepaths=filepaths)
        except yara_mod.SyntaxError as exc:
            self._compile_error = f"YARA rule compile error: {exc}"

    async def is_available(self) -> DetectorAvailability:
        if self._compiled is not None:
            import yara

            return DetectorAvailability(
                status=AvailabilityStatus.AVAILABLE,
                detail=f"Compiled rules from {self._rules_dir}",
                engine_version=getattr(yara, "__version__", "unknown"),
            )
        return DetectorAvailability(
            status=AvailabilityStatus.NOT_CONFIGURED,
            detail=self._compile_error or "YARA rules not compiled",
        )

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        if self._compiled is None:
            return DetectionResult(
                detector=self.name,
                category=self.category,
                severity=Severity.SAFE,
                score=0.0,
                confidence=0.0,
                evidence=[],
                recommended_action=RecommendedAction.ALLOW,
                model_version=None,
            )

        sha256 = event.metadata.get("sha256")
        data = blob_store.get(sha256) if sha256 else None
        if data is None:
            return DetectionResult(
                detector=self.name,
                category=self.category,
                severity=Severity.SAFE,
                score=0.0,
                confidence=0.0,
                evidence=[],
                recommended_action=RecommendedAction.ALLOW,
                model_version=None,
            )

        matches = self._compiled.match(data=data)
        if not matches:
            return DetectionResult(
                detector=self.name,
                category=self.category,
                severity=Severity.SAFE,
                score=0.0,
                confidence=0.9,
                evidence=[],
                recommended_action=RecommendedAction.ALLOW,
                model_version="yara-rules-demo-v1",
            )

        evidence = [
            Evidence(
                type="yara_match",
                detail=m.meta.get("description", m.rule),
                excerpt=m.rule,
            )
            for m in matches
        ]
        max_declared_severity = max(
            (_severity_from_meta(m.meta.get("severity")) for m in matches),
            default=Severity.MEDIUM,
            key=lambda s: s.rank,
        )
        return DetectionResult(
            detector=self.name,
            category=self.category,
            severity=max_declared_severity,
            score=min(1.0, 0.5 + 0.15 * len(matches)),
            confidence=0.9,
            evidence=evidence,
            recommended_action=(
                RecommendedAction.BLOCK
                if max_declared_severity.rank >= Severity.HIGH.rank
                else RecommendedAction.REVIEW
            ),
            model_version="yara-rules-demo-v1",
        )


def _severity_from_meta(value: str | None) -> Severity:
    try:
        return Severity(value) if value else Severity.MEDIUM
    except ValueError:
        return Severity.MEDIUM
