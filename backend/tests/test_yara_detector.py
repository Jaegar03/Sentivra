"""YaraDetector against the real demo rule pack (detection-rules/yara/) —
this exercises actual yara-python compilation and matching, not a mock."""

from __future__ import annotations

import pytest

from app.detectors.base import AvailabilityStatus
from app.detectors.yara_detector import YaraDetector
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from app.schemas.detection import Severity
from app.services.file_blob_store import blob_store

EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("ascii")


@pytest.fixture()
def yara_detector():
    return YaraDetector()


async def _event_for(data: bytes) -> SecurityEvent:
    import hashlib

    sha = hashlib.sha256(data).hexdigest()
    blob_store.put(sha, data)
    return SecurityEvent(
        event_type=SecurityEventType.FILE_ANALYSIS,
        source="test",
        source_type=SourceType.DEMO_DATA,
        metadata={"sha256": sha},
    )


@pytest.mark.asyncio
async def test_yara_is_available_with_bundled_rules(yara_detector: YaraDetector):
    availability = await yara_detector.is_available()
    assert availability.status == AvailabilityStatus.AVAILABLE


@pytest.mark.asyncio
async def test_yara_detects_eicar_string(yara_detector: YaraDetector):
    event = await _event_for(EICAR)
    result = await yara_detector.analyze(event)
    assert result.severity != Severity.SAFE
    assert any("EICAR" in e.detail or "EICAR" in (e.excerpt or "") for e in result.evidence)
    blob_store.discard(event.metadata["sha256"])


@pytest.mark.asyncio
async def test_yara_reports_safe_for_benign_content(yara_detector: YaraDetector):
    event = await _event_for(b"just a normal harmless text file with nothing suspicious in it")
    result = await yara_detector.analyze(event)
    assert result.severity == Severity.SAFE
    blob_store.discard(event.metadata["sha256"])


@pytest.mark.asyncio
async def test_yara_detects_obfuscated_powershell(yara_detector: YaraDetector):
    payload = b'powershell.exe -WindowStyle Hidden -EncodedCommand JABzAGgAZQBsAGwA'
    event = await _event_for(payload)
    result = await yara_detector.analyze(event)
    assert result.severity != Severity.SAFE
    blob_store.discard(event.metadata["sha256"])
