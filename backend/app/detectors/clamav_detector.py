"""ClamAVDetector — talks to a locally installed `clamd` daemon directly
over its native INSTREAM protocol (no Docker, no third-party HTTP wrapper —
see docs/repository-analysis.md §3 for why the cyberphor/clamav-api
Unix-socket pattern was adopted as a *pattern* rather than as a Docker
dependency).

If clamd isn't reachable (not installed, not running, not configured),
`is_available()` reports Not Configured — this is the expected state on a
machine without ClamAV installed, and is never papered over (brief §32,
§3 of the brief: "ClamAV: Available / Not Configured" must be truthful).
"""

from __future__ import annotations

import socket
import struct

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

_CHUNK_SIZE = 1024 * 1024  # 1 MB per INSTREAM chunk
_SOCKET_TIMEOUT_S = 5.0


class ClamdConnectionError(RuntimeError):
    pass


def _connect() -> socket.socket:
    settings = get_settings()
    if settings.clamd_socket:
        if not hasattr(socket, "AF_UNIX"):
            raise ClamdConnectionError("Unix sockets are not supported on this platform")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_SOCKET_TIMEOUT_S)
        sock.connect(settings.clamd_socket)
        return sock
    if settings.clamd_host:
        sock = socket.create_connection((settings.clamd_host, settings.clamd_port), timeout=_SOCKET_TIMEOUT_S)
        return sock
    raise ClamdConnectionError("Neither SENTIVRA_CLAMD_SOCKET nor SENTIVRA_CLAMD_HOST is configured")


def _ping() -> str | None:
    """Returns clamd's VERSION string on success, or None if unreachable."""
    try:
        with _connect() as sock:
            sock.sendall(b"zVERSION\0")
            response = sock.recv(4096)
            return response.decode("utf-8", errors="replace").strip("\0").strip()
    except (ClamdConnectionError, OSError):
        return None


def _instream_scan(data: bytes) -> str:
    """Sends `data` via clamd's INSTREAM protocol, returns clamd's raw
    result line (e.g. "stream: OK" or "stream: Eicar-Test-Signature FOUND")."""
    with _connect() as sock:
        sock.sendall(b"zINSTREAM\0")
        for offset in range(0, len(data), _CHUNK_SIZE):
            chunk = data[offset : offset + _CHUNK_SIZE]
            sock.sendall(struct.pack("!L", len(chunk)) + chunk)
        sock.sendall(struct.pack("!L", 0))  # zero-length chunk terminates the stream
        response = sock.recv(4096)
        return response.decode("utf-8", errors="replace").strip("\0").strip()


class ClamAVDetector(BaseDetector):
    name = "ClamAVDetector"
    version = "0.1.0"
    category = DetectorCategory.MALWARE
    applicable_event_types = _APPLICABLE

    async def is_available(self) -> DetectorAvailability:
        version = _ping()
        if version:
            return DetectorAvailability(
                status=AvailabilityStatus.AVAILABLE,
                detail="clamd reachable",
                engine_version=version,
            )
        return DetectorAvailability(
            status=AvailabilityStatus.NOT_CONFIGURED,
            detail=(
                "clamd is not reachable — set SENTIVRA_CLAMD_SOCKET or "
                "SENTIVRA_CLAMD_HOST/SENTIVRA_CLAMD_PORT if ClamAV is installed"
            ),
        )

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        sha256 = event.metadata.get("sha256")
        data = blob_store.get(sha256) if sha256 else None

        safe_result = DetectionResult(
            detector=self.name,
            category=self.category,
            severity=Severity.SAFE,
            score=0.0,
            confidence=0.0,
            evidence=[],
            recommended_action=RecommendedAction.ALLOW,
            model_version=None,
        )
        if data is None:
            return safe_result

        try:
            raw_result = _instream_scan(data)
        except (ClamdConnectionError, OSError):
            return safe_result  # Not Configured — is_available() is the source of truth for that state

        if raw_result.endswith("OK"):
            return DetectionResult(
                detector=self.name,
                category=self.category,
                severity=Severity.SAFE,
                score=0.0,
                confidence=0.95,
                evidence=[],
                recommended_action=RecommendedAction.ALLOW,
                model_version="clamav-signatures",
            )

        signature_name = raw_result.split(":", 1)[-1].replace("FOUND", "").strip()
        return DetectionResult(
            detector=self.name,
            category=self.category,
            severity=Severity.CRITICAL,
            score=0.98,
            confidence=0.95,
            evidence=[Evidence(type="clamav_signature", detail=f"ClamAV signature match: {signature_name}")],
            recommended_action=RecommendedAction.BLOCK,
            model_version="clamav-signatures",
        )
