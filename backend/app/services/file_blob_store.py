"""FileBlobStore — a transient, in-memory, request-scoped holder for raw
file bytes.

Why this exists: brief §30 requires Sentivra to persist hash + metadata +
detection result for files, never the raw bytes, by default. But
BaseDetector.analyze() only receives a SecurityEvent, and SecurityEvent
deliberately carries no raw bytes (app.events.schema.AttachmentRef is a
reference, not the content). This store is the bridge: the API layer puts
the uploaded bytes in here keyed by SHA-256 for the lifetime of one
request, detectors that need the bytes (YaraDetector, ClamAVDetector,
MalwareDetector) look them up by the sha256 carried in
`event.metadata["sha256"]`, and the API layer discards the entry when the
request completes — nothing here ever reaches the database.
"""

from __future__ import annotations

import threading


class FileBlobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blobs: dict[str, bytes] = {}

    def put(self, sha256: str, data: bytes) -> None:
        with self._lock:
            self._blobs[sha256] = data

    def get(self, sha256: str) -> bytes | None:
        with self._lock:
            return self._blobs.get(sha256)

    def discard(self, sha256: str) -> None:
        with self._lock:
            self._blobs.pop(sha256, None)


# Process-wide singleton — acceptable for the single-process demo scope
# (docs/architecture.md §2); a multi-worker deployment would need this
# scoped per-worker or replaced with a short-TTL cache, not shared state.
blob_store = FileBlobStore()
