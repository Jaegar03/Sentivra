"""Upload validation: size caps, archive-bomb / nested-archive limits
(brief §29). This module never trusts a client-declared filename or
content-type — those are recorded as metadata only, never used as a
filesystem path (docs/threat-model.md, path-traversal mitigation) and
never trusted as the file's true type (brief §7 — file detection itself
determines type via magic bytes, separately).
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from io import BytesIO

from app.core.config import get_settings


class UploadTooLarge(ValueError):
    pass


class ArchiveBombSuspected(ValueError):
    pass


@dataclass
class ArchiveInspectionResult:
    entry_count: int
    total_uncompressed_bytes: int
    max_depth_seen: int
    truncated: bool


def validate_upload_size(size_bytes: int) -> None:
    limit = get_settings().max_upload_bytes
    if size_bytes > limit:
        raise UploadTooLarge(f"Upload of {size_bytes} bytes exceeds the {limit}-byte limit")


def inspect_zip_bomb_safe(data: bytes, *, _depth: int = 0) -> ArchiveInspectionResult:
    """Walks a ZIP's central directory (never fully extracts) to total up
    declared uncompressed sizes and entry counts, bailing out before
    exceeding configured limits. Nested ZIPs are inspected recursively up
    to max_archive_depth, each still bounded by the same caps — this is
    what stops a small file from declaring an unbounded decompression
    ratio (the classic "zip bomb") from ever being fully inflated.
    """
    settings = get_settings()
    if _depth > settings.max_archive_depth:
        raise ArchiveBombSuspected(f"Archive nesting exceeds max depth {settings.max_archive_depth}")

    entry_count = 0
    total_uncompressed = 0
    max_depth_seen = _depth
    truncated = False

    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for info in zf.infolist():
                entry_count += 1
                total_uncompressed += info.file_size

                if entry_count > settings.max_archive_entries:
                    truncated = True
                    break
                if total_uncompressed > settings.max_archive_uncompressed_bytes:
                    raise ArchiveBombSuspected(
                        f"Declared uncompressed size {total_uncompressed} exceeds "
                        f"{settings.max_archive_uncompressed_bytes}-byte cap"
                    )

                if info.filename.lower().endswith(".zip") and not truncated:
                    try:
                        nested_bytes = zf.read(info, pwd=None)
                    except (RuntimeError, zipfile.BadZipFile):
                        continue  # encrypted or malformed nested entry — skip, don't crash
                    if len(nested_bytes) <= settings.max_upload_bytes:
                        nested = inspect_zip_bomb_safe(nested_bytes, _depth=_depth + 1)
                        max_depth_seen = max(max_depth_seen, nested.max_depth_seen)
                        total_uncompressed += nested.total_uncompressed_bytes
                        truncated = truncated or nested.truncated
    except zipfile.BadZipFile:
        # Not a real/parseable ZIP despite the name/extension — handled by
        # the caller's magic-byte check, not an error here.
        return ArchiveInspectionResult(0, 0, _depth, truncated=False)

    return ArchiveInspectionResult(
        entry_count=entry_count,
        total_uncompressed_bytes=total_uncompressed,
        max_depth_seen=max_depth_seen,
        truncated=truncated,
    )
