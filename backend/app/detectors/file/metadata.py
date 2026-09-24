"""FileMetadata — the MIME / hash / magic-bytes triage step of the file
pipeline (brief §7 diagram). This is the layer that produces the first,
cheapest signal: does the extension agree with the actual bytes?
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass, field

from app.detectors.file import magic_bytes
from app.detectors.file.hashing import sha256_hex, shannon_entropy


@dataclass
class FileMetadata:
    filename: str
    declared_extension: str
    declared_mime: str | None
    guessed_mime_from_extension: str | None
    size_bytes: int
    sha256: str
    entropy: float
    matched_magic_types: list[str] = field(default_factory=list)
    extension_mismatch: bool = False
    is_polyglot: bool = False


def analyze_file(filename: str, data: bytes, declared_mime: str | None = None) -> FileMetadata:
    declared_extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    guessed_mime, _ = mimetypes.guess_type(filename)
    matched = magic_bytes.sniff(data)

    return FileMetadata(
        filename=filename,
        declared_extension=declared_extension,
        declared_mime=declared_mime,
        guessed_mime_from_extension=guessed_mime,
        size_bytes=len(data),
        sha256=sha256_hex(data),
        entropy=shannon_entropy(data),
        matched_magic_types=matched,
        extension_mismatch=magic_bytes.extension_mismatch(declared_extension, matched),
        # More than one *structurally distinct* signature matching (e.g. a
        # ZIP that is also valid as something else at a non-zero offset) is
        # the classic polyglot pattern — treated as elevated-risk evidence,
        # not proof of malice on its own.
        is_polyglot=len({t for t in matched if t != "javascript_heuristic"}) > 1,
    )
