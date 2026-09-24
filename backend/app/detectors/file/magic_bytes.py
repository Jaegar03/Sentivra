"""Magic-byte file-type sniffing — never trust the extension (brief §7).

Deliberately dependency-free (no libmagic/python-magic binding) so file-type
identification works identically on Windows dev machines and Linux
deployments without a native library being present or absent changing
results. The signature table below covers the file families the brief
calls out explicitly (EXE/DLL, ELF, PDF, Office/ZIP-based formats, GIF,
SVG, HTML, JavaScript) plus enough general-purpose formats to make
extension-vs-content mismatch detection meaningful.

This is intentionally a *curated* table, not a claim of exhaustive format
coverage — see the "Unknown" fallback and docs/threat-model.md's malware
detector limitations section.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileTypeSignature:
    type_id: str
    description: str
    typical_extensions: tuple[str, ...]
    magic: bytes
    offset: int = 0


_SIGNATURES: tuple[FileTypeSignature, ...] = (
    FileTypeSignature("pe", "Windows PE executable/DLL", (".exe", ".dll", ".sys"), b"MZ"),
    FileTypeSignature("elf", "Linux ELF binary", (".elf", "", ".so", ".bin"), b"\x7fELF"),
    FileTypeSignature("macho32", "Mach-O binary (32-bit)", (".dylib", ""), b"\xfe\xed\xfa\xce"),
    FileTypeSignature("macho64", "Mach-O binary (64-bit)", (".dylib", ""), b"\xfe\xed\xfa\xcf"),
    FileTypeSignature("pdf", "PDF document", (".pdf",), b"%PDF-"),
    FileTypeSignature("zip_or_office", "ZIP archive / Office Open XML (docx/xlsx/pptx/jar/apk)",
                       (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"), b"PK\x03\x04"),
    FileTypeSignature("zip_empty", "Empty ZIP archive", (".zip",), b"PK\x05\x06"),
    FileTypeSignature("ole_cfb", "Legacy Office document (doc/xls/ppt) / MSI",
                       (".doc", ".xls", ".ppt", ".msi"), b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    FileTypeSignature("gzip", "GZIP archive", (".gz", ".tgz"), b"\x1f\x8b"),
    FileTypeSignature("rar", "RAR archive", (".rar",), b"Rar!\x1a\x07"),
    FileTypeSignature("sevenzip", "7-Zip archive", (".7z",), b"7z\xbc\xaf\x27\x1c"),
    FileTypeSignature("gif87", "GIF image", (".gif",), b"GIF87a"),
    FileTypeSignature("gif89", "GIF image", (".gif",), b"GIF89a"),
    FileTypeSignature("png", "PNG image", (".png",), b"\x89PNG\r\n\x1a\n"),
    FileTypeSignature("jpeg", "JPEG image", (".jpg", ".jpeg"), b"\xff\xd8\xff"),
    FileTypeSignature("bmp", "BMP image", (".bmp",), b"BM"),
    FileTypeSignature("rtf", "RTF document", (".rtf",), b"{\\rtf"),
)

# These formats are text-based and can't be identified by a fixed byte
# prefix alone (leading whitespace/BOM/comments are legal) — sniffed via a
# bounded, case-insensitive scan of the first few KB instead.
_TEXT_MARKERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("svg", "SVG image (XML, may embed script)", (".svg",)),
    ("html", "HTML document", (".html", ".htm")),
)


def _looks_like_svg(head: str) -> bool:
    lowered = head.lower()
    return "<svg" in lowered and ("<?xml" in lowered or "<svg" in lowered[:200])


def _looks_like_html(head: str) -> bool:
    lowered = head.lstrip().lower()
    return lowered.startswith(("<!doctype html", "<html")) or "<html" in lowered[:500]


def _looks_like_script(head: str) -> bool:
    stripped = head.strip()
    js_markers = ("function(", "function (", "=>", "require(", "eval(", "document.", "window.")
    return any(m in stripped[:2000] for m in js_markers)


def sniff(data: bytes) -> list[str]:
    """Returns every matching type_id (a polyglot file can legitimately
    match more than one signature — that fact is itself evidence, see
    FileDetector's polyglot handling)."""
    matches: list[str] = []
    for sig in _SIGNATURES:
        end = sig.offset + len(sig.magic)
        if len(data) >= end and data[sig.offset:end] == sig.magic:
            matches.append(sig.type_id)

    head_text = data[:4096].decode("utf-8", errors="ignore")
    if _looks_like_svg(head_text):
        matches.append("svg")
    if _looks_like_html(head_text):
        matches.append("html")
    if _looks_like_script(head_text) and "html" not in matches:
        matches.append("javascript_heuristic")

    return matches


def describe(type_id: str) -> str:
    for sig in _SIGNATURES:
        if sig.type_id == type_id:
            return sig.description
    return {
        "svg": "SVG image (XML, may embed script)",
        "html": "HTML document",
        "javascript_heuristic": "Likely JavaScript (heuristic, not a fixed signature)",
    }.get(type_id, "Unknown")


def extension_mismatch(declared_extension: str, matched_type_ids: list[str]) -> bool:
    """True when the declared extension doesn't correspond to *any* matched
    magic-byte type — the core "never trust the extension" check (brief §7)."""
    if not matched_type_ids:
        return False  # unknown type: can't assert a mismatch, only unknown-ness
    ext = declared_extension.lower()
    for sig in _SIGNATURES:
        if sig.type_id in matched_type_ids and ext in sig.typical_extensions:
            return False
    if ext == ".svg" and "svg" in matched_type_ids:
        return False
    return not (ext in (".html", ".htm") and "html" in matched_type_ids)
