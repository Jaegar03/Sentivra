"""Derived "views" of a piece of text that undo common obfuscation.

Pattern rules run against every view. A rule that only matches after
decoding (for example, the base64 view contains "ignore previous
instructions" but the plain text doesn't) is stronger evidence than a
plain match, because it shows someone went out of their way to hide the
text. Each view records how it was derived so that shows up in evidence.

All decoders are bounded: segment counts, segment lengths and total output
are capped, so an input can't make view generation expensive.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from app.detectors.text.unicode_tools import (
    decode_tag_characters,
    decode_variation_selectors,
    strip_invisible,
    to_skeleton,
)

_MAX_SEGMENTS = 10
_MAX_SEGMENT_CHARS = 4096

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_SPACED_LETTERS_RE = re.compile(r"\b(?:[A-Za-z][ .\-_*]){3,}[A-Za-z]\b")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})


@dataclass(frozen=True)
class TextView:
    name: str        # e.g. "normalized", "base64_decoded"
    text: str
    obfuscated: bool  # True if producing this view required undoing an obfuscation


def normalize(text: str) -> str:
    """NFKC (folds fullwidth and math-alphanumeric letters to ASCII), drop
    invisible characters, collapse whitespace, lowercase."""
    folded = unicodedata.normalize("NFKC", text)
    folded = strip_invisible(folded)
    return " ".join(folded.split()).lower()


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\t" for ch in s) / len(s)


def _decode_base64_segments(text: str) -> list[str]:
    out: list[str] = []
    for match in _BASE64_RE.finditer(text):
        segment = match.group(0)[:_MAX_SEGMENT_CHARS]
        padded = segment + "=" * (-len(segment) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Real encoded text decodes to mostly printable characters; random
        # alphanumeric runs (IDs, hashes) almost never do.
        if len(decoded) >= 6 and _printable_ratio(decoded) > 0.9:
            out.append(decoded)
        if len(out) >= _MAX_SEGMENTS:
            break
    return out


def _decode_hex_segments(text: str) -> list[str]:
    out: list[str] = []
    for match in _HEX_RE.finditer(text):
        raw = match.group(0)[:_MAX_SEGMENT_CHARS].replace("\\x", "")
        try:
            decoded = bytes.fromhex(raw).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(decoded) >= 4 and _printable_ratio(decoded) > 0.9:
            out.append(decoded)
        if len(out) >= _MAX_SEGMENTS:
            break
    return out


def _collapse_spaced_letters(text: str) -> str:
    return _SPACED_LETTERS_RE.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), text)


def _url_decode(text: str, rounds: int = 3) -> str:
    current = text
    for _ in range(rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def build_views(text: str) -> list[TextView]:
    """All distinct views of `text`, plain normalized view first."""
    base = normalize(text)
    candidates: list[TextView] = [TextView("normalized", base, obfuscated=False)]

    def add(name: str, value: str, obfuscated: bool = True) -> None:
        value = normalize(value)
        if value and all(value != v.text for v in candidates):
            candidates.append(TextView(name, value, obfuscated))

    add("confusable_skeleton", to_skeleton(unicodedata.normalize("NFKC", text)))
    add("leetspeak", base.translate(_LEET))
    add("spacing_collapsed", _collapse_spaced_letters(base))
    add("url_decoded", _url_decode(text))
    add("html_unescaped", html.unescape(text))
    add("rot13", codecs.decode(base, "rot13"))
    add("reversed", base[::-1])

    hidden_tags = decode_tag_characters(text)
    if hidden_tags.strip():
        add("unicode_tag_decoded", hidden_tags)
    hidden_vs = decode_variation_selectors(text)
    if hidden_vs:
        add("variation_selector_decoded", hidden_vs)

    for i, segment in enumerate(_decode_base64_segments(text)):
        add(f"base64_decoded[{i}]", segment)
    for i, segment in enumerate(_decode_hex_segments(text)):
        add(f"hex_decoded[{i}]", segment)

    return candidates
