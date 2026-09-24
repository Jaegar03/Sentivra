"""Normalization for SQL injection analysis.

Attackers rarely send `' or 1=1--` verbatim to a filtering application.
They URL-encode it (sometimes twice), use fullwidth quotes that the
database's collation folds back to ASCII, split keywords with comments, or
swap spaces for tabs, newlines or `+`. This module undoes those so the
signature, lexical and ML layers all see the same canonical text, and it
records how much undoing was needed, because heavy encoding is itself a
signal.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

_MAX_DECODE_ROUNDS = 4
_BLOCK_COMMENT_RE = re.compile(r"/\*!?\d{0,5}|\*/|/\*.*?\*/", re.DOTALL)
_WHITESPACE_RE = re.compile(r"[\s\x0b\x0c\xa0]+")


@dataclass
class SQLiViews:
    raw: str                    # decoded + lowercased, comments intact
    normalized: str             # raw with block comments removed, whitespace collapsed
    plus_as_space: str          # normalized, but '+' treated as a space (query-string context)
    url_decode_rounds: int      # how many URL-decoding passes changed the input
    html_entities_decoded: bool
    unicode_folded: bool        # NFKC changed something (e.g. fullwidth quote U+FF07)
    notes: list[str] = field(default_factory=list)

    def all(self) -> dict[str, str]:
        return {"raw": self.raw, "normalized": self.normalized, "plus_as_space": self.plus_as_space}


def _decode(text: str, decoder) -> tuple[str, int]:
    rounds = 0
    current = text
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = decoder(current)
        if decoded == current:
            break
        current = decoded
        rounds += 1
    return current, rounds


def _collapse(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def build_sqli_views(text: str) -> SQLiViews:
    decoded, rounds = _decode(text, unquote)
    unescaped = html.unescape(decoded)
    folded = unicodedata.normalize("NFKC", unescaped)

    raw = _collapse(folded.lower())
    normalized = _collapse(_BLOCK_COMMENT_RE.sub(" ", raw))
    plus_decoded, _ = _decode(text, unquote_plus)
    plus_view = _collapse(
        _BLOCK_COMMENT_RE.sub(" ", unicodedata.normalize("NFKC", html.unescape(plus_decoded)).lower())
    )

    views = SQLiViews(
        raw=raw,
        normalized=normalized,
        plus_as_space=plus_view,
        url_decode_rounds=rounds,
        html_entities_decoded=unescaped != decoded,
        unicode_folded=folded != unescaped,
    )
    if rounds >= 2:
        views.notes.append(f"input was URL-encoded {rounds} times")
    if views.unicode_folded:
        views.notes.append("input contained Unicode compatibility characters (e.g. fullwidth quotes)")
    if views.html_entities_decoded:
        views.notes.append("input contained HTML entities")
    return views


def text_for_model(text: str) -> str:
    """The single canonical form the ML classifier is trained and served on."""
    return build_sqli_views(text).normalized
