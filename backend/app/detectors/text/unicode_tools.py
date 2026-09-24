"""Unicode tricks that hide or disguise text, and how to undo them.

Covers the techniques the prompt-injection and URL detectors care about:

  * Confusables: letters from other scripts that render like Latin ones
    (Cyrillic "а" for "a"), used to dodge keyword filters or impersonate
    a domain.
  * Invisible characters: zero-width spaces/joiners, soft hyphens, and
    bidi controls such as RIGHT-TO-LEFT OVERRIDE ("Trojan Source").
  * Tag-character smuggling: U+E0020–U+E007E mirror printable ASCII but
    render as nothing, so a whole instruction can be invisible to a human
    reviewer while an LLM tokenizer still sees it.
  * Variation-selector smuggling: arbitrary bytes encoded as a run of
    variation selectors attached to one visible character.

The confusable table is a hand-picked subset of Unicode TR39
confusables.txt (https://www.unicode.org/Public/security/latest/), limited
to letters that render as plain Latin in common fonts. It isn't the full
table. Fullwidth and mathematical-alphanumeric lookalikes aren't listed
because NFKC normalization already folds them to ASCII.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

# Keys are written as escapes on purpose: a Cyrillic small a and a Latin a
# look identical in an editor, and this table is only auditable if you can
# see which code point each key is.
CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u051b": "q", "\u051d": "w",
    "\u0432": "b",  # only confusable with small-caps B in some fonts; kept, low harm
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    # Greek
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03b9": "i",
    "\u03ba": "k", "\u03c5": "u", "\u0391": "A", "\u0392": "B", "\u0395": "E",
    "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y",
    "\u03a7": "X",
    # Armenian
    "\u0585": "o", "\u057d": "u", "\u0570": "h", "\u0578": "n",
    # Latin lookalikes outside basic ASCII
    "\u0131": "i",  # dotless i
    "\u0261": "g",  # script g
    "\u01c0": "l",  # dental click
}

ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u180e", "\u00ad"})
BIDI_OVERRIDES = frozenset({"\u202D", "\u202E"})  # LRO / RLO: reorder what the reader sees
BIDI_OTHER = frozenset({"\u202A", "\u202B", "\u202C", "\u2066", "\u2067", "\u2068", "\u2069", "\u200E", "\u200F"})

_TAG_START, _TAG_END = 0xE0000, 0xE007F
_BLACK_FLAG = "\U0001f3f4"  # subdivision flags (e.g. England) are legitimately built from tag chars


@dataclass
class HiddenTextReport:
    zero_width_in_words: int = 0
    bidi_overrides: int = 0
    bidi_other: int = 0
    tag_chars: int = 0
    decoded_tag_text: str = ""
    variation_selector_payload: str = ""
    mixed_script_words: list[str] = field(default_factory=list)
    confusable_count: int = 0

    @property
    def anything_hidden(self) -> bool:
        return bool(
            self.zero_width_in_words
            or self.bidi_overrides
            or self.decoded_tag_text
            or self.variation_selector_payload
        )


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    return name.split(" ", 1)[0]  # "LATIN", "CYRILLIC", "GREEK", ...


def decode_tag_characters(text: str) -> str:
    """Decode Unicode tag characters back to the ASCII they shadow, skipping
    legitimate emoji subdivision-flag sequences."""
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == _BLACK_FLAG:
            # Skip the tag run that belongs to a flag emoji, through CANCEL TAG.
            j = i + 1
            while j < len(text) and _TAG_START <= ord(text[j]) <= _TAG_END:
                j += 1
                if ord(text[j - 1]) == _TAG_END:
                    break
            i = j
            continue
        cp = ord(ch)
        if _TAG_START + 0x20 <= cp <= _TAG_START + 0x7E:
            out.append(chr(cp - _TAG_START))
        i += 1
    return "".join(out)


def decode_variation_selectors(text: str, *, min_run: int = 8) -> str:
    """Decode runs of variation selectors used to smuggle bytes.

    VS1–VS16 (U+FE00–U+FE0F) carry values 0–15 and VS17–VS256
    (U+E0100–U+E01EF) carry 16–255. A single selector after an emoji is
    normal; only runs of `min_run` or more are treated as a payload."""
    payloads: list[bytes] = []
    current = bytearray()
    for ch in text:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            current.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            current.append(cp - 0xE0100 + 16)
        else:
            if len(current) >= min_run:
                payloads.append(bytes(current))
            current = bytearray()
    if len(current) >= min_run:
        payloads.append(bytes(current))
    decoded = [p.decode("utf-8", errors="ignore") for p in payloads]
    return " ".join(d for d in decoded if d.strip())


def strip_invisible(text: str) -> str:
    return "".join(
        ch for ch in text
        if ch not in ZERO_WIDTH
        and ch not in BIDI_OVERRIDES
        and ch not in BIDI_OTHER
        and not (_TAG_START <= ord(ch) <= _TAG_END)
        and not (0xFE00 <= ord(ch) <= 0xFE0F)
        and not (0xE0100 <= ord(ch) <= 0xE01EF)
    )


def to_skeleton(text: str) -> str:
    """Map confusable letters to their Latin lookalike."""
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def inspect_hidden_text(text: str) -> HiddenTextReport:
    report = HiddenTextReport()
    for idx, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            # A ZWJ inside an emoji sequence or a ZWNJ in Persian/Indic text is
            # normal. One sitting between two Latin letters is splitting a word.
            prev = text[idx - 1] if idx > 0 else ""
            nxt = text[idx + 1] if idx + 1 < len(text) else ""
            if prev.isascii() and prev.isalpha() and nxt.isascii() and nxt.isalpha():
                report.zero_width_in_words += 1
        elif ch in BIDI_OVERRIDES:
            report.bidi_overrides += 1
        elif ch in BIDI_OTHER:
            report.bidi_other += 1
        elif _TAG_START <= ord(ch) <= _TAG_END:
            report.tag_chars += 1
        if ch in CONFUSABLES:
            report.confusable_count += 1

    report.decoded_tag_text = decode_tag_characters(text).strip()
    report.variation_selector_payload = decode_variation_selectors(text)

    for word in strip_invisible(text).split():
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN"}:
            report.mixed_script_words.append(word[:40])
            if len(report.mixed_script_words) >= 10:
                break
    return report
