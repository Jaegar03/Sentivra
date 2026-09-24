"""SHA-256 hashing and Shannon entropy — both cheap, deterministic signals
computed on every file before anything heavier runs (brief §7)."""

from __future__ import annotations

import hashlib
import math
from collections import Counter


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Bytes per byte, in [0, 8]. High entropy (>~7.5) across a whole file
    is consistent with packing/encryption/compression — a signal, not
    proof, of obfuscation. Empty input is defined as zero entropy."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
