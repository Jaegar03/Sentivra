"""Generic HMAC webhook-signature verification, used by the WhatsApp
integration (X-Hub-Signature-256 over the raw body) and reusable anywhere
else an HMAC-signed webhook shows up. Timing-safe comparison throughout —
never a plain `==` on a secret-derived value (docs/threat-model.md,
Boundary A / WhatsApp section).
"""

from __future__ import annotations

import hmac
from hashlib import sha256


def verify_hmac_sha256(*, secret: str, payload: bytes, signature_header: str | None, prefix: str = "sha256=") -> bool:
    if not signature_header or not signature_header.startswith(prefix):
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, sha256).hexdigest()
    provided = signature_header[len(prefix):]
    return hmac.compare_digest(expected, provided)
