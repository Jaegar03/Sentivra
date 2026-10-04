"""Provider webhook authentication.

The three Phase 7 connectors are the only routes on this API that don't
authenticate with a SENTIVRA bearer token — their callers are Google,
Telegram and Meta, which can't hold one. Each is authenticated by something
only the real provider can produce (docs/threat-model.md, Boundary A):

  WhatsApp  HMAC-SHA256 over the raw request body, compared against the
            `X-Hub-Signature-256` header, using the Meta app secret.
  Telegram  the `X-Telegram-Bot-Api-Secret-Token` header, set to the
            `secret_token` chosen when the webhook was registered.
  Gmail     an RS256 JWT signed by Google, verified against Google's
            published certificates, plus the shared verification token
            when one is configured.

Timing-safe comparison throughout — never a plain `==` on a secret-derived
value.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from collections.abc import Awaitable, Callable
from hashlib import sha256
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger("sentivra.webhooks")


class WebhookAuthError(Exception):
    """The request could not be authenticated as coming from the provider.

    `transient` marks the cases where the answer isn't known (Google's
    certificate endpoint unreachable) — those must fail closed *and* invite a
    retry (HTTP 503), unlike a definitively forged request (HTTP 403).
    """

    def __init__(self, reason: str, *, transient: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.transient = transient


def hmac_sha256_hex(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, sha256).hexdigest()


def verify_hmac_sha256(*, secret: str, payload: bytes, signature_header: str | None, prefix: str = "sha256=") -> bool:
    """WhatsApp's `X-Hub-Signature-256`: sha256=<hex> over the raw body."""
    if not secret or not signature_header or not signature_header.startswith(prefix):
        return False
    return _equal(hmac_sha256_hex(secret, payload), signature_header[len(prefix):])


def verify_shared_secret(provided: str | None, expected: str) -> bool:
    """Constant-time exact match against a pre-shared webhook secret.

    An empty configured secret never matches: "not configured" must not
    silently authenticate everything.
    """
    if not expected or provided is None:
        return False
    return _equal(expected, provided)


def _equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---- Gmail Pub/Sub push: Google-signed JWT ---------------------------------
#
# Google signs every Pub/Sub push request with an RS256 JWT (issuer
# accounts.google.com) and publishes the corresponding public keys as a JWKS.
# Only Google can produce a token that verifies against those keys, so a
# forged "new mail" notification is rejected before anything is normalized.

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"  # a constant, never built from input
GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
JWKS_TTL_S = 3600.0
# A request with an unknown `kid` may mean Google rotated its keys, so allow
# one refresh — rate-limited, or an attacker could turn garbage tokens into
# an outbound request per call.
_FORCE_REFRESH_MIN_INTERVAL_S = 60.0
CLOCK_LEEWAY_S = 60.0

_cache: dict[str, Any] = {"keys": None, "expires": 0.0, "fetched_at": 0.0}

# Production uses `google_jwks`; tests inject their own keys through this hook.
JwksProvider = Callable[[], Awaitable[dict]]


def reset_jwks_cache() -> None:
    _cache.update(keys=None, expires=0.0, fetched_at=0.0)


async def google_jwks() -> dict:
    """Google's published JWT signing keys, cached for JWKS_TTL_S."""
    now = time.monotonic()
    if _cache["keys"] is not None and now < _cache["expires"]:
        return _cache["keys"]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(GOOGLE_JWKS_URL, headers={"Accept": "application/json"})
            resp.raise_for_status()
            keys = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise WebhookAuthError(f"could not fetch Google's signing certificates: {exc}", transient=True) from exc
    if not isinstance(keys, dict) or not keys.get("keys"):
        raise WebhookAuthError("Google's signing certificates were empty", transient=True)
    _cache.update(keys=keys, expires=now + JWKS_TTL_S, fetched_at=now)
    return keys


def _jwk_for(kid: str | None, jwks: dict) -> dict | None:
    keys = [k for k in jwks.get("keys", []) if k.get("kty") == "RSA"]
    if kid is None:
        return keys[0] if len(keys) == 1 else None
    for key in keys:
        if key.get("kid") == kid:
            return key
    return None


async def verify_google_push_jwt(token: str, *, jwks: JwksProvider | None = None) -> dict:
    """Verify a Pub/Sub push JWT and return its claims.

    Raises WebhookAuthError (transient=False) for anything that definitively
    isn't a Google-issued token, transient=True when the answer depends on
    certificates we couldn't fetch right now.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise WebhookAuthError(f"malformed JWT header: {exc}") from exc
    if header.get("alg") != "RS256":
        # Algorithm pinned: Google signs these with RS256, and a token must
        # never get to choose its own verification method.
        raise WebhookAuthError(f"unexpected JWT algorithm {header.get('alg')!r}, expected RS256")

    keys = await (jwks or google_jwks)()
    jwk = _jwk_for(header.get("kid"), keys)
    # The kid isn't in the cached set: Google may have rotated keys, so allow
    # one refresh of the cache (rate-limited above).
    if (jwk is None and jwks is None
            and time.monotonic() - float(_cache["fetched_at"]) > _FORCE_REFRESH_MIN_INTERVAL_S):
        reset_jwks_cache()
        keys = await google_jwks()
        jwk = _jwk_for(header.get("kid"), keys)
    if jwk is None:
        raise WebhookAuthError("JWT signing key not found in Google's certificate set", transient=True)

    try:
        key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            leeway=CLOCK_LEEWAY_S,
            # `aud` is required to be present (Google sets it to the push
            # endpoint URI) but is not matched against a known value: a
            # deployment's public URL isn't known to the code, so PyJWT's
            # audience comparison is switched off and presence is enforced
            # through `require` instead.
            options={"require": ["exp", "iat", "iss", "aud"], "verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise WebhookAuthError(f"JWT verification failed: {exc}") from exc

    if claims["iss"] not in GOOGLE_ISSUERS:
        raise WebhookAuthError(f"unexpected JWT issuer {claims['iss']!r}")
    # The signature is the authenticating gate: only Google can mint a token
    # that verifies against these keys. Possession of the mailbox's own OAuth
    # credentials is what makes reading it possible afterwards.
    return claims
