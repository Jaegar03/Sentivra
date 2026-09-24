"""API authentication: the OAuth2 client-credentials grant (RFC 6749 §4.4)
with short-lived signed bearer tokens and per-route scopes.

  POST /api/v1/auth/token  grant_type=client_credentials, client_id, client_secret
                           (form fields, or HTTP Basic)  ->  {"access_token", ...}
  every other route        Authorization: Bearer <access_token>

Why this shape:
  * Bearer tokens in a header (not cookies) mean browsers never attach them
    automatically, so cross-site request forgery doesn't apply.
  * Least privilege: each route needs a scope. `read` for GETs, `analyze` for
    analysis and demo runs, `ingest` for telemetry/log/event submission,
    `alerts:write` for status changes. An ingest-only agent can't read alerts.
  * Client secrets are 256-bit random values stored only as SHA-256 hashes
    and compared in constant time. (A slow password hash protects low-entropy
    human passwords; these aren't.)
  * Tokens are HS256 JWTs with exp/iat/iss/jti, verified with the algorithm
    pinned so a token can't choose its own verification method.

Local, first-run convenience (development only): with no clients configured,
a `dashboard` client is generated, its secret printed once to the log and
only its hash kept in state_dir. The signing key is likewise generated
there when SENTIVRA_SECRET_KEY is unset, a placeholder published in this repo,
or too short. Outside development, both must be configured explicitly or the
app refuses to start.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import MIN_SECRET_KEY_CHARS, get_settings

logger = logging.getLogger("sentivra.auth")

SCOPES = {
    "read": "Read alerts, events, metrics, models, rules, audit log and status",
    "analyze": "Run analyses and demo scenarios",
    "ingest": "Submit events, endpoint telemetry and logs",
    "alerts:write": "Change alert status",
}
ALGORITHM = "HS256"
ISSUER = "sentivra"
_DASHBOARD_SCOPES = ("read", "analyze", "ingest", "alerts:write")


class AuthConfigError(RuntimeError):
    """Raised at startup when authentication can't be configured safely."""


@dataclass(frozen=True)
class Client:
    client_id: str
    secret_sha256: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class Principal:
    client_id: str
    scopes: frozenset[str]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # best effort; ACLs govern this on Windows
    except OSError:
        pass


def _parse_clients(raw: str) -> dict[str, Client]:
    raw = raw.strip()
    entries: list[tuple[str, str, list[str]]] = []
    if raw.startswith("["):
        for item in json.loads(raw):
            entries.append((item["client_id"], item["client_secret"], list(item["scopes"])))
    else:
        for chunk in filter(None, (c.strip() for c in raw.split(";"))):
            client_id, secret, scopes = chunk.split(":", 2)
            entries.append((client_id.strip(), secret.strip(), scopes.split()))
    clients: dict[str, Client] = {}
    for client_id, secret, scopes in entries:
        unknown = set(scopes) - set(SCOPES)
        if unknown:
            raise AuthConfigError(f"client {client_id!r} has unknown scopes {sorted(unknown)}")
        if len(secret) < 32:
            raise AuthConfigError(f"client {client_id!r}: secrets must be at least 32 characters")
        clients[client_id] = Client(client_id, _sha256(secret), frozenset(scopes))
    return clients


@lru_cache
def load_clients() -> dict[str, Client]:
    settings = get_settings()
    if settings.oauth_clients.strip():
        return _parse_clients(settings.oauth_clients)

    store = settings.state_dir / "clients.json"
    if store.exists():
        data = json.loads(store.read_text(encoding="utf-8"))
        return {c["client_id"]: Client(c["client_id"], c["secret_sha256"], frozenset(c["scopes"])) for c in data}

    if not settings.is_development:
        raise AuthConfigError("No API clients configured: set SENTIVRA_OAUTH_CLIENTS")
    secret = secrets.token_urlsafe(32)
    client = Client("dashboard", _sha256(secret), frozenset(_DASHBOARD_SCOPES))
    _write_private(store, json.dumps([{"client_id": client.client_id, "secret_sha256": client.secret_sha256,
                                       "scopes": sorted(client.scopes)}], indent=2))
    logger.warning(
        "\n\n  SENTIVRA generated an API client for the dashboard (development only).\n"
        "  client_id:     dashboard\n"
        "  client_secret: %s\n"
        "  Paste the secret into the dashboard's sign-in screen. It is shown only once;\n"
        "  only its hash is stored in %s. Delete that file to generate a new one.\n",
        secret, store,
    )
    return {client.client_id: client}


@lru_cache
def signing_key() -> str:
    settings = get_settings()
    if not settings.secret_key_is_unsafe:
        return settings.secret_key.strip()
    if not settings.is_development:
        raise AuthConfigError(
            f"SENTIVRA_SECRET_KEY must be a random value of at least {MIN_SECRET_KEY_CHARS} characters outside "
            "development (not a placeholder from .env.example)")
    # An unset, placeholder or short key would let anyone forge tokens.
    # Development uses a random per-install key instead.
    path = settings.state_dir / "signing.key"
    if not path.exists():
        _write_private(path, secrets.token_urlsafe(48))
    return path.read_text(encoding="utf-8").strip()


def verify_client(client_id: str, client_secret: str) -> Client | None:
    client = load_clients().get(client_id)
    # Compare against a dummy hash for unknown ids too, so response timing
    # doesn't reveal which client ids exist.
    expected = client.secret_sha256 if client else _sha256("unknown-client")
    ok = hmac.compare_digest(expected, _sha256(client_secret))
    return client if ok and client else None


def issue_token(client: Client, requested: set[str] | None = None) -> tuple[str, int, frozenset[str]]:
    scopes = client.scopes if not requested else client.scopes & requested
    now = int(time.time())
    ttl = get_settings().token_ttl_s
    claims = {"iss": ISSUER, "sub": client.client_id, "scope": " ".join(sorted(scopes)),
              "iat": now, "exp": now + ttl, "jti": str(uuid.uuid4())}
    return jwt.encode(claims, signing_key(), algorithm=ALGORITHM), ttl, frozenset(scopes)


def decode_token(token: str) -> Principal:
    claims = jwt.decode(token, signing_key(), algorithms=[ALGORITHM], issuer=ISSUER,
                        options={"require": ["exp", "iat", "iss", "sub"]})
    client = load_clients().get(claims["sub"])
    if client is None:
        raise jwt.InvalidTokenError("client no longer exists")
    # Scopes can only narrow: a token never carries more than its client now has.
    return Principal(claims["sub"], frozenset(claims.get("scope", "").split()) & client.scopes)


_bearer = HTTPBearer(auto_error=False)
# Set by require_scopes for the duration of a request, so the audit log can
# record which client acted without threading it through every call.
_current: ContextVar[Principal | None] = ContextVar("sentivra_principal", default=None)


def current_actor() -> str:
    principal = _current.get()
    return principal.client_id if principal else "system"


def require_scopes(*needed: str):
    unknown = set(needed) - set(SCOPES)
    if unknown:
        raise ValueError(f"unknown scopes {unknown}")

    async def dependency(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required",
                                headers={"WWW-Authenticate": 'Bearer realm="sentivra"'})
        try:
            principal = decode_token(credentials.credentials)
        except jwt.PyJWTError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
                                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}) from exc
        missing = set(needed) - principal.scopes
        if missing:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing scope: {' '.join(sorted(missing))}",
                                headers={"WWW-Authenticate": f'Bearer error="insufficient_scope" scope="{" ".join(needed)}"'})
        _current.set(principal)
        return principal

    return dependency
