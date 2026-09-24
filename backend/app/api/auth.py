"""POST /api/v1/auth/token — OAuth2 client-credentials grant (RFC 6749 §4.4).

Client credentials arrive as form fields or HTTP Basic (RFC 6749 §2.3.1).
Errors use the RFC's JSON shape ({"error": ...}); a failed client check says
only "invalid_client", never whether the id or the secret was wrong. The
rate limiter gives this path its own, much tighter budget.
"""

from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Form, Header
from fastapi.responses import JSONResponse

from app.security.auth import SCOPES, issue_token, verify_client

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _error(status_code: int, error: str, description: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, headers={"Cache-Control": "no-store", **(headers or {})},
                        content={"error": error, "error_description": description})


def _basic(authorization: str | None) -> tuple[str, str] | None:
    if not authorization or not authorization.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    client_id, _, secret = decoded.partition(":")
    return client_id, secret


@router.post("/token")
async def token(
    grant_type: str = Form(..., max_length=64),
    client_id: str | None = Form(None, max_length=128),
    client_secret: str | None = Form(None, max_length=256),
    scope: str | None = Form(None, max_length=256),
    authorization: str | None = Header(None),
) -> JSONResponse:
    if grant_type != "client_credentials":
        return _error(400, "unsupported_grant_type", "Only client_credentials is supported")
    basic = _basic(authorization)
    cid, secret = basic if basic else (client_id, client_secret)
    if not cid or not secret:
        return _error(400, "invalid_request", "client_id and client_secret are required")

    client = verify_client(cid, secret)
    if client is None:
        return _error(401, "invalid_client", "Client authentication failed",
                      headers={"WWW-Authenticate": 'Basic realm="sentivra"'})

    requested = set(scope.split()) if scope else None
    if requested and not requested <= set(SCOPES):
        return _error(400, "invalid_scope", f"Unknown scope(s): {' '.join(sorted(requested - set(SCOPES)))}")
    access_token, ttl, granted = issue_token(client, requested)
    return JSONResponse(
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        # bandit B105: the OAuth2 token_type value, not a secret
        content={"access_token": access_token, "token_type": "bearer", "expires_in": ttl,  # nosec B105
                 "scope": " ".join(sorted(granted))},
    )
