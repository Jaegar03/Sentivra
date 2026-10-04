"""Gmail API access for the push connector — `gmail.readonly` only.

The Pub/Sub push notification carries no mail: it says only "this mailbox
changed, here is its historyId". Reading what changed needs an OAuth2 access
token obtained from a stored refresh token, and then two Gmail REST calls
(history.list, messages.get) on fixed, code-constant Google hosts.

Scope is never widened: no token request in this module asks for anything
but the access already granted under `https://www.googleapis.com/auth/gmail.readonly`.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.core.config import Settings, get_settings

logger = logging.getLogger("sentivra.integrations.gmail")

# A fixed Google endpoint, never built from input: not a credential.
TOKEN_URL = "https://oauth2.googleapis.com/token"  # nosec B105
API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
REQUEST_TIMEOUT_S = 10.0

# Access tokens are cached per refresh token (with a 60 s safety margin), so
# a burst of pushes costs one token exchange, not one per notification.
_token_cache: dict[str, tuple[str, float]] = {}


class GmailNotConfigured(Exception):
    """No OAuth client id/secret/refresh token: the mailbox cannot be read."""


class GmailUpstreamError(Exception):
    """Google answered with an error, or didn't answer at all.

    `status_code` is the HTTP status when Google answered, so callers can
    tell a genuinely gone history (404/410 GONE — fall back) from an outage.
    """

    def __init__(self, reason: str, *, status_code: int | None = None) -> None:
        super().__init__(reason)
        self.status_code = status_code


def reset_token_cache() -> None:
    _token_cache.clear()


class GmailClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def configured(self) -> bool:
        s = self._settings
        return bool(s.gmail_oauth_client_id and s.gmail_oauth_client_secret and s.gmail_oauth_refresh_token)

    async def _access_token(self) -> str:
        s = self._settings
        if not self.configured:
            raise GmailNotConfigured(
                "SENTIVRA_GMAIL_OAUTH_CLIENT_ID, SENTIVRA_GMAIL_OAUTH_CLIENT_SECRET and "
                "SENTIVRA_GMAIL_OAUTH_REFRESH_TOKEN are all required to read mail"
            )
        cached = _token_cache.get(s.gmail_oauth_refresh_token)
        if cached and cached[1] > time.monotonic():
            return cached[0]

        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
                resp = await client.post(TOKEN_URL, data={
                    "grant_type": "refresh_token",
                    "client_id": s.gmail_oauth_client_id,
                    "client_secret": s.gmail_oauth_client_secret,
                    "refresh_token": s.gmail_oauth_refresh_token,
                })
        except httpx.HTTPError as exc:
            raise GmailUpstreamError(f"could not reach Google's token endpoint: {exc}") from exc

        if resp.status_code != 200:
            # Google's OAuth error code only — never the credentials themselves.
            error = _error_detail(resp)
            raise GmailUpstreamError(f"exchanging the Gmail refresh token failed ({resp.status_code}): {error}",
                                     status_code=resp.status_code)
        try:
            payload = resp.json()
            token = str(payload["access_token"])
            expires_in = float(payload.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError) as exc:
            raise GmailUpstreamError("Google's token endpoint returned an unexpected body") from exc
        _token_cache[s.gmail_oauth_refresh_token] = (token, time.monotonic() + expires_in - 60.0)
        return token

    async def _get(self, path: str, params: dict[str, Any]) -> dict:
        token = await self._access_token()
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
                resp = await client.get(f"{API_BASE}{path}", params=params,
                                        headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as exc:
            raise GmailUpstreamError(f"could not reach the Gmail API: {exc}") from exc
        if resp.status_code != 200:
            raise GmailUpstreamError(f"Gmail API {path} failed ({resp.status_code}): {_error_detail(resp)}",
                                     status_code=resp.status_code)
        try:
            return resp.json()
        except ValueError as exc:
            raise GmailUpstreamError(f"Gmail API {path} returned a non-JSON body") from exc

    async def changed_message_ids(self, history_id: str | None, *, limit: int) -> list[str]:
        """Message ids added since the push's historyId, newest first.

        `history.list` is exact; when the historyId is gone (Gmail keeps
        history for a limited window, 404/410 GONE) or absent — a manual
        test push, for instance — fall back to the newest messages, which the
        caller dedupes by message id anyway.
        """
        if history_id:
            try:
                payload = await self._get("/history", {
                    "startHistoryId": history_id,
                    "historyTypes": "messageAdded",
                    "maxResults": limit,
                })
            except GmailUpstreamError as exc:
                if exc.status_code not in (404, 410):
                    raise
                logger.info("Gmail historyId %s is no longer available; using the newest messages", history_id)
            else:
                ids: list[str] = []
                for entry in payload.get("history") or []:
                    for added in entry.get("messagesAdded") or []:
                        message_id = (added.get("message") or {}).get("id")
                        if message_id and message_id not in ids:
                            ids.append(message_id)
                return ids[:limit]

        payload = await self._get("/messages", {"maxResults": limit})
        return [m["id"] for m in payload.get("messages") or [] if m.get("id")][:limit]

    async def get_message(self, message_id: str) -> dict:
        return await self._get(f"/messages/{message_id}", {"format": "full"})


def _error_detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        return str(body.get("error_description") or body.get("error") or body)[:200]
    except ValueError:
        return resp.text[:200] if resp.text else "no details"
