"""POST /api/v1/integrations/gmail/webhook — authentication and orchestration.

Gmail has no direct webhook: `users.watch` on the mailbox publishes to a
Cloud Pub/Sub topic, and the subscription pushes to this endpoint. Two
authentication paths, both checked before anything is parsed:

1. **Google's RS256 push JWT**, verified against Google's published
   certificates (`app.security.webhooks.verify_google_push_jwt`). This is
   what a real Pub/Sub subscription sends, and it is required by default.
2. **The shared verification token** (`SENTIVRA_GMAIL_PUBSUB_VERIFICATION_TOKEN`),
   compared in constant time when it is configured — the `verify_token` of a
   manual `curl` push, for exercising the endpoint before a subscription
   exists. A real Pub/Sub push never carries it, so this path only opens when
   an operator has deliberately set one.

A push that verifies but can't be processed (no read credentials, Google
unreachable) answers 503, so Pub/Sub keeps the notification and retries
instead of silently dropping mail (docs/threat-model.md §3).
"""

from __future__ import annotations

import base64
import json
import logging

from app.core.config import Settings
from app.integrations.common import WebhookOutcome, WebhookRejected
from app.integrations.gmail.client import GmailClient, GmailNotConfigured, GmailUpstreamError
from app.integrations.gmail.normalizer import normalize_message
from app.security.webhooks import WebhookAuthError, verify_google_push_jwt, verify_shared_secret

logger = logging.getLogger("sentivra.integrations.gmail")

# Parameter and header *names* the operator/provider uses — the values they
# carry are compared in constant time, never these literals.
VERIFY_TOKEN_QUERY = "verify_token"  # nosec B105
VERIFY_TOKEN_HEADER = "x-goog-verification-token"  # nosec B105
AUTH_HEADER = "authorization"

# One push should never turn into an unbounded burst of Gmail API calls; the
# caller dedupes by message id, so a later push can pick up whatever is left.
MAX_MESSAGES_PER_PUSH = 5


async def _verify(*, headers, query, settings: Settings) -> None:
    if verify_shared_secret(query.get(VERIFY_TOKEN_QUERY) or headers.get(VERIFY_TOKEN_HEADER),
                            settings.gmail_pubsub_verification_token):
        return

    auth = headers.get(AUTH_HEADER) or ""
    bearer = auth[7:] if auth.lower().startswith("bearer ") else None
    if not bearer:
        raise WebhookRejected(
            403,
            "Missing credentials: expected Google's Pub/Sub push JWT in the Authorization header"
            + (f" or the verification token as ?{VERIFY_TOKEN_QUERY}=" if settings.gmail_pubsub_verification_token
               else "."),
        )
    try:
        await verify_google_push_jwt(bearer)
    except WebhookAuthError as exc:
        # Transient = we could not fetch Google's certificates, so the request
        # is unverified *right now*: fail closed, but say "retry" (503) rather
        # than "forged" (403).
        raise WebhookRejected(503 if exc.transient else 403, f"Push JWT rejected: {exc.reason}") from exc


def _parse_push(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookRejected(400, "Malformed Pub/Sub push payload") from exc
    if not isinstance(payload, dict):
        raise WebhookRejected(400, "Malformed Pub/Sub push payload: expected a JSON object")
    return payload


def _notification(payload: dict) -> tuple[str | None, str | None, str | None]:
    """(mailbox, history_id, note) from a Pub/Sub envelope.

    The data field is base64-encoded JSON: `{"emailAddress": ..., "historyId": ...}`.
    """
    message = payload.get("message") or {}
    data = message.get("data")
    if not data:
        return None, None, "The push carried no Gmail notification data; fetched the newest messages instead."
    try:
        decoded = base64.urlsafe_b64decode(str(data) + "=" * (-len(str(data)) % 4)).decode("utf-8")
        inner = json.loads(decoded)
    except (ValueError, TypeError) as exc:
        raise WebhookRejected(400, "Pub/Sub message data is not base64-encoded JSON") from exc
    if not isinstance(inner, dict):
        raise WebhookRejected(400, "Pub/Sub message data is not a JSON object")
    mailbox = inner.get("emailAddress")
    history_id = str(inner["historyId"]) if inner.get("historyId") is not None else None
    return mailbox, history_id, None


async def collect(raw: bytes, *, headers, query, settings: Settings) -> WebhookOutcome:
    await _verify(headers=headers, query=query, settings=settings)
    mailbox, history_id, note = _notification(_parse_push(raw))

    client = GmailClient(settings)
    if not client.configured:
        # The push was authenticated but cannot be acted on. 503 makes Pub/Sub
        # retry rather than acknowledge a notification we never processed.
        raise WebhookRejected(
            503,
            "Gmail push verified, but the mailbox cannot be read: set SENTIVRA_GMAIL_OAUTH_CLIENT_ID, "
            "SENTIVRA_GMAIL_OAUTH_CLIENT_SECRET and SENTIVRA_GMAIL_OAUTH_REFRESH_TOKEN "
            "(the connector only ever requests gmail.readonly).",
        )

    try:
        message_ids = await client.changed_message_ids(history_id, limit=MAX_MESSAGES_PER_PUSH)
        messages = [await client.get_message(message_id) for message_id in message_ids]
    except GmailNotConfigured as exc:  # pragma: no cover - guarded by client.configured above
        raise WebhookRejected(503, str(exc)) from exc
    except GmailUpstreamError as exc:
        logger.warning("Gmail read failed for mailbox %s: %s", mailbox, exc)
        raise WebhookRejected(502, f"Gmail could not be read: {exc}") from exc

    if not messages:
        suffix = note or f"Gmail reported no new messages for historyId {history_id or 'unknown'}."
        return WebhookOutcome(ignored=1, note=f"Notification verified and acknowledged, nothing to analyze. {suffix}")

    events = [normalize_message(message, mailbox=mailbox, history_id=history_id,
                                max_body_chars=settings.max_text_chars)
              for message in messages]
    if note:
        logger.info("Gmail push handled without notification data: %s", note)
    return WebhookOutcome(events=events, note=note)
