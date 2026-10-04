"""Webhook handshake and verification for
POST/GET /api/v1/integrations/whatsapp/webhook (brief §15).

Meta's two-step contract:
  * GET  with `hub.mode=subscribe`, `hub.verify_token`, `hub.challenge` —
    answered by echoing the challenge when the token matches.
  * POST with `X-Hub-Signature-256`, an HMAC-SHA256 of the *raw* body using
    the app secret. Computed before any parsing, so an unsigned or
    wrongly-signed request never becomes an event
    (docs/threat-model.md, Boundary A).
"""

from __future__ import annotations

import json

from app.core.config import Settings
from app.integrations.common import WebhookOutcome, WebhookRejected
from app.integrations.whatsapp.normalizer import normalize_message
from app.security.webhooks import verify_hmac_sha256, verify_shared_secret

SIGNATURE_HEADER = "x-hub-signature-256"
MODE = "subscribe"


def verify_subscription(*, query, settings: Settings) -> str:
    """GET handshake: returns the challenge to echo, or raises WebhookRejected."""
    if not settings.whatsapp_webhook_verify_token:
        raise WebhookRejected(
            503,
            "WhatsApp connector is not configured: set SENTIVRA_WHATSAPP_WEBHOOK_VERIFY_TOKEN "
            "to the value you entered in the Meta App Dashboard.",
        )
    if query.get("hub.mode") != MODE:
        raise WebhookRejected(400, "hub.mode must be 'subscribe'")
    if not verify_shared_secret(query.get("hub.verify_token"), settings.whatsapp_webhook_verify_token):
        raise WebhookRejected(403, "hub.verify_token did not match SENTIVRA_WHATSAPP_WEBHOOK_VERIFY_TOKEN")
    challenge = query.get("hub.challenge")
    if challenge is None:
        raise WebhookRejected(400, "hub.challenge is missing")
    return challenge


def collect(raw: bytes, *, headers, query, settings: Settings) -> WebhookOutcome:
    if not settings.whatsapp_app_secret:
        raise WebhookRejected(
            503,
            "WhatsApp connector is not configured: set SENTIVRA_WHATSAPP_APP_SECRET "
            "(the App Secret from the Meta App Dashboard).",
        )
    if not verify_hmac_sha256(secret=settings.whatsapp_app_secret, payload=raw,
                              signature_header=headers.get(SIGNATURE_HEADER)):
        raise WebhookRejected(403, f"Missing or invalid {SIGNATURE_HEADER} signature")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookRejected(400, "Malformed WhatsApp webhook payload") from exc
    if not isinstance(payload, dict):
        raise WebhookRejected(400, "Malformed WhatsApp webhook payload: expected a JSON object")

    events = []
    ignored = 0
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            if change.get("field") != "messages":
                continue
            value = change.get("value") or {}
            contacts = value.get("contacts") or []
            metadata = value.get("metadata") or {}
            business_number = metadata.get("display_phone_number")
            phone_number_id = metadata.get("phone_number_id")
            for item in value.get("messages") or []:
                if not isinstance(item, dict):
                    continue
                event = normalize_message(item, contacts=contacts, business_number=business_number,
                                          phone_number_id=phone_number_id,
                                          max_body_chars=settings.max_text_chars)
                if event is None:
                    ignored += 1
                else:
                    events.append(event)
            # Delivery/read/status updates carry no content to analyze.
            ignored += len(value.get("statuses") or [])

    note = None
    if not events and not ignored:
        note = "Webhook verified, but the payload contained no message entries."
    elif ignored and not events:
        note = f"Webhook verified: {ignored} status update(s) accepted, nothing to analyze."
    return WebhookOutcome(events=events, ignored=ignored, note=note)
