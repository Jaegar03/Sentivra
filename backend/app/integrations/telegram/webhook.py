"""POST /api/v1/integrations/telegram/webhook — authentication and parsing.

Telegram authenticates a webhook with the `secret_token` chosen when
`setWebhook` is called: Telegram echoes it back in
`X-Telegram-Bot-Api-Secret-Token` on every delivery. A request without the
right value never reaches a normalizer (docs/threat-model.md §3).
"""

from __future__ import annotations

import json

from app.core.config import Settings
from app.integrations.common import WebhookOutcome, WebhookRejected
from app.integrations.telegram.normalizer import normalize_update
from app.security.webhooks import verify_shared_secret

# Telegram's header name, not a secret: the value it carries is compared in
# constant time against SENTIVRA_TELEGRAM_WEBHOOK_SECRET_TOKEN.
SECRET_HEADER = "x-telegram-bot-api-secret-token"  # nosec B105


def collect(raw: bytes, *, headers, query, settings: Settings) -> WebhookOutcome:
    if not settings.telegram_bot_token or not settings.telegram_webhook_secret_token:
        raise WebhookRejected(
            503,
            "Telegram connector is not configured: set SENTIVRA_TELEGRAM_BOT_TOKEN and "
            "SENTIVRA_TELEGRAM_WEBHOOK_SECRET_TOKEN (the same value passed to setWebhook as secret_token).",
        )
    if not verify_shared_secret(headers.get(SECRET_HEADER), settings.telegram_webhook_secret_token):
        # 403, not 401: this caller is a provider, not an API client that
        # could retry with different credentials.
        raise WebhookRejected(403, "Missing or invalid X-Telegram-Bot-Api-Secret-Token header")

    try:
        update = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookRejected(400, "Malformed Telegram update payload") from exc
    if not isinstance(update, dict):
        raise WebhookRejected(400, "Malformed Telegram update payload: expected a JSON object")

    event = normalize_update(update, max_body_chars=settings.max_text_chars)
    if event is None:
        return WebhookOutcome(
            ignored=1,
            note="Update accepted but ignored: this connector only takes messages sent to the bot "
                 "(message / edited_message).",
        )
    return WebhookOutcome(events=[event])
