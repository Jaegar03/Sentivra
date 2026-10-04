"""Shared pieces of the three Phase 7 webhook connectors.

Every connector follows the same shape:

    verify the request came from the provider  (app.security.webhooks)
      -> parse the provider payload            (integration webhook.py)
      -> normalize it into a SecurityEvent     (integration normalizer.py)
      -> run the shared pipeline and persist redacted  (app.api.webhooks)

so that no provider-specific payload ever reaches a detector, and no raw
message body is retained once the analysis has run (README principle 4,
docs/privacy.md).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field

from app.events.schema import SecurityEvent

# Conservative: scheme + non-space run, then trailing sentence punctuation
# trimmed. Detectors get the real URLs from the body; this only seeds the
# event's `content.urls` with what a human would click.
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URL_TRAILERS = ".,;:!?)]}>"


class WebhookRejected(Exception):
    """A webhook request the connector refused, with the HTTP status to answer.

    Raised only after the route has parsed the request body: verification
    failures (403), an unconfigured connector (503), a malformed provider
    payload (400) or an upstream read that failed (502).
    """

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class WebhookOutcome:
    """What a connector extracted from one verified webhook request."""

    events: list[SecurityEvent] = field(default_factory=list)
    # Updates that are valid but carry nothing to analyze (a delivery receipt,
    # a non-message Telegram update). Counted, never silently dropped.
    ignored: int = 0
    note: str | None = None


def event_id_for(provider: str, message_id: str) -> str:
    """A deterministic event id, so a provider retry can't create a twin.

    Providers redeliver when they don't like our response. Deriving the id
    from the provider's own message id lets the repository's
    `create_if_absent` (and the webhook route's pre-check) treat a redelivery
    as the same event instead of a second alert (docs/threat-model.md §3).
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentivra:{provider}:{message_id}"))


def extract_urls(text: str | None, *, limit: int = 25) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for match in _URL_RE.findall(text):
        url = match.rstrip(_URL_TRAILERS)
        if url and url not in found:
            found.append(url)
        if len(found) >= limit:
            break
    return found


def clip(text: str, limit: int) -> tuple[str, bool]:
    """Bound a provider-supplied body before it is analyzed or stored."""
    if limit <= 0 or len(text) <= limit:
        return text, False
    return text[:limit], True


def without_body(event: SecurityEvent) -> SecurityEvent:
    """The copy that gets persisted: hash + metadata, never the body.

    Detectors analyze the full body; only this redacted copy reaches the
    database (README principle 4 — raw message bodies are not retained by
    default). The subject, sender, recipients and extracted URLs stay: they
    are the header/indicator metadata an analyst needs, and they are what the
    dashboard shows.
    """
    if event.content is None or event.content.body is None:
        return event
    body = event.content.body
    stored = event.model_copy(deep=True)
    stored.content.body = None
    stored.metadata = {
        **event.metadata,
        "content_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "content_chars": len(body),
        "body_retained": False,
    }
    return stored
