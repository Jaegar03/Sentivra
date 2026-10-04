"""Gmail message -> SecurityEvent (brief §13, docs/privacy.md).

Only `gmail.readonly` is ever used: this module reads a message that has
already arrived and normalizes it. Nothing here labels, moves, sends or
deletes mail, and no attachment bytes are ever downloaded — attachments are
recorded as filename / type / size metadata only.
"""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime

from app.events.schema import (
    AttachmentRef,
    EventContent,
    SecurityEvent,
    SecurityEventType,
    SourceType,
)
from app.integrations.common import clip, event_id_for, extract_urls

logger = logging.getLogger("sentivra.integrations.gmail")

PROVIDER = "gmail"

# Headers worth keeping on the event: sender/recipient context and the
# authentication trail a phishing verdict later leans on. Everything else
# (Received chains, bulk list headers) stays in the mail itself.
_KEEP_HEADERS = frozenset({
    "from", "to", "cc", "reply-to", "return-path", "subject", "date",
    "message-id", "list-unsubscribe", "authentication-results", "x-originating-ip",
    "x-mailer",
})


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _walk_parts(part: dict):
    """Yield every MIME part of a Gmail payload, depth first."""
    yield part
    for child in part.get("parts") or []:
        if isinstance(child, dict):
            yield from _walk_parts(child)


def _body_text(payload: dict) -> str | None:
    plain: str | None = None
    html: str | None = None
    for part in _walk_parts(payload):
        data = (part.get("body") or {}).get("data")
        if not data:
            continue
        try:
            text = _b64url_decode(data).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            logger.warning("Gmail part had undecodable base64 body data; skipped")
            continue
        mime = str(part.get("mimeType") or "").lower()
        if plain is None and mime.startswith("text/plain"):
            plain = text
        elif html is None and mime.startswith("text/html"):
            html = text
        elif plain is None and not mime:
            plain = text
    return plain if plain is not None else html


def _attachments(payload: dict) -> list[AttachmentRef]:
    refs: list[AttachmentRef] = []
    for part in _walk_parts(payload):
        filename = part.get("filename")
        if not filename:
            continue
        body = part.get("body") or {}
        refs.append(AttachmentRef(
            filename=str(filename),
            declared_mime=part.get("mimeType"),
            size_bytes=body.get("size"),
            sha256=None,  # bytes are never fetched, so there is no hash to report
        ))
    return refs


def _headers(payload: dict) -> dict[str, str]:
    kept: dict[str, str] = {}
    for header in payload.get("headers") or []:
        if not isinstance(header, dict):
            continue
        name = str(header.get("name") or "").lower()
        value = str(header.get("value") or "").strip()
        if name in _KEEP_HEADERS and value and name not in kept:
            kept[name] = value
    return kept


def _timestamp(message: dict) -> datetime:
    raw = message.get("internalDate")
    try:
        return datetime.fromtimestamp(int(raw) / 1000, tz=UTC)
    except (TypeError, ValueError, OSError):
        return datetime.now(UTC)


def normalize_message(message: dict, *, mailbox: str | None = None,
                      history_id: str | None = None, max_body_chars: int = 100_000) -> SecurityEvent:
    payload = message.get("payload") or {}
    headers = _headers(payload)
    body_text = _body_text(payload)
    if body_text is None:
        # Single-part messages and some MIME shapes put the text at the top
        # level; `snippet` is Gmail's own short preview and is only used as
        # the analysis input when there is nothing else.
        body_text = str(message.get("snippet") or "")
    body, truncated = clip(body_text, max_body_chars)

    recipients = [value for key in ("to", "cc") if (value := headers.get(key))]
    metadata: dict = {
        "message_id": message.get("id"),
        "thread_id": message.get("threadId"),
        "labels": message.get("labelIds") or [],
        "internal_date": message.get("internalDate"),
        "history_id": history_id,
        "mailbox": mailbox,
    }
    if truncated:
        metadata["content_truncated"] = True

    return SecurityEvent(
        event_id=event_id_for(PROVIDER, str(message.get("id"))),
        event_type=SecurityEventType.GMAIL_MESSAGE,
        source=PROVIDER,
        source_type=SourceType.LIVE,
        user_id=mailbox,
        content=EventContent(
            subject=headers.get("subject"),
            body=body,
            sender=headers.get("from"),
            recipients=recipients,
            urls=extract_urls(body),
            headers=headers,
        ),
        attachments=_attachments(payload),
        metadata=metadata,
    )
