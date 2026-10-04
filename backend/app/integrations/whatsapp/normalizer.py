"""WhatsApp Cloud API message -> SecurityEvent (brief §15, docs/privacy.md).

Talks to Meta's Graph API directly — no third-party proxy (repository-analysis
§9). Media bytes are never fetched: a media message is recorded as its
WhatsApp-provided metadata (mime type, filename, media id and Meta's own
SHA-256 when present), which keeps the connector read-only and the storage
content-free.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from app.events.schema import (
    AttachmentRef,
    EventContent,
    SecurityEvent,
    SecurityEventType,
    SourceType,
)
from app.integrations.common import clip, event_id_for, extract_urls

PROVIDER = "whatsapp"

# message type -> (attachment filename fallback, mime)
_MEDIA_TYPES = {
    "image": ("image.jpg", "image/jpeg"),
    "video": ("video.mp4", "video/mp4"),
    "audio": ("audio.ogg", "audio/ogg"),
    "document": ("document", "application/octet-stream"),
    "sticker": ("sticker.webp", "image/webp"),
}


def _media_ref(item: dict) -> AttachmentRef | None:
    kind = item.get("type")
    if kind not in _MEDIA_TYPES:
        return None
    media = item.get(kind) or {}
    fallback_name, fallback_mime = _MEDIA_TYPES[kind]
    filename = media.get("filename")
    if not filename and kind == "document":
        filename = fallback_name
    sha256: str | None = None
    if media.get("sha256"):
        try:
            # WhatsApp sends the digest base64-encoded; the event schema keeps hex.
            sha256 = base64.b64decode(str(media["sha256"]), validate=True).hex()
        except (ValueError, TypeError):
            sha256 = None
    return AttachmentRef(
        filename=str(filename or fallback_name),
        declared_mime=media.get("mime_type") or fallback_mime,
        size_bytes=None,  # the Cloud API does not report a size in the webhook
        sha256=sha256,
    )


def _profile_name(contacts: list, wa_id: str | None) -> str | None:
    for contact in contacts:
        if not isinstance(contact, dict):
            continue
        if wa_id and contact.get("wa_id") == wa_id:
            return ((contact.get("profile") or {}).get("name")) or None
    return None


def _body(item: dict) -> str:
    kind = item.get("type")
    if kind == "text":
        return str((item.get("text") or {}).get("body") or "")
    if kind in _MEDIA_TYPES:
        return str((item.get(kind) or {}).get("caption") or "")
    if kind == "interactive":
        interactive = item.get("interactive") or {}
        replied = interactive.get("button_reply") or interactive.get("list_reply") or {}
        return str(replied.get("title") or "")
    if kind == "button":
        return str((item.get("button") or {}).get("text") or "")
    return ""


def _timestamp(item: dict) -> datetime:
    try:
        return datetime.fromtimestamp(int(item.get("timestamp")), tz=UTC)
    except (TypeError, ValueError, OSError):
        return datetime.now(UTC)


def normalize_message(item: dict, *, contacts: list | None = None, business_number: str | None = None,
                      phone_number_id: str | None = None, max_body_chars: int = 100_000
                      ) -> SecurityEvent | None:
    message_id = item.get("id")
    if not message_id:
        # Without Meta's message id there is no stable key for replay dedup.
        return None

    contacts = contacts or []
    sender = str(item.get("from") or "")
    body_raw = _body(item)
    body, truncated = clip(body_raw, max_body_chars)
    kind = str(item.get("type") or "unknown")
    profile = _profile_name(contacts, sender)

    metadata: dict = {
        "message_id": message_id,
        "message_type": kind,
        "sender_profile_name": profile,
        "phone_number_id": phone_number_id,
        "display_phone_number": business_number,
    }
    if truncated:
        metadata["content_truncated"] = True
    location = item.get("location")
    if isinstance(location, dict):
        metadata["location"] = {k: location.get(k) for k in ("latitude", "longitude", "address", "name")
                                if location.get(k) is not None}
    reaction = item.get("reaction")
    if isinstance(reaction, dict):
        metadata["reaction"] = {k: reaction.get(k) for k in ("message_id", "emoji") if reaction.get(k) is not None}

    attachment = _media_ref(item)

    return SecurityEvent(
        event_id=event_id_for(PROVIDER, str(message_id)),
        event_type=SecurityEventType.WHATSAPP_MESSAGE,
        source=PROVIDER,
        source_type=SourceType.LIVE,
        user_id=sender or None,
        timestamp=_timestamp(item),
        content=EventContent(
            subject=None,  # chat messages have no subject line
            body=body,
            sender=f"{profile} ({sender})" if profile else sender,
            recipients=[business_number] if business_number else [],
            urls=extract_urls(body),
        ),
        attachments=[attachment] if attachment else [],
        metadata=metadata,
    )
