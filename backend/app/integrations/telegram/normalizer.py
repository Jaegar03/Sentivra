"""Telegram Bot API update -> SecurityEvent.

Scope (brief §14): the Bot API only ever delivers messages sent directly to
the bot, or posted in a chat the bot is a member of. It cannot see a user's
private conversations with anyone else, and this connector never asks for
anything more.

Media bytes are never downloaded: attachments are recorded as filename /
type / size metadata only (docs/privacy.md).
"""

from __future__ import annotations

from app.events.schema import (
    AttachmentRef,
    EventContent,
    SecurityEvent,
    SecurityEventType,
    SourceType,
)
from app.integrations.common import clip, event_id_for, extract_urls

PROVIDER = "telegram"

# (payload key, fallback filename, fallback mime) — the media Telegram puts
# inline in an update; only metadata is kept, never the bytes.
_MEDIA_KEYS = (
    ("photo", "photo.jpg", "image/jpeg"),
    ("video", "video.mp4", "video/mp4"),
    ("animation", "animation.mp4", "video/mp4"),
    ("audio", "audio.ogg", "audio/ogg"),
    ("voice", "voice.ogg", "audio/ogg"),
    ("video_note", "video_note.mp4", "video/mp4"),
    ("sticker", "sticker.webp", "image/webp"),
)


def _attachments(message: dict) -> list[AttachmentRef]:
    refs: list[AttachmentRef] = []
    for key, filename, mime in _MEDIA_KEYS:
        media = message.get(key)
        if isinstance(media, dict):
            # For photos Telegram sends a list of sizes; the last is largest.
            size = media.get("file_size")
            refs.append(AttachmentRef(filename=filename, declared_mime=mime, size_bytes=size))
        elif isinstance(media, list) and media:
            largest = media[-1] if isinstance(media[-1], dict) else {}
            refs.append(AttachmentRef(filename=filename, declared_mime=mime,
                                      size_bytes=largest.get("file_size")))
    doc = message.get("document")
    if isinstance(doc, dict):
        refs.append(AttachmentRef(filename=doc.get("file_name") or "document",
                                  declared_mime=doc.get("mime_type"),
                                  size_bytes=doc.get("file_size")))
    return refs


def _sender(from_field: dict) -> tuple[str | None, str | None]:
    user_id = str(from_field["id"]) if from_field.get("id") is not None else None
    username = from_field.get("username")
    if username:
        return f"@{username}", user_id
    name = " ".join(part for part in (from_field.get("first_name"), from_field.get("last_name")) if part)
    return (name or None), user_id


def _forwarded_from(message: dict) -> str | None:
    origin = message.get("forward_origin") or message.get("forward_from")
    if not isinstance(origin, dict):
        return None
    sender = origin.get("sender_chat") or origin.get("sender_user") or origin
    if not isinstance(sender, dict):
        return None
    return sender.get("username") or sender.get("title") or sender.get("first_name") or None


def normalize_update(update: dict, *, max_body_chars: int = 100_000) -> SecurityEvent | None:
    """One Telegram update -> one event, or None if it carries no message.

    Only `message` and `edited_message` are taken: those are messages sent to
    the bot. Other update kinds (_inline_query, callback queries, membership
    changes) are reported as ignored by the caller rather than guessed at.
    """
    message = update.get("message") or update.get("edited_message")
    if not isinstance(message, dict):
        return None

    body_raw = message.get("text") or message.get("caption") or ""
    body, truncated = clip(str(body_raw), max_body_chars)
    attachments = _attachments(message)
    sender, user_id = _sender(message.get("from") or {})
    chat = message.get("chat") or {}
    message_id = message.get("message_id")

    entities = message.get("entities") or message.get("caption_entities") or []
    link_urls = [e.get("url") for e in entities
                 if isinstance(e, dict) and e.get("type") == "text_link" and e.get("url")]
    urls = extract_urls(body)
    for url in link_urls:
        if url not in urls:
            urls.append(url)

    metadata: dict = {
        "message_id": message_id,
        "chat_id": chat.get("id"),
        "chat_type": chat.get("type"),
        "message_kind": "media" if attachments else ("text" if body else "service"),
    }
    if truncated:
        metadata["content_truncated"] = True
    forwarded = _forwarded_from(message)
    if forwarded:
        metadata["forwarded_from"] = forwarded
    if isinstance(message.get("reply_to_message"), dict):
        metadata["reply_to_message_id"] = message["reply_to_message"].get("message_id")

    return SecurityEvent(
        event_id=event_id_for(PROVIDER, f"{chat.get('id')}:{message_id}"),
        event_type=SecurityEventType.TELEGRAM_MESSAGE,
        source=PROVIDER,
        source_type=SourceType.LIVE,
        user_id=user_id,
        content=EventContent(
            subject=None,  # Telegram has no subject line; the chat is the context
            body=body,
            sender=sender,
            recipients=[f"chat:{chat.get('id')}"] if chat.get("id") is not None else [],
            urls=urls,
        ),
        attachments=attachments,
        metadata=metadata,
    )
