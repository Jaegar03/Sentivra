"""Phase 7 webhook connectors (docs/api.md § Webhooks, docs/privacy.md).

Three claims are proved here for each provider:

1. An unverified request never reaches a normalizer — no bearer token is
   accepted on these routes, only the provider's own proof.
2. A verified message is normalized, analyzed and stored exactly once: a
   redelivery is counted as a duplicate, not a second event.
3. Detectors saw the body; the database did not (README principle 4).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.core.config import get_settings

GMAIL_URL = "/api/v1/integrations/gmail/webhook"
TELEGRAM_URL = "/api/v1/integrations/telegram/webhook"
WHATSAPP_URL = "/api/v1/integrations/whatsapp/webhook"

TELEGRAM_SECRET = "telegram-secret-0123456789abcdef0123456789"
WHATSAPP_APP_SECRET = "whatsapp-app-secret-0123456789abcdef0123456789"
WHATSAPP_VERIFY_TOKEN = "whatsapp-verify-0123456789abcdef"
GMAIL_VERIFY_TOKEN = "gmail-verify-0123456789abcdef"


# ---- configuration helpers (monkeypatched onto the cached Settings) ---------

def _use_telegram(monkeypatch, *, bot_token="999123456:TEST-BOT-TOKEN", secret=TELEGRAM_SECRET) -> str:
    s = get_settings()
    monkeypatch.setattr(s, "telegram_bot_token", bot_token)
    monkeypatch.setattr(s, "telegram_webhook_secret_token", secret)
    return secret


def _use_whatsapp(monkeypatch) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "whatsapp_app_secret", WHATSAPP_APP_SECRET)
    monkeypatch.setattr(s, "whatsapp_webhook_verify_token", WHATSAPP_VERIFY_TOKEN)


def _use_gmail(monkeypatch, *, verification_token: str | None = None) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "gmail_oauth_client_id", "sentivra-test.apps.googleusercontent.com")
    monkeypatch.setattr(s, "gmail_oauth_client_secret", "GOCSPX-test-client-secret-value-0123456789")
    monkeypatch.setattr(s, "gmail_oauth_refresh_token", "1//0-refresh-token-test-value")
    if verification_token is not None:
        monkeypatch.setattr(s, "gmail_pubsub_verification_token", verification_token)


def _clear_gmail(monkeypatch) -> None:
    s = get_settings()
    for name in ("gmail_oauth_client_id", "gmail_oauth_client_secret", "gmail_oauth_refresh_token",
                 "gmail_pubsub_verification_token"):
        monkeypatch.setattr(s, name, "")


# ---- provider payloads ------------------------------------------------------

def _telegram_update(message_id: int, text: str = "Verify your account: http://192.168.0.10/login") -> dict:
    return {
        "update_id": 5000 + message_id,
        "message": {
            "message_id": message_id,
            "from": {"id": 7001, "is_bot": False, "first_name": "Mira", "username": "mira"},
            "chat": {"id": -100123, "type": "group", "title": "SOC"},
            "date": 1767225600,
            "text": text,
            "entities": [{"type": "url", "offset": 19, "length": 27}],
        },
    }


def _whatsapp_payload(message_id: str = "wamid.TEST-1") -> dict:
    return {
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WABA-1",
            "changes": [{
                "field": "messages",
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {"display_phone_number": "15551234567", "phone_number_id": "PNID-1"},
                    "contacts": [{"wa_id": "15557654321", "profile": {"name": "Ava"}}],
                    "messages": [{
                        "from": "15557654321",
                        "id": message_id,
                        "timestamp": "1767225600",
                        "type": "text",
                        "text": {"body": "Your parcel is held: https://track-parcel.example/pay"},
                    }],
                    "statuses": [{"id": "wamid.OLD", "status": "delivered", "timestamp": "1767225601"}],
                },
            }],
        }],
    }


def _gmail_message(message_id: str = "msg-1") -> dict:
    return {
        "id": message_id,
        "threadId": "thread-1",
        "labelIds": ["INBOX"],
        "snippet": "Reset your password",
        "internalDate": "1767225600000",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "security@paypa1.example"},
                {"name": "To", "value": "soc@example.com"},
                {"name": "Subject", "value": "Urgent: password reset"},
                {"name": "Message-ID", "value": "<abc@paypa1.example>"},
                {"name": "X-Mailer", "value": "bulk-sender"},
                {"name": "X-Unrelated", "value": "dropped"},
            ],
            "parts": [
                {"mimeType": "text/plain", "filename": "",
                 "body": {"data": base64.urlsafe_b64encode(
                     b"Reset your password at http://evil.example/reset within 24h.").decode()}},
                {"mimeType": "application/pdf", "filename": "invoice.pdf",
                 "body": {"attachmentId": "att-1", "size": 1234}},
            ],
        },
    }


def _pubsub_push(*, mailbox="soc@example.com", history_id="987654321") -> dict:
    inner = json.dumps({"emailAddress": mailbox, "historyId": history_id}).encode()
    return {
        "message": {
            "data": base64.urlsafe_b64encode(inner).decode(),
            "messageId": "pubsub-message-1",
            "publishTime": "2026-01-01T00:00:00.000Z",
        },
        "subscription": "projects/sentivra/subscriptions/mail",
    }


# ---- Google push JWT test doubles ------------------------------------------

_signing_pair: tuple | None = None


def _google_key():
    """One RSA key + JWK per session, shared by the token and the fake JWKS."""
    global _signing_pair
    if _signing_pair is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update(kid="sentivra-test-key", alg="RS256", use="sig")
        _signing_pair = (key, jwk)
    return _signing_pair


def _push_token(*, kid: str | None = None, **overrides) -> str:
    key, jwk = _google_key()
    now = int(time.time())
    claims = {"iss": "https://accounts.google.com",
              "aud": "https://soc.example.com/api/v1/integrations/gmail/webhook",
              "sub": "push@sentivra-test.iam.gserviceaccount.com",
              "iat": now, "exp": now + 300}
    claims.update(overrides)
    return pyjwt.encode(claims, key, algorithm="RS256", headers={"kid": kid or jwk["kid"]})


def _patch_jwks(monkeypatch) -> None:
    from app.security import webhooks as w

    _, jwk = _google_key()

    async def fake_jwks() -> dict:
        return {"keys": [jwk]}

    monkeypatch.setattr(w, "google_jwks", fake_jwks)
    w.reset_jwks_cache()


def _patch_gmail_client(monkeypatch, messages: list[dict] | None = None) -> None:
    from app.integrations.gmail import webhook as gmail_webhook

    messages = [_gmail_message()] if messages is None else messages

    class FakeGmailClient:
        def __init__(self, settings=None) -> None:
            self.configured = True

        async def changed_message_ids(self, history_id, *, limit):
            return [m["id"] for m in messages][:limit]

        async def get_message(self, message_id):
            return next(m for m in messages if m["id"] == message_id)

    monkeypatch.setattr(gmail_webhook, "GmailClient", FakeGmailClient)


def _whatsapp_signature(body: bytes, secret: str = WHATSAPP_APP_SECRET) -> dict:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {"Content-Type": "application/json", "X-Hub-Signature-256": f"sha256={digest}"}


# ---- Telegram ----------------------------------------------------------------

def test_telegram_webhook_fails_closed_when_not_configured(app_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "telegram_bot_token", "")
    monkeypatch.setattr(get_settings(), "telegram_webhook_secret_token", "")
    resp = app_client.post(TELEGRAM_URL, json=_telegram_update(1))
    assert resp.status_code == 503 and "not configured" in resp.json()["detail"]


def test_telegram_rejects_a_request_without_the_secret_header(app_client, monkeypatch):
    _use_telegram(monkeypatch)
    assert app_client.post(TELEGRAM_URL, json=_telegram_update(2)).status_code == 403
    forged = app_client.post(TELEGRAM_URL, json=_telegram_update(2),
                             headers={"X-Telegram-Bot-Api-Secret-Token": "not-the-secret"})
    assert forged.status_code == 403 and "secret" in forged.json()["detail"].lower()


def test_telegram_message_is_normalized_stored_and_redacted(app_client, monkeypatch):
    secret = _use_telegram(monkeypatch)
    text = "Verify your account: http://192.168.0.10/login"
    resp = app_client.post(TELEGRAM_URL, json=_telegram_update(11, text),
                           headers={"X-Telegram-Bot-Api-Secret-Token": secret})
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 1 and body["duplicates"] == 0 and body["event_ids"]
    # Honest about coverage: no detector in this build reads message content.
    assert body["detectors"] == [] and "Phase 4" in body["note"]

    stored = app_client.get(f"/api/v1/events/{body['event_ids'][0]}").json()
    assert stored["event_type"] == "telegram_message" and stored["source_type"] == "LIVE"
    assert stored["content"]["sender"] == "@mira" and stored["content"]["body"] is None
    assert stored["content"]["urls"] == ["http://192.168.0.10/login"]
    assert stored["metadata"]["chat_id"] == -100123
    assert stored["metadata"]["body_retained"] is False
    assert stored["metadata"]["content_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert stored["metadata"]["content_chars"] == len(text)

    audit = app_client.get("/api/v1/audit", params={"action": "analyze"}).json()["entries"]
    assert any(e["resource"] == f"event:{stored['event_id']}" and e["actor"] == "webhook:telegram"
               for e in audit)


def test_telegram_redelivery_is_counted_as_a_duplicate(app_client, monkeypatch):
    secret = _use_telegram(monkeypatch)
    payload = _telegram_update(12)
    first = app_client.post(TELEGRAM_URL, json=payload,
                            headers={"X-Telegram-Bot-Api-Secret-Token": secret})
    second = app_client.post(TELEGRAM_URL, json=payload,
                             headers={"X-Telegram-Bot-Api-Secret-Token": secret})
    assert first.json()["accepted"] == 1
    assert second.json()["accepted"] == 0 and second.json()["duplicates"] == 1
    assert second.json()["event_ids"] == []
    # Exactly one stored event for that message.
    events = app_client.get("/api/v1/events", params={"limit": 200}).json()
    assert sum(1 for e in events if e["event_id"] == first.json()["event_ids"][0]) == 1


def test_telegram_ignores_updates_that_carry_no_message(app_client, monkeypatch):
    secret = _use_telegram(monkeypatch)
    resp = app_client.post(TELEGRAM_URL, json={"update_id": 99, "my_chat_member": {"chat": {"id": 1}}},
                           headers={"X-Telegram-Bot-Api-Secret-Token": secret})
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 0 and resp.json()["ignored"] == 1
    assert "sent to the bot" in resp.json()["note"]


def test_telegram_rejects_a_body_that_is_not_json(app_client, monkeypatch):
    secret = _use_telegram(monkeypatch)
    resp = app_client.post(TELEGRAM_URL, content=b"{not json",
                           headers={"X-Telegram-Bot-Api-Secret-Token": secret,
                                    "Content-Type": "application/json"})
    assert resp.status_code == 400


# ---- WhatsApp ----------------------------------------------------------------

def test_whatsapp_subscription_handshake(app_client, monkeypatch):
    _use_whatsapp(monkeypatch)
    params = {"hub.mode": "subscribe", "hub.verify_token": WHATSAPP_VERIFY_TOKEN, "hub.challenge": "123456"}
    ok = app_client.get(WHATSAPP_URL, params=params)
    assert ok.status_code == 200 and ok.text == "123456"

    bad = {**params, "hub.verify_token": "wrong"}
    assert app_client.get(WHATSAPP_URL, params=bad).status_code == 403
    assert app_client.get(WHATSAPP_URL, params={**params, "hub.mode": "unsubscribe"}).status_code == 400

    monkeypatch.setattr(get_settings(), "whatsapp_webhook_verify_token", "")
    assert app_client.get(WHATSAPP_URL, params=params).status_code == 503


def test_whatsapp_rejects_unsigned_and_mis_signed_posts(app_client, monkeypatch):
    _use_whatsapp(monkeypatch)
    raw = json.dumps(_whatsapp_payload()).encode()
    assert app_client.post(WHATSAPP_URL, content=raw,
                           headers={"Content-Type": "application/json"}).status_code == 403

    forged = dict(_whatsapp_signature(raw))
    forged["X-Hub-Signature-256"] = "sha256=" + "0" * 64
    assert app_client.post(WHATSAPP_URL, content=raw, headers=forged).status_code == 403

    # A signature made with someone else's app secret must not verify either.
    wrong_secret = dict(_whatsapp_signature(raw, secret="someone-elses-app-secret"))
    assert app_client.post(WHATSAPP_URL, content=raw, headers=wrong_secret).status_code == 403


def test_whatsapp_fails_closed_when_not_configured(app_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "whatsapp_app_secret", "")
    raw = json.dumps(_whatsapp_payload()).encode()
    resp = app_client.post(WHATSAPP_URL, content=raw, headers=_whatsapp_signature(raw))
    assert resp.status_code == 503 and "SENTIVRA_WHATSAPP_APP_SECRET" in resp.json()["detail"]


def test_whatsapp_message_is_stored_redacted_and_status_updates_are_counted(app_client, monkeypatch):
    _use_whatsapp(monkeypatch)
    raw = json.dumps(_whatsapp_payload(message_id="wamid.STORED-1")).encode()
    resp = app_client.post(WHATSAPP_URL, content=raw, headers=_whatsapp_signature(raw))
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 1 and body["ignored"] == 1  # the delivery receipt is not an event

    stored = app_client.get(f"/api/v1/events/{body['event_ids'][0]}").json()
    assert stored["event_type"] == "whatsapp_message" and stored["source_type"] == "LIVE"
    assert stored["content"]["sender"] == "Ava (15557654321)"
    assert stored["content"]["body"] is None and stored["content"]["urls"]
    assert stored["metadata"]["display_phone_number"] == "15551234567"
    assert stored["metadata"]["body_retained"] is False
    assert len(stored["metadata"]["content_sha256"]) == 64


def test_whatsapp_statuses_only_payload_creates_no_event(app_client, monkeypatch):
    _use_whatsapp(monkeypatch)
    payload = _whatsapp_payload()
    value = payload["entry"][0]["changes"][0]["value"]
    value.pop("messages")
    raw = json.dumps(payload).encode()
    resp = app_client.post(WHATSAPP_URL, content=raw, headers=_whatsapp_signature(raw))
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 0 and resp.json()["ignored"] == 1
    assert "nothing to analyze" in resp.json()["note"]


# ---- Gmail -------------------------------------------------------------------

def test_gmail_rejects_a_push_with_no_credentials_at_all(anon_client, monkeypatch):
    _clear_gmail(monkeypatch)
    # A client without any Authorization header at all (the authenticated
    # dashboard fixture would send its own SENTIVRA bearer token, which this
    # route must never mistake for Google's).
    resp = anon_client.post(GMAIL_URL, json=_pubsub_push())
    assert resp.status_code == 403 and "Missing credentials" in resp.json()["detail"]


def test_gmail_rejects_a_forged_or_foreign_algorithm_jwt(app_client, monkeypatch):
    _clear_gmail(monkeypatch)
    _patch_jwks(monkeypatch)

    # Signed with the right key but the wrong algorithm: rejected before any
    # key is even fetched.
    hs256 = pyjwt.encode({"iss": "https://accounts.google.com", "aud": "x",
                          "iat": int(time.time()), "exp": int(time.time()) + 60},
                         "insecure-shared-secret-used-only-by-this-test", algorithm="HS256")
    resp = app_client.post(GMAIL_URL, json=_pubsub_push(), headers={"Authorization": f"Bearer {hs256}"})
    assert resp.status_code == 403 and "RS256" in resp.json()["detail"]

    # A token minted by a stranger (our test key, wrong issuer).
    stranger = _push_token(iss="https://accounts.google.com.evil.example")
    resp = app_client.post(GMAIL_URL, json=_pubsub_push(), headers={"Authorization": f"Bearer {stranger}"})
    assert resp.status_code == 403 and "issuer" in resp.json()["detail"]


def test_gmail_rejects_an_expired_jwt(app_client, monkeypatch):
    _clear_gmail(monkeypatch)
    _patch_jwks(monkeypatch)
    stale = _push_token(iat=int(time.time()) - 7200, exp=int(time.time()) - 3600)
    resp = app_client.post(GMAIL_URL, json=_pubsub_push(), headers={"Authorization": f"Bearer {stale}"})
    assert resp.status_code == 403


def test_gmail_verified_push_without_read_credentials_answers_503(app_client, monkeypatch):
    # Authenticated, but nothing can read the mailbox: say so, and let Pub/Sub
    # retry rather than acknowledging a notification we never processed.
    _clear_gmail(monkeypatch)
    _patch_jwks(monkeypatch)
    resp = app_client.post(GMAIL_URL, json=_pubsub_push(),
                           headers={"Authorization": f"Bearer {_push_token()}"})
    assert resp.status_code == 503
    assert "SENTIVRA_GMAIL_OAUTH_REFRESH_TOKEN" in resp.json()["detail"]


def test_gmail_accepts_a_manual_push_with_the_configured_verification_token(app_client, monkeypatch):
    _use_gmail(monkeypatch, verification_token=GMAIL_VERIFY_TOKEN)
    _patch_gmail_client(monkeypatch)

    wrong = app_client.post(GMAIL_URL, json=_pubsub_push(), params={"verify_token": "nope"})
    assert wrong.status_code == 403

    ok = app_client.post(GMAIL_URL, json=_pubsub_push(), params={"verify_token": GMAIL_VERIFY_TOKEN})
    assert ok.status_code == 200 and ok.json()["accepted"] == 1


def test_gmail_message_is_read_normalized_and_redacted(app_client, monkeypatch):
    _use_gmail(monkeypatch)
    _patch_jwks(monkeypatch)
    _patch_gmail_client(monkeypatch, messages=[_gmail_message("msg-42")])

    resp = app_client.post(GMAIL_URL, json=_pubsub_push(),
                           headers={"Authorization": f"Bearer {_push_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 1 and body["duplicates"] == 0

    stored = app_client.get(f"/api/v1/events/{body['event_ids'][0]}").json()
    assert stored["event_type"] == "gmail_message" and stored["source"] == "gmail"
    assert stored["content"]["subject"] == "Urgent: password reset"
    assert stored["content"]["sender"] == "security@paypa1.example"
    assert stored["content"]["recipients"] == ["soc@example.com"]
    assert stored["content"]["urls"] == ["http://evil.example/reset"]
    # Headers: the allowlist kept, the rest dropped, body hashed not stored.
    assert set(stored["content"]["headers"]) == {"from", "to", "subject", "message-id", "x-mailer"}
    assert stored["content"]["body"] is None
    assert stored["metadata"]["mailbox"] == "soc@example.com"
    assert stored["metadata"]["history_id"] == "987654321"
    assert stored["metadata"]["body_retained"] is False
    # Attachment metadata only — the PDF bytes were never fetched.
    assert stored["attachments"][0]["filename"] == "invoice.pdf"
    assert stored["attachments"][0]["size_bytes"] == 1234
    assert stored["attachments"][0]["sha256"] is None

    # The same push again is the same event, not a second copy.
    again = app_client.post(GMAIL_URL, json=_pubsub_push(),
                            headers={"Authorization": f"Bearer {_push_token()}"})
    assert again.json()["accepted"] == 0 and again.json()["duplicates"] == 1


async def test_google_push_jwt_unit_checks(monkeypatch):
    from app.security.webhooks import WebhookAuthError, verify_google_push_jwt

    _patch_jwks(monkeypatch)
    claims = await verify_google_push_jwt(_push_token())
    assert claims["iss"] == "https://accounts.google.com" and claims["aud"]

    with pytest.raises(WebhookAuthError) as wrong_kid:
        await verify_google_push_jwt(_push_token(kid="unknown-key-id"))
    # An unknown key id falls back to the certificate set, not to acceptance.
    assert wrong_kid.value.transient is True

    with pytest.raises(WebhookAuthError) as missing_claim:
        await verify_google_push_jwt("not.a.jwt")
    assert missing_claim.value.transient is False


# ---- status reporting --------------------------------------------------------

def test_integrations_status_reports_configured_receiving_and_missing(app_client, monkeypatch):
    from app.services.event_repository import EventRepository

    items = {i["name"]: i for i in app_client.get("/api/v1/integrations").json()}
    for name in ("Gmail", "Telegram", "WhatsApp Business"):
        assert items[name]["status"] == "Not configured", name
        assert "SENTIVRA_" in items[name]["detail"]
        assert items[name]["kind"] == "messaging"

    _use_gmail(monkeypatch)
    _use_telegram(monkeypatch)
    _use_whatsapp(monkeypatch)

    monkeypatch.setattr(EventRepository, "count_by_source", lambda self, source: 0)
    items = {i["name"]: i for i in app_client.get("/api/v1/integrations").json()}
    for name in ("Gmail", "Telegram", "WhatsApp Business"):
        assert items[name]["status"] == "Available", name
        assert "no messages received yet" in items[name]["detail"]

    monkeypatch.setattr(EventRepository, "count_by_source", lambda self, source: 7)
    items = {i["name"]: i for i in app_client.get("/api/v1/integrations").json()}
    for name in ("Gmail", "Telegram", "WhatsApp Business"):
        assert items[name]["status"] == "Connected", name
        assert "7 message event(s) stored" in items[name]["detail"]


def test_a_delivered_message_moves_the_connector_to_connected(app_client, monkeypatch):
    secret = _use_telegram(monkeypatch)
    app_client.post(TELEGRAM_URL, json=_telegram_update(77),
                    headers={"X-Telegram-Bot-Api-Secret-Token": secret})
    items = {i["name"]: i for i in app_client.get("/api/v1/integrations").json()}
    assert items["Telegram"]["status"] == "Connected"
    assert "message event(s) stored" in items["Telegram"]["detail"]
