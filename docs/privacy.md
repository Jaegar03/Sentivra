# SENTIVRA Data Handling — Per Integration

**Status:** written with the Phase 7 connectors (README principle 4: *raw file bytes and message bodies are not retained by default — hash + metadata + result are*).

The rule this document describes, in one line: **detectors see the content, storage keeps the evidence.**

---

## 1. What happens to a message that arrives over a webhook

Every connector — Gmail, Telegram, WhatsApp — follows the same four steps:

1. **Verify first.** The request is authenticated with the provider's own proof (Google's push JWT, Telegram's `secret_token`, Meta's HMAC signature) before the body is parsed. An unverified request never becomes an event. See [api.md § Webhooks](api.md#webhooks).
2. **Normalize.** The provider payload becomes one `SecurityEvent` (`app/integrations/<provider>/normalizer.py`). The full body exists in process memory for the duration of the request.
3. **Analyze.** The shared pipeline runs every detector that applies to that event type on the full body, in memory.
4. **Persist redacted.** The event written to SQLite has `content.body = null` and instead carries:
   - `metadata.content_sha256` — SHA-256 of the body that was analyzed;
   - `metadata.content_chars` — its length;
   - `metadata.body_retained = false` — the explicit statement that no text was kept.

   What *is* kept: subject, sender, recipients, extracted URLs (indicators, not prose), attachment metadata (filename / type / size / provider hash), timestamp, chat or mailbox identifiers, and the header allowlist for email.

Nothing is logged: connector logs record counts and outcomes, never message text.

**Why hashes instead of text.** The hash lets an analyst confirm that a message they still possess is the one SENTIVRA saw, without SENTIVRA holding a copy. It cannot be reversed into the message.

**Alerts and evidence.** When a detector fires, its `DetectionResult` may quote a short excerpt as evidence. That is part of the finding — the result — not a second copy of the message, and it is what explains the verdict on the alert.

**Deletion.** Everything lives in the local database file (`sentivra.db` by default). Deleting an event or alert row deletes SENTIVRA's copy; there is no other store, cache or export. The audit log is append-only by design and records that an analysis happened (event id, actor, severity), not what the message said.

---

## 2. Gmail

| | |
|---|---|
| **What arrives on the webhook** | A Cloud Pub/Sub notification: the mailbox address and a `historyId`. **No mail content** is in the push. |
| **What SENTIVRA reads** | Only what the notification points at: `users.history.list` (or, as a fallback, the newest messages), capped at **5 messages per push**, then `users.messages.get` for each. |
| **Scope** | `https://www.googleapis.com/auth/gmail.readonly` — and only that. Nothing in SENTIVRA ever requests `gmail.modify`, `gmail.send` or any write scope, so a compromised connector still cannot move, delete or send mail. |
| **Honest limitation** | `gmail.readonly` *technically* authorizes reading the whole mailbox. The connector does not use that: it never exports, bulk-lists or downloads a mailbox, only the messages the watch notification reports, and only when a verified push asks for them. |
| **Attachment bytes** | Never fetched. Recorded as filename, MIME type and size (`sha256: null` because SENTIVRA never saw the bytes to hash). |
| **Headers kept** | `from`, `to`, `cc`, `reply-to`, `return-path`, `subject`, `date`, `message-id`, `list-unsubscribe`, `authentication-results`, `x-originating-ip`, `x-mailer` — sender/recipient context plus the authentication trail a phishing verdict will later lean on. Everything else (Received chains, bulk headers) is not copied out of the mail. |
| **Credentials** | Client id, client secret and refresh token come from the environment. Access tokens are cached in process memory only, never written to disk or returned by any API. |
| **Verification** | The push JWT is verified against Google's published certificates before parsing; a configured `SENTIVRA_GMAIL_PUBSUB_VERIFICATION_TOKEN` is an additional, constant-time-compared shared secret for manual test pushes. |
| **The bot/connector can't** | Send, delete, label, mark or modify anything — no scope for it exists in this codebase. |

---

## 3. Telegram

| | |
|---|---|
| **What arrives** | Only what the Bot API delivers to the bot: messages sent directly to it, and messages in chats/channels the bot was added to. |
| **What SENTIVRA can never see** | Arbitrary private conversations between other people. The Bot API has no such access, SENTIVRA does not ask for any, and the product says so in-product (brief §14). |
| **Attachment bytes** | Never downloaded. Photo / document / audio / video entries are recorded as filename, MIME type and size only. |
| **What is stored** | Sender (`@username` or display name), `user_id`, chat id and type, timestamp, message id, forwarded-from when Telegram reports one, extracted URLs, and — as with every connector — the body hash rather than the body. |
| **Verification** | `X-Telegram-Bot-Api-Secret-Token` must equal the `secret_token` chosen at `setWebhook`, compared in constant time. The webhook endpoint answers nothing else. |
| **The bot does** | Receive. SENTIVRA never calls `sendMessage`, never joins a chat on its own and never reads update kinds it doesn't need (`callback_query`, inline results and membership changes are counted as `ignored`). |

---

## 4. WhatsApp Business

| | |
|---|---|
| **What arrives** | Cloud API webhook payloads for the `messages` field, signed by Meta. |
| **Data path** | Meta's official Cloud API, **direct** — no third-party proxy or intermediary ever sees the payload (repository-analysis §9). |
| **Attachment bytes** | Never fetched. A media message records its MIME type, filename (documents), WhatsApp's media id and Meta's own SHA-256 when present (converted from base64 to hex). |
| **What is stored** | Sender (`wa_id`, plus Meta's contact profile name), the business number the message was addressed to, `phone_number_id`, timestamp, message id, type, extracted URLs, and the body hash. Location and reaction payloads are kept as structured metadata. |
| **Statuses** | Delivery/read receipts are counted as `ignored` and produce no event — SENTIVRA has no use for read receipts and keeps none. |
| **Verification** | `X-Hub-Signature-256`, HMAC-SHA256 of the raw body with the App Secret, compared in constant time before parsing. The subscription handshake (`GET`) echoes Meta's challenge only when the verify token matches. |
| **The connector does** | Receive. It never sends messages, never calls the Messages API, and never fetches media. `SENTIVRA_WHATSAPP_ACCESS_TOKEN` / `PHONE_NUMBER_ID` are stored for completeness of the connector's configuration and are not used on the ingest path. |

---

## 5. Before you connect anything

- The connectors are inert until their credentials are set: each one answers `503 Not configured` and `GET /api/v1/integrations` names the missing variables. Nothing is "connected" because a variable is half-filled.
- Keep the backend on `localhost` until you deliberately expose it — webhooks need a public HTTPS URL, and that is a deployment decision documented in [future-deployment.md](future-deployment.md).
- You can exercise every verification path locally without any provider: the Gmail `verify_token` push, a Telegram `setWebhook`-style curl, and a locally HMAC-signed WhatsApp body. See [api.md § Webhooks](api.md#webhooks).

## 6. Known limits, stated rather than glossed

- **No re-analysis from storage.** Because bodies are not retained, a detector added later cannot be run over old messages. That is the trade the privacy rule makes deliberately: the hash proves *which* message, not *what* it said.
- **No message-content verdicts yet.** The phishing, URL and prompt-injection detectors are Phase 4. Until they land, a webhook response reports `detectors: []` and says no verdict was produced — it never reports a clean result for analysis that didn't happen.
- **URLs are stored.** Extracted URLs are indicators an analyst needs; they are literal strings copied from the message and are kept alongside the hash rather than hashed themselves.
