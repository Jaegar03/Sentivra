# SENTIVRA Threat Model

**Scope:** this document models threats *against Sentivra itself* (it is a security product; it must not become the incident it's meant to detect) and states, per detection capability, what Sentivra can and cannot actually catch. Written before implementation per the mandated Phase 1 order.

Methodology: STRIDE per trust boundary, plus an explicit "what this does NOT detect" section per detector — because an unstated detection gap is itself a false sense of security, and this project's quality bar (brief §32–33) forbids overclaiming.

---

## 1. Trust Boundaries

```
[Untrusted: Internet]
   │  Gmail Pub/Sub push │ Telegram webhook │ WhatsApp webhook │ public demo endpoints
   ▼
[Boundary A — Ingress]  ──────────────────────────────────────────
   │  body-size limit → rate limit → OAuth2 bearer token + scope → FastAPI handlers
   │  (webhooks, when built: provider signature verification instead of a bearer token)
   ▼
[Trusted-but-limited: Sentivra backend process]
   │  detectors, risk engine, ML inference
   ▼
[Boundary B — Persistence]  ────────────────────────────────────
   │  SQLAlchemy → SQLite
   ▼
[Trusted: local data store]

[Boundary C — Model supply chain]
   research/ (training) ──► models/ (registry, SHA-256 pinned) ──► ModelLoader (backend)

[Boundary D — Optional native engines]
   Sentivra backend ──(subprocess/socket, local only)──► Suricata / Zeek / ClamAV / YARA
```

---

## 2. STRIDE by Boundary

### Boundary A — Ingress (webhooks, file upload, analyze API)

| Threat | STRIDE | Mitigation | Where enforced |
|---|---|---|---|
| Forged webhook claiming to be Meta/Telegram | Spoofing | HMAC-SHA256 verification over raw body (WhatsApp `X-Hub-Signature-256`), Telegram secret-token header check | `backend/app/security/webhooks.py`, per-integration `webhook.py` |
| Replayed/old webhook payload | Spoofing/Tampering | Timestamp/nonce freshness check where the provider supplies one; idempotent event_id dedup at the repository layer | `EventRepository.create_if_absent` |
| Unauthenticated use of the API (reading alerts, running analyses, changing alert status) | Spoofing/Info disclosure/EoP | OAuth2 client-credentials. Every `/api/` route needs a bearer token except the token endpoint and the liveness probe. A test walks the OpenAPI schema and fails on any route that answers without a token | `backend/app/security/auth.py`, `backend/tests/test_auth.py` |
| A compromised or over-trusted client doing more than its job | EoP | Per-route scopes (`read`, `analyze`, `ingest`, `alerts:write`). An ingest-only agent can't read alerts back. Scopes are re-checked against the client's configuration on every request | `backend/app/security/auth.py` |
| Forged or tampered token (`alg: none`, re-signed, edited scope claim) | Spoofing/Tampering | HS256 with the algorithm pinned at verification; `exp`, `iat`, `iss` and `sub` required; tokens for unknown clients rejected | `backend/app/security/auth.py` |
| Signing key that anyone can read (the old default, or the `.env.example` placeholder copied as-is) | Spoofing | Unset, repo-published and too-short (< 256-bit) keys are never used. Development generates a random per-install key in `.sentivra/`; other environments refuse to start | `backend/app/core/config.py`, `backend/app/security/auth.py` |
| Guessing or enumerating client secrets | Spoofing | 256-bit random secrets, stored only as SHA-256 hashes and compared in constant time; unknown IDs are compared against a dummy hash too, and wrong-ID and wrong-secret get the same response; the token endpoint has its own 10/min per-IP budget | `backend/app/security/auth.py`, `backend/app/api/auth.py`, `backend/app/security/rate_limit.py` |
| Cross-site request forgery from a page the operator visits | Tampering | Tokens travel in the `Authorization` header, never in cookies, so the browser doesn't attach them to cross-site requests; CORS never allows credentials | `backend/app/main.py`, `frontend/lib/api.ts` |
| Script injection in the dashboard stealing the stored token | Info disclosure | React escaping (no raw HTML from data); the token is in `sessionStorage` (per tab, gone when the tab closes), never `localStorage`, and the secret is never stored; the dashboard's CSP `connect-src`/`img-src` allow only its own origin and the API, so injected code can't `fetch` or beacon the token elsewhere (verified in a browser) | `frontend/lib/auth.ts`, `frontend/next.config.ts` |
| Oversized request body, including chunked bodies with no `Content-Length` | DoS | Limits are enforced while the body is received, before parsing: 1 MB for JSON, the upload cap plus multipart framing on the four upload routes. A declared oversize gets `413` before any read | `backend/app/security/body_limit.py` |
| Decompression-bomb file upload | DoS | Nested-archive depth, entry-count and uncompressed-size limits | `backend/app/security/uploads.py` |
| SSRF via a URL-analysis request fetching attacker-controlled internal address | Tampering/Info disclosure | `URLDetector`/any outbound fetch goes through an SSRF-guarded HTTP client: DNS-resolves and rejects RFC1918/loopback/link-local targets before connecting, no redirects followed blindly | `backend/app/security/ssrf_guard.py` |
| Path traversal via filename in upload/attachment metadata | Tampering | SENTIVRA never writes an upload to a path of its own choosing, let alone one derived from the filename. Bytes are analyzed in memory and discarded, and the original filename is kept only as metadata. (The multipart parser spools parts over 1 MB to an anonymous OS temporary file for the life of the request; its name is never derived from input) | `backend/app/api/analyze.py`, `backend/app/security/uploads.py` |
| Upload content lingering on disk | Info disclosure | Starlette spools multipart parts over 1 MB to an anonymous temporary file: unlinked at creation on POSIX, delete-on-close on Windows, gone when the request ends. It is never retained, but it does reach the temp filesystem, so deployments mount a memory-backed `/tmp` ([future-deployment.md](future-deployment.md) §5) | Starlette `MultiPartParser` (`spool_max_size`) |
| Command/argument injection when shelling out to Suricata/ClamAV/YARA CLI | Tampering/EoP | No shell=True, argument lists only, no user input concatenated into a command string; engine subprocess run with minimal env | `backend/app/detectors/{yara,clamav}_detector.py` |
| Abusive request volume against `/analyze/*` or webhooks | DoS | Per-IP rate limiting at the ASGI layer (300/min for the API, 10/min for the token endpoint; `429` with `Retry-After`) | `backend/app/security/rate_limit.py` |
| Cross-origin misuse of the API from an unintended web origin | Tampering | Explicit CORS allowlist, never a wildcard; credentials never allowed; only `Authorization` and `Content-Type` request headers | `backend/app/core/config.py`, `backend/app/main.py` |
| API responses cached, framed or rendered as a page | Info disclosure | `Cache-Control: no-store` and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on every API response, plus `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`; interactive docs only in development | `backend/app/security/headers.py`, `backend/app/main.py` |
| Malicious file executed accidentally during analysis | EoP | Files are **never executed** — only parsed (hash/magic-bytes/MIME/static structure); no sandboxed detonation in this phase | `backend/app/detectors/malware_detector.py` |

#### Boundary A: what the API hardening does not cover yet

These are known gaps in this build, not solved problems. [future-deployment.md](future-deployment.md) §3 lists the change that closes each deployment-related one:

- **No TLS in the app.** The backend serves plain HTTP on localhost. Any deployment beyond localhost must terminate TLS in front of it; bearer tokens and client secrets must never cross a network in clear text.
- **No per-token revocation.** A leaked token stays valid until it expires (default 1 hour). The levers are:
  - remove the client, or rotate its secret, and restart;
  - rotate `SENTIVRA_SECRET_KEY` (or delete `.sentivra/signing.key`), which invalidates every token at once.
- **Rate limits live in one process.** Buckets are kept in memory: they reset on restart and aren't shared between workers.
- **`X-Forwarded-For` is ignored.** That's deliberate, since an unauthenticated header can't be trusted. The consequence is that behind a reverse proxy, every client shares the proxy's per-IP bucket.
- **Clients, not people.** There are no user accounts or roles. Whoever holds the `dashboard` secret has all four scopes, and the audit log records the client ID, not a person.
- **The development bootstrap prints a secret to the log.** The first-start `dashboard` secret appears once in the backend's log output. Anyone who can read that log can use it. Outside development there's no bootstrap: clients must be configured explicitly.
- **The dashboard's CSP allows inline scripts.** Statically rendered Next.js pages inline their RSC payload, so `script-src` includes `'unsafe-inline'`. The policy's value is in `connect-src`, `img-src`, `frame-ancestors`, `base-uri` and `object-src`, not in blocking injected script outright. A nonce-based policy would need every page rendered per request.
- **Webhook ingress doesn't exist yet.** Gmail, Telegram and WhatsApp will authenticate with provider signatures rather than bearer tokens. Their threats are listed in §3, but those mitigations are designs, not code, until Phase 7. The WhatsApp HMAC helper exists and is unit-tested.

### Boundary B — Persistence

| Threat | STRIDE | Mitigation |
|---|---|---|
| SQL injection into Sentivra's own SQLite via crafted event content | Tampering | SQLAlchemy ORM/parameterized queries exclusively — no raw string-formatted SQL, anywhere, including in the `SQLInjectionDetector`'s own test harness |
| Sensitive raw content (email body, file bytes) retained indefinitely, becoming a high-value breach target | Info disclosure | Files: hash + metadata + result stored, not raw bytes, by default (brief §30). Message bodies: retained only as long as documented per-integration in `docs/privacy.md`, with a configurable retention window |
| Local DB file readable by other local users/processes | Info disclosure | Documented OS-level file-permission guidance in deployment docs; out of scope to enforce cross-platform from the app itself in this phase — stated as a known limitation, not silently ignored |
| Audit log tampering (an attacker who gains code-execution rewrites history) | Repudiation | Audit log is append-only at the ORM level (no update/delete API exposed for `audit_log` rows); full compromise of the host defeats this — documented as a limitation, not claimed as tamper-proof |

### Boundary C — Model Supply Chain

| Threat | STRIDE | Mitigation |
|---|---|---|
| Malicious pickle/joblib model achieving code execution on load | EoP (critical) | `ModelLoader` only loads artifacts from `models/` whose SHA-256 matches the pinned hash in that model's own `metadata.json`, both committed together; no runtime path ever loads a model from an upload, a URL, or any user-writable location |
| Model swapped for a backdoored one that still passes hash check (attacker with repo write access replaces both file and metadata together) | Tampering | Out of scope for the application layer — this is a source-control / CI integrity problem, mitigated by normal code-review and branch-protection practice, stated explicitly as a limitation rather than solved in-app |
| Adversarial input crafted to evade a specific classifier (e.g., an obfuscated prompt injection that evades the ONNX classifier) | Tampering (evasion) | This is why no detector is ML-only (brief §8/§9) — pattern/heuristic/entropy layers catch what a single evaded classifier misses; documented per-detector limitation below, not claimed as solved |
| Training data poisoning in a future retraining pipeline | Tampering | `research/` enforces TRAIN/CALIBRATION/TEST separation and documents dataset provenance (brief §28); poisoning of *public* upstream datasets (e.g. CIC-IDS2017) is a known, stated limitation, not something Sentivra can detect |

### Boundary D — Optional Native Engines (Suricata/Zeek/ClamAV/YARA)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Engine not installed reported as "ran clean" instead of "not configured" | Info disclosure (false assurance) | Availability probe at startup (`is_available()`) is authoritative; `Not Configured` is a distinct, always-surfaced state from `Available + no findings` (brief §32) |
| Malformed input crashing/exploiting the native engine (these engines process untrusted bytes by design) | DoS/EoP | Engines invoked as isolated local subprocesses with resource/time limits, never with elevated privileges beyond what the demo requires; this is a known, industry-wide attack surface for any AV/IDS engine — mitigated by process isolation, not eliminated |
| ClamAV/YARA signature databases stale, producing false negatives | Info disclosure (false assurance) | Engine version + signature DB timestamp surfaced in `GET /api/v1/detectors`, not hidden |

---

## 3. Integration-Specific Threats

### Gmail
- **Threat:** Over-scoped OAuth grant lets Sentivra (or an attacker who compromises it) send email or modify the mailbox. **Mitigation:** `gmail.readonly` only, enforced at the OAuth consent/token-request layer (brief §13).
- **Threat:** Stolen OAuth refresh token gives long-lived mailbox read access. **Mitigation:** token stored via the standard credential-handling path (env-var-sourced secret store in this phase, never committed/logged), documented rotation guidance.
- **Threat:** Sentivra's own Pub/Sub webhook endpoint spoofed to inject fake "new mail" events. **Mitigation:** Pub/Sub push messages are JWT-verified against Google's published certs before any event is normalized.

### Telegram
- **Threat:** Someone assumes the bot sees all of a user's private Telegram traffic. **Mitigation:** documented explicitly, in-product and in `docs/privacy.md`, that the Bot API only ever sees messages sent directly to the bot or in groups/channels it is a member of — never arbitrary private chats (brief §14).
- **Threat:** Webhook endpoint hit by non-Telegram traffic. **Mitigation:** Telegram's `secret_token` webhook header checked on every request.

### WhatsApp Business
- **Threat:** Webhook forged without a valid app secret. **Mitigation:** HMAC-SHA256 over the raw request body against `X-Hub-Signature-256`, computed with `hmac.compare_digest` (timing-safe), before any parsing occurs.
- **Threat:** Media retrieval used to exfiltrate arbitrary attacker-hosted URLs. **Mitigation:** media is only ever fetched via Meta's authenticated media-ID endpoint, never an arbitrary URL from the payload — closes the same SSRF class as Boundary A.

---

## 4. What Each Detector Does NOT Catch (Stated Limitations)

This section exists because brief §32/§33/§38 forbid overclaiming. Every detector below is genuinely useful and independently evaluated — none of them are complete.

- **`SQLInjectionDetector`**: tuned for common injection syntax in HTTP-adjacent text inputs; not a full SQL parser for every dialect, and a sufficiently novel obfuscation (e.g., second-order injection assembled server-side from two separately-benign-looking inputs) will not be caught by single-input analysis.
- **`PromptInjectionDetector`**: catches known jailbreak/override patterns, common encoding tricks, and statistically-similar-to-training-data attacks; a genuinely novel injection phrasing with no lexical/semantic overlap to anything in its training/pattern set can evade it — this is an active-research problem industry-wide, not unique to Sentivra.
- **`PhishingDetector` / `URLDetector`**: lexical/structural/reputation-based; a phishing page hosted on a freshly-registered but structurally "clean-looking" domain with no reputation history yet will score lower — freshness/reputation data is only as good as what's available without paid threat-intel feeds in this phase.
- **`MalwareDetector`**: static analysis only (no dynamic detonation/sandboxing in this phase) — a file that is benign until executed with a specific runtime trigger, or that relies on fetching a second-stage payload at runtime, will not be caught by static inspection alone.
- **`NetworkAnomalyDetector`**: Isolation Forest/Autoencoder are trained on the reference datasets documented in `docs/model-card.md` (e.g. CIC-IDS2017/UNSW-NB15-style flow features); traffic patterns far outside that training distribution (a genuinely novel attack class, or an environment with very different baseline behavior) will have degraded accuracy — this is explicitly why signature detection (Suricata) is a parallel layer, not a fallback.
- **`BehavioralAnomalyDetector`**: operates on *simulated* endpoint telemetry in this phase (brief §12) — it demonstrates the detection logic, not real production endpoint coverage; a real deployment requires the future native agent.
- **`SigmaDetector` / `LogDetector`**: only as good as the rules loaded in `detection-rules/sigma/`; an attack technique with no corresponding rule produces no alert. Coverage is a stated, visible property (which rule packs are loaded), not assumed to be complete.

---

## 5. Explicitly Out of Scope (This Phase)

- Dynamic/behavioral malware detonation (no sandbox execution of uploaded files — brief §7, §38: "never execute uploaded files").
- Real-time full-packet network capture on production infrastructure (PCAP analysis is demo-upload-driven, brief §26).
- Autonomous remediation of any kind (brief §36) — Sentivra only ever detects and surfaces; a human acts. The future design, with its approval gate and guardrails, is in [future-automation.md](future-automation.md).
- Multi-tenant isolation hardening — this phase assumes a single operator/demo context; multi-tenant security boundaries are future work.
- Decryption or unofficial access to WhatsApp/Telegram private data (brief §12, §14, §15) — explicitly refused as out of scope, not a gap.
