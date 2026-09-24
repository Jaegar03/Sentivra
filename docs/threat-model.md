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
   │  FastAPI request handlers, webhook signature verification
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
| Oversized or decompression-bomb file upload | DoS | Hard upload size cap, nested-archive depth/size limits, streaming hash computation before full extraction | `backend/app/security/uploads.py` |
| SSRF via a URL-analysis request fetching attacker-controlled internal address | Tampering/Info disclosure | `URLDetector`/any outbound fetch goes through an SSRF-guarded HTTP client: DNS-resolves and rejects RFC1918/loopback/link-local targets before connecting, no redirects followed blindly | `backend/app/security/ssrf_guard.py` |
| Path traversal via filename in upload/attachment metadata | Tampering | Filenames never used as filesystem paths directly; storage keyed by SHA-256, original name kept as metadata only | `backend/app/services/file_storage.py` |
| Command/argument injection when shelling out to Suricata/ClamAV/YARA CLI | Tampering/EoP | No shell=True, argument lists only, no user input concatenated into a command string; engine subprocess run with minimal env | `backend/app/detectors/{yara,clamav}_detector.py` |
| Abusive request volume against `/analyze/*` or webhooks | DoS | Rate limiting (per-IP and per-API-key) at the ASGI middleware layer | `backend/app/security/rate_limit.py` |
| Cross-origin misuse of the API from an unintended web origin | Tampering | Explicit CORS allowlist, no wildcard `*` with credentials | `backend/app/core/config.py` |
| Malicious file executed accidentally during analysis | EoP | Files are **never executed** — only parsed (hash/magic-bytes/MIME/static structure); no sandboxed detonation in this phase | `backend/app/detectors/malware_detector.py` |

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
- Autonomous remediation of any kind (brief §36) — Sentivra only ever detects and surfaces; a human acts.
- Multi-tenant isolation hardening — this phase assumes a single operator/demo context; multi-tenant security boundaries are future work.
- Decryption or unofficial access to WhatsApp/Telegram private data (brief §12, §14, §15) — explicitly refused as out of scope, not a gap.
