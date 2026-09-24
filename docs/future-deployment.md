# SENTIVRA: Future Deployment Architecture

**Status: design only.** Nothing in this document is implemented. The repository contains no Dockerfile, compose file or Kubernetes manifest, and none should be added until someone explicitly asks for one (brief §35). SENTIVRA runs today as two local processes, `uvicorn` and `next start`, and must keep running that way.

This document covers three things:
- what the current build already does that makes containers straightforward;
- what would break if it were split across processes or hosts, and what has to change first;
- the staged target architecture, and when each stage is worth its cost.

Every claim about the current code was checked against the source; file references are given so they can be re-checked.

The build isn't feature-complete. The Phase 4 detectors (SQL injection, phishing/URL and prompt injection) aren't wired, and the Phase 7 connectors (Gmail, Telegram, WhatsApp) don't exist. The brief puts this document "only after the above works", so treat it as the plan for when they do. Nothing here should be read as a reason to deploy the current build beyond localhost.

---

## 1. The current build, as deployed today

| Component | Today | State it holds |
|---|---|---|
| Backend | One `uvicorn app.main:app` process: FastAPI, every detector in-process, ONNX Runtime and LightGBM in the same process | See [§1.1](#11-state-that-lives-in-process-memory) |
| Dashboard | Next.js 16 (`next start`); the browser calls the backend directly | None server-side. The access token lives in the browser tab's `sessionStorage` |
| Database | SQLite file (`sentivra.db` at the repo root) through SQLAlchemy. Tables are created by `Base.metadata.create_all` at startup; there are no migrations | Events, alerts, audit log |
| Models | Read-only files under `models/`, each pinned by SHA-256 in its `metadata.json` and verified by `ModelLoader` before load | None (immutable) |
| Rules | `detection-rules/` (YARA, Sigma, custom YAML, ATT&CK index), loaded at startup | None (immutable) |
| YARA | In-process via `yara-python` | — |
| ClamAV | Optional. `clamd` over a Unix socket (`SENTIVRA_CLAMD_SOCKET`) or TCP (`SENTIVRA_CLAMD_HOST`/`_PORT`); reports `Not configured` when unreachable | — |
| Suricata, Zeek | **Not integrated.** The settings exist, but nothing reads EVE or Zeek logs; the API reports both as `Not implemented` | — |
| Local state | `.sentivra/`: development-only signing key and client-secret hashes | Written once, at first start |

### 1.1 State that lives in process memory

These pieces are correct for one process and are the first things to revisit when there are several:

| Where | What | Consequence with more than one process |
|---|---|---|
| `app/security/rate_limit.py` | Sliding-window buckets per client IP (API and token endpoint) | Each process has its own buckets: N workers allow N× the budget, and a restart clears them |
| `app/services/file_blob_store.py`, `app/services/transient_store.py` (`blob_store`, `flow_batches`, `event_batches`) | Request-scoped handoff: the API puts uploaded bytes or parsed batches here, detectors look them up by key, and the entry is discarded when the request ends. This is how raw content reaches detectors without ever being persisted (brief §30) | Safe across `uvicorn --workers`, because a request stays in one process. It stops working as soon as detection runs somewhere other than the process that received the upload (a worker or an inference service) |
| `ModelLoader` cache, `get_suite()` | Deserialized models | Every worker loads every model, so memory grows with the worker count |
| `lru_cache` on `get_settings`, `load_clients`, `signing_key` | Configuration read once per process | Config changes need a restart of every process |

---

## 2. What already carries over

These properties were built in on purpose, and a container deployment relies on them:

- **All configuration comes from `SENTIVRA_*` environment variables** (`app/core/config.py`, template in `.env.example`). Relative directory settings resolve against the repo root. In an image, set absolute paths or keep the repo layout.
- **Unsafe production configuration fails at startup.**
  - With `SENTIVRA_ENV` set to anything other than `development`/`dev`/`test`, the backend refuses to start without a real `SENTIVRA_SECRET_KEY` (32+ characters, not a published placeholder) and explicit `SENTIVRA_OAUTH_CLIENTS`.
  - The interactive docs and `/openapi.json` are switched off.
  - An orchestrator therefore sees a crash-looping container, never a running backend with forgeable tokens.
- **With secrets configured, SENTIVRA itself writes nothing to local disk except the database.**
  - `signing_key()` and `load_clients()` only touch `state_dir` when they have to bootstrap, which happens in development only.
  - Uploads are analyzed in memory and never stored.
  - One caveat: Starlette's multipart parser spools any part over 1 MB to an anonymous OS temporary file for the life of the request. The backend can run with a read-only root filesystem **plus a memory-backed `/tmp`**, so upload content never reaches persistent storage.
- **A liveness probe exists without credentials.** `GET /api/v1/health/live` returns `{"status": "ok"}` and nothing else.
- **Models and rules are immutable, hash-verified inputs.** They can be baked into the image or mounted read-only. `ModelLoader`'s SHA-256 check stays the authority either way (threat model, Boundary C).
- **Optional engines report their own absence.** A ClamAV sidecar that isn't up shows `Not configured`, never a clean scan.
- **Request bodies are capped inside the app** (`app/security/body_limit.py`), so a proxy that forgets its own limit doesn't open a memory-exhaustion hole.
- **First-start bootstrap is safe with several workers.** `.sentivra/` files are created atomically with owner-only permissions, and concurrent first starts agree on one key and one client (tested in `tests/test_auth.py`). Production shouldn't rely on the bootstrap at all.
- **Logs go to stdout/stderr** as plain-text Python logging, which is what container runtimes collect. The one secret that is ever logged, the development bootstrap's client secret, can't appear outside development, because the bootstrap refuses to run there.

---

## 3. Changes required before splitting processes or hosts

Listed in the order they should be done. None of them needs Docker, and the first five are worth doing even for a single-host deployment.

| # | Area | Today | Why it matters | Change | Code |
|---|---|---|---|---|---|
| 1 | CPU-bound detection on the event loop | Sigma, host-behavior and authentication rules (batches up to 200,000 rows) and YARA matching run synchronously inside `async def analyze`. Only network scoring is moved to a thread (`asyncio.to_thread`) | A large osquery or log upload stalls every other request until it finishes, including the liveness probe. An orchestrator can then kill a healthy but busy container | Move each synchronous evaluation into `asyncio.to_thread`, as `NetworkAnomalyDetector` already does. Later, move batch uploads to the worker tier (Stage 2) | `app/detectors/{sigma,behavioral_anomaly,log,yara}_detector.py` |
| 2 | Readiness probe | `/api/v1/health` needs the `read` scope; the public probe only proves the process is up | A load balancer can't send traffic only to instances whose database is reachable | Add an unauthenticated readiness route that returns only ready/not-ready (database reachable, detectors registered). Keep detail behind `read` | `app/api/health.py` |
| 3 | Database migrations | `create_all` at startup; no migration history | `create_all` never alters an existing table, so the first schema change after go-live would silently not apply | Add Alembic with a baseline migration of the current schema, and run migrations as a separate step before the backend starts | `app/core/database.py` |
| 4 | PostgreSQL | SQLite. SQLite-specific connect args are already applied only for `sqlite://` URLs | Several processes can't share a SQLite file safely at write volume, and it can't be reached from another host | Add a PostgreSQL driver dependency and run the test suite against PostgreSQL. The audit log is append-only at the ORM level today; on PostgreSQL, also revoke `UPDATE`/`DELETE` on the audit table from the application role | `app/core/database.py`, `app/models/orm.py`, `pyproject.toml` |
| 5 | Client IP behind a proxy | The rate limiter keys on the socket peer address and deliberately ignores `X-Forwarded-For` | Behind a reverse proxy, every client shares the proxy's bucket | Add a trusted-proxy setting (proxy CIDRs). Honour `X-Forwarded-For` only from those addresses, taking the right-most untrusted hop | `app/security/rate_limit.py`, `app/core/config.py` |
| 6 | Dashboard origin | `NEXT_PUBLIC_API_BASE_URL` and the dashboard CSP's `connect-src` are fixed at build time; the API is a separate origin behind CORS | An image built for one environment points at that environment's API only | Serve the dashboard and the API from one origin behind the reverse proxy (`/` to the dashboard, `/api/` to the backend). The API base becomes the page's own origin, `connect-src 'self'` is enough, and CORS is no longer needed | `frontend/next.config.ts`, `frontend/lib/api.ts` |
| 7 | TLS | The backend and dashboard speak plain HTTP | Bearer tokens and client secrets must never cross a network in clear text. Phase 7 webhooks require public HTTPS | Terminate TLS at the reverse proxy or ingress, set HSTS there, and keep backend traffic on an internal network | — |
| 8 | Secrets delivery | Environment variables | Values baked into images or committed files leak | Inject `SENTIVRA_SECRET_KEY`, `SENTIVRA_OAUTH_CLIENTS` and the connector credentials from a secret store at runtime, never at build time. Rotating the signing key invalidates every token (at most 1 hour of re-sign-ins) | — |
| 9 | Request handoff to other processes | `blob_store` / `flow_batches` / `event_batches` in memory ([§1.1](#11-state-that-lives-in-process-memory)) | A worker or inference service can't see the API process's memory | Pass bounded payloads with the job itself. Or use short-lived object storage with encryption, no versioning, a TTL, and deletion when the job finishes, so the "raw content is never retained" rule (brief §30) still holds | `app/services/`, the detectors that read those stores |
| 10 | Rate limits across processes | Per-process memory | See [§1.1](#11-state-that-lives-in-process-memory) | Back `RateLimiter` with Redis behind the same interface. Keep the token endpoint's separate, tighter budget | `app/security/rate_limit.py` |
| 11 | Token verification by other services | HS256: the key that verifies tokens can also sign them | Once a second service (inference, worker) verifies tokens, it would also be able to mint them | Switch to an asymmetric algorithm (EdDSA or RS256). Only the token endpoint holds the private key; other services get the public key | `app/security/auth.py` |

Items 1–8 apply to a single host. Items 9–11 only matter once the process split in Stage 2 happens.

---

## 4. Target architecture, in stages

The brief's future shape is: frontend, backend, ML inference, Redis, worker, PostgreSQL, ClamAV and the other security engines. That's the end state, not the next step. Each stage below lists what triggers it; adding infrastructure without its trigger is the over-engineering the brief warns against (§38).

### Stage 0: today

```
browser ──► next start :3000 (dashboard)
   └──────► uvicorn :8000 (API + all detectors + models) ──► SQLite file
                                             └──(optional)──► clamd
```

### Stage 1: one host, containers

**Trigger:** SENTIVRA has to run on a server that someone other than its developer uses. Also a prerequisite for the Phase 7 connectors, whose webhooks need public HTTPS.

```
internet ──TLS──► reverse proxy ──► dashboard container (/)
                       └──────────► backend container (/api/) ──► PostgreSQL container
                                          └─────────────────────► ClamAV container (clamd :3310)
```

**Code changes:** items 1–8 in §3.

**Unchanged:** detectors, the `SecurityEvent` contract, the risk engine, the model registry and the API.

### Stage 2: split work off the request path

**Triggers:**
- batch uploads take long enough that synchronous responses are unacceptable;
- Phase 7 webhook volume needs queued, retryable processing;
- model memory per API worker becomes the limiting factor.

```
reverse proxy ──► backend (API only) ──► Redis (job queue, rate limits)
                                              │
                                              ▼
                                   worker(s) (detectors) ──► inference service (ONNX Runtime)
                                              │
                                              ▼
                                         PostgreSQL
```

**Code changes:** items 9–11 in §3, plus:
- **Asynchronous job API.** Uploads answer `202 Accepted` with a job ID; the dashboard polls job status.
- **Second model backend.** `ModelLoader` gets a remote implementation, over HTTP or gRPC to the inference service, behind the same interface. `ModelRegistry` and the SHA-256 pinning are unchanged; the inference service does the verification.
- **Worker image.** The worker runs the backend image with a different entrypoint. The detector code is identical.

### Stage 3: several hosts, orchestration, observability

**Trigger:** availability requirements that a single host can't meet, or several teams operating it.

**Adds:**
- Kubernetes (or a managed container platform);
- managed PostgreSQL with backups and point-in-time recovery;
- S3-compatible object storage, only if item 9 chose it, with the retention rules above;
- Prometheus and Grafana.

**Code changes:**
- A `/metrics` endpoint on an internal port only. It exposes counts and latencies, never alert content, message text, file names or client secrets.
- JSON-structured logs.

---

## 5. Container responsibilities

This section describes what each container must and must not do, as requirements for whoever writes the images later. It deliberately contains no Dockerfile or manifest syntax.

| Container | Contents | Runs as | Writable | Exposed to | Probes |
|---|---|---|---|---|---|
| Reverse proxy | TLS termination, routing `/` and `/api/`, request-size limit matching `SENTIVRA_MAX_UPLOAD_BYTES`, sets `X-Forwarded-For` | Non-root | None | Internet (443) | Proxy's own |
| Dashboard | Next.js production build (standalone output) | Non-root | None (tmpfs for Next's cache if needed) | Proxy only | HTTP GET `/` |
| Backend | Python ≥ 3.11, the `backend` package, `models/` and `detection-rules/` read-only | Non-root, no added capabilities | None, except `/tmp` as memory-backed tmpfs sized for concurrent uploads (Starlette spools uploads over 1 MB there) | Proxy only | Liveness `/api/v1/health/live`; readiness per §3 item 2 |
| Worker (Stage 2) | Same image as the backend, worker entrypoint | Non-root | None | No inbound traffic | Queue heartbeat |
| Inference (Stage 2) | ONNX Runtime plus the pinned artifacts; verifies SHA-256 at load | Non-root | None | Backend and workers only | Model-loaded check |
| PostgreSQL | Database; the application role can't alter the audit log | Postgres default | Data volume | Backend, workers, migration job | `pg_isready` |
| Redis (Stage 2) | Job queue and rate-limit buckets; password and TLS | Non-root | Optional (rate limits need no persistence) | Backend and workers only | `PING` |
| ClamAV | `clamd` on TCP 3310, `freshclam` for signature updates | Non-root | Signature volume | Backend and workers only; egress to ClamAV mirrors only | `PING` over the clamd protocol |
| Suricata / Zeek | Engine writing EVE JSON / Zeek logs to a shared volume | Least privilege the capture needs | Log volume | None inbound | Engine's own |

The Suricata and Zeek containers are pointless until SENTIVRA can read their output. EVE and Zeek log ingestion is **not implemented**, and the API says so even when their paths are configured.

---

## 6. Network zones and egress

| Zone | Members | Inbound from | Outbound to |
|---|---|---|---|
| Edge | Reverse proxy | Internet | Dashboard, backend |
| App | Dashboard, backend, workers | Edge | Data, engines, inference; plus the external APIs below |
| Data | PostgreSQL, Redis | App | Nothing |
| Engines | ClamAV, Suricata, Zeek | App (clamd only) | ClamAV signature mirrors only |
| Inference | Inference service | App | Nothing |

The backend and workers make no outbound internet calls today. The planned ones are:
- **Phase 7 connectors:** Gmail API, Telegram Bot API and Meta Graph API, each with least-privilege credentials (Gmail: `gmail.readonly`).
- **Opt-in URL enrichment:** part of the unbuilt Phase 4 URL detector, through the existing SSRF guard (`app/security/ssrf_guard.py`). In a deployment, route it through an egress proxy that also blocks internal ranges.

Everything else is denied. In particular, no container may reach the host's container-runtime socket or the cloud metadata endpoint.

---

## 7. Security requirements that carry over

A deployment is incorrect if any of these is missing:

- **Runtime configuration**
  - `SENTIVRA_ENV=production`, which turns off the docs and the bootstrap.
  - Real secrets injected at runtime.
  - `SENTIVRA_CORS_ORIGINS` limited to the dashboard origin, or unused with the same-origin layout.
- **Container isolation**
  - Non-root containers, read-only root filesystems, no privileged mode, capabilities dropped.
  - ClamAV and Suricata isolated most strictly, because they parse attacker-supplied bytes by design (threat model, Boundary D).
- **Supply chain**
  - Base images pinned by digest.
  - Dependency audits (`pip-audit`, `npm audit`) plus an image scan in CI.
  - An SBOM per image, and signed images.
- **Model artifacts** come only from the image or a controlled registry, never from a volume that uploads or users can write to. No detector gets write access to `models/`.
- **Files are never executed.** No container ever runs uploaded files, and no dynamic-analysis sandbox is part of this design.
- **Data**
  - Encrypted PostgreSQL backups, with a documented retention period for events, alerts and the audit log.
  - Raw file bytes and message bodies are never persisted by any container: the §3 item 9 handoff rules apply.
- **Access**
  - One OAuth2 client per real consumer (dashboard, each agent, each connector), each with only the scopes it needs.
  - Secrets rotated on a schedule, and immediately after anyone who knew them leaves.

---

## 8. What doesn't change

The point of the staged plan is that detection logic never gets rewritten for infrastructure:

- The `SecurityEvent` schema and the `BaseDetector` interface.
- The detectors and their rule packs.
- The `RiskEngine`.
- The `ModelRegistry` metadata and the SHA-256 pinning.
- The API contract. It gains asynchronous job endpoints in Stage 2 but keeps every existing route.
- The dashboard, apart from its origin and the job-status polling.

See [architecture.md](architecture.md) for the components themselves, [threat-model.md](threat-model.md) for the threats these requirements answer, and [future-automation.md](future-automation.md) for what may one day act on alerts.
