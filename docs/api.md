# SENTIVRA API

Base URL: `http://localhost:8000`. Interactive OpenAPI docs are served by the running backend at `/docs`, and the machine-readable schema at `/openapi.json`. The route list below was generated from that schema.

**Security posture of this build.**
- **Authentication.** Every `/api/` route needs an OAuth2 bearer token with the right scope. Only two routes are open: the token endpoint and the liveness probe. A test walks the OpenAPI schema and fails if any other route answers without a token. See [Authentication](#authentication).
- **CORS** is restricted to `SENTIVRA_CORS_ORIGINS`. Credentials (cookies) are never allowed; only the `Authorization` and `Content-Type` request headers are.
- **Rate limits** are per client IP:
  - `SENTIVRA_RATE_LIMIT_PER_MINUTE` for the API (default 300);
  - `SENTIVRA_TOKEN_RATE_LIMIT_PER_MINUTE` for the token endpoint (default 10).
  - Excess requests get `429` with `Retry-After: 60`.
- **Request bodies are capped while they're being received**, so an oversized body is never parsed or buffered. See [Request size limits](#request-size-limits).
- **Secure headers.** Every response carries them. API responses also get `Content-Security-Policy: default-src 'none'` and `Cache-Control: no-store`.
- **Interactive docs** (`/docs`, `/redoc`, `/openapi.json`) are served in development only.
- **Audit.** Every analysis and every alert status change is written to the append-only audit log, with the client ID that made the request as the `actor`.

Webhook connectors (Phase 7) aren't built. Until they are, keep the backend bound to localhost, as `uvicorn app.main:app` does by default.

## Authentication

SENTIVRA uses the OAuth2 **client-credentials** grant (RFC 6749 §4.4).

1. A client exchanges its ID and secret for a short-lived access token.
2. It sends that token on every call, as `Authorization: Bearer <token>`.

There are no user accounts or passwords. Each client is a program: the dashboard, an osquery forwarder, a script.

```bash
# 1. Get a token (form fields, or HTTP Basic with -u dashboard:$SECRET)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d grant_type=client_credentials -d client_id=dashboard -d "client_secret=$SECRET" \
  | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# 2. Use it
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/alerts
```

| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/api/v1/auth/token` | form: `grant_type=client_credentials`, `client_id`, `client_secret`, optional `scope` | Returns `{"access_token", "token_type": "bearer", "expires_in", "scope"}` with `Cache-Control: no-store`. See the token endpoint notes below. |
| GET | `/api/v1/health/live` | — | Liveness probe, **no token needed**. Always `{"status": "ok"}` and nothing else. Detailed health is `/api/v1/health` (`read`). |

Token endpoint notes:
- **Scope.** Without `scope`, the token gets all of the client's scopes. With a space-separated `scope`, the token is narrowed to those; it never gains scopes the client lacks.
- **Errors** use the RFC's shape, `{"error", "error_description"}`: `unsupported_grant_type`, `invalid_request`, `invalid_scope` (400) and `invalid_client` (401).
- **No client enumeration.** A wrong secret and an unknown client ID get the same answer.

**Scopes.** Each route needs exactly one scope, listed in the tables below.

| Scope | Grants |
|---|---|
| `read` | Every `GET`: alerts, events, metrics, models, rules, detectors, integrations, audit log, detailed health |
| `analyze` | Interactive analysis: `/analyze/*`, `/network/analyze`, and the `/network/demo` and `/endpoint/demo` runs |
| `ingest` | Telemetry submission: `POST /events`, `/endpoint/osquery`, `/logs/analyze` |
| `alerts:write` | `PATCH /alerts/{alert_id}` (status changes) |

An ingest-only client, such as an osquery forwarder, can submit telemetry but can't read alerts back.

**Failures.**
- A missing, expired, tampered or foreign-key token gets `401` with `WWW-Authenticate: Bearer`.
- A token for a client that no longer exists also gets `401`.
- A valid token without the route's scope gets `403` with `WWW-Authenticate: Bearer error="insufficient_scope"`.

**Tokens** are HS256 JWTs.
- Claims: `iss=sentivra`, `sub` (the client ID), `scope`, `iat`, `exp` and `jti`.
- The lifetime is `SENTIVRA_TOKEN_TTL_S` (default 3600 s).
- Verification pins the algorithm, so an `alg: none` or re-signed token is rejected.
- Every request re-checks the token's scopes against the client's configuration. Client configuration is loaded at startup, so removing a client, or a scope from it, takes effect at the next restart. That includes tokens issued before the change.

**Configuring clients.**
- **Development, first start.** With `SENTIVRA_OAUTH_CLIENTS` empty, the backend creates a `dashboard` client with all four scopes and prints its secret once in the log. Only the secret's SHA-256 is stored, in `.sentivra/clients.json`. Delete that file and restart to issue a new secret. The JWT signing key is generated alongside it, in `.sentivra/signing.key`, unless `SENTIVRA_SECRET_KEY` holds a real secret.
- **Outside development**, set both of these, or the backend refuses to start:
  - `SENTIVRA_SECRET_KEY`: at least 32 random characters. Placeholders from `.env.example` are refused.
  - `SENTIVRA_OAUTH_CLIENTS`: `id:secret:scope scope;id2:secret2:scope`, or a JSON list of `{"client_id", "client_secret", "scopes"}`. Client secrets need at least 32 characters.

## Request size limits

Limits apply while the body is received, before FastAPI parses it:

| Routes | Limit |
|---|---|
| `/analyze/file`, `/network/analyze`, `/endpoint/osquery`, `/logs/analyze` (multipart uploads) | `SENTIVRA_MAX_UPLOAD_BYTES` (default 50 MB) + 64 KB for multipart framing |
| Every other route | `SENTIVRA_MAX_JSON_BYTES` (default 1 MB) |

- A declared `Content-Length` over the limit is refused with `413` before any of the body is read.
- A body without one (chunked transfer) is cut off with `413` the moment it crosses the limit.
- Row and packet caps (`SENTIVRA_MAX_NETWORK_FLOWS`, `SENTIVRA_MAX_PCAP_PACKETS`, `SENTIVRA_MAX_ENDPOINT_ROWS`, `SENTIVRA_MAX_LOG_LINES`) then bound the work done per request.
- Multipart parts over 1 MB are spooled by Starlette to an anonymous OS temporary file while the request is parsed. The file is deleted when the request ends; SENTIVRA never stores uploads.

## Conventions

- **Detection results** use the `DetectionResult` shape: `detector`, `category`, `severity`, `score`, `confidence`, `evidence[]`, `recommended_action`, `model_version`, `mitre_attack[]`. Any severity above LOW always has at least one evidence item.
- **Aggregate verdicts** use the `RiskAssessment` shape: `risk_score` (0–100), `severity`, `classification`, `confidence` and `findings[]`. `risk_score` is a weighted heuristic, not a calibrated probability.
- **Input labels.** Every analysis response carries `source_type`: `LIVE` for real input (an upload or an integration), `SIMULATED` for the endpoint simulator, or `DEMO_DATA` for bundled synthetic samples. Alert listings carry it too, under `event.source_type`.
- **Not implemented yet.** An endpoint that is defined but not built answers `501` with an explanation. It never returns a fabricated result.

## System

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | Database state and the live availability of every engine and detector. An engine that isn't installed says `Not Configured`. |
| GET | `/api/v1/detectors` | Registered detectors: version, category, the event types each one applies to, and their availability. |
| GET | `/api/v1/models` | Model registry, read from each `models/<domain>/<name>/metadata.json`: version, datasets, splits, threshold policy, test-split metrics, evaluation date, SHA-256, limitations. Untrained models report `trained: false` with a reason. |
| GET | `/api/v1/rules` | Loaded rule packs (YARA files, Sigma rules, custom YAML packs), Sigma rules the engine couldn't support with the reason, and the ATT&CK version used for tag resolution. |
| GET | `/api/v1/metrics?window_hours=24` | Counts only, never model accuracy. See details below. |
| GET | `/api/v1/audit?limit&offset&action` | Audit log, newest first. Read-only. |
| GET | `/api/v1/integrations` | The status of each connector, telemetry source and engine: `Connected`, `Available`, `Not configured` or `Not implemented`. |

`/api/v1/metrics` returns:
- totals of events and alerts;
- window aggregates by severity, status, classification, detector, domain and source type, plus an hourly or daily timeline;
- `security_score`, whose formula and a note that it is not a probability are always returned alongside the value.

## Events and alerts

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/events` | Ingest one `SecurityEvent` (JSON) and run every applicable detector on it. Returns `findings` and `risk_assessment`. |
| GET | `/api/v1/events?limit&offset` | Recent events. |
| GET | `/api/v1/events/{event_id}` | One event. |
| GET | `/api/v1/alerts?limit&offset&min_severity&status` | Alerts, newest first. Each is a `RiskAssessment` plus `status` and `event` (`source`, `source_type`, `event_type`). Filters are applied before `limit`. |
| GET | `/api/v1/alerts/{alert_id}` | One alert, with the full event it was raised on. |
| PATCH | `/api/v1/alerts/{alert_id}` | Body `{"status": "OPEN" \| "ACKNOWLEDGED" \| "RESOLVED", "note"?: string ≤ 500}`. The change is recorded in the audit log. |

An alert is created only when the aggregate severity is above SAFE.

## Analysis

| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/api/v1/analyze/file` | multipart `file` | Detects the type from magic bytes, computes SHA-256 and entropy, and checks for archive bombs. Then runs YARA, ClamAV (when reachable) and structural heuristics. The file is never executed. Its bytes are analyzed in memory for the request only and never stored; the hash, metadata and verdict are persisted. Returns `file_metadata`, `findings`, `risk_assessment` and `source_type`. |
| POST | `/api/v1/analyze/text` | — | **501**: detector not built yet. |
| POST | `/api/v1/analyze/url` | — | **501**: detector not built yet. |
| POST | `/api/v1/analyze/prompt` | — | **501**: detector not built yet. |
| POST | `/api/v1/analyze/sql` | — | **501**: detector not built yet. |

## Network

| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/api/v1/network/analyze` | multipart `file` | Accepts a PCAP/PCAPNG, a Sentivra flow CSV or a CICFlowMeter (CIC-IDS2017) CSV. Runs the behavior rules plus the statistical, Isolation Forest, autoencoder and classifier layers. See the response notes below. |
| POST | `/api/v1/network/demo?seed=2026` | — | The same analysis on the bundled synthetic sample, labeled `DEMO_DATA`. |

The `network` section of the response contains:
- layer status and per-layer fire counts;
- behavior findings, with ATT&CK mappings where one is defensible;
- the fusion cut, and a batch significance test (flagged count vs the calibrated benign rate);
- the highest-scoring flagged flows, with explanations.

Parsed flows are discarded after the request.

## Endpoint and logs

| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/api/v1/endpoint/osquery` | multipart `file` | osquery result logs: the NDJSON `osqueryd.results.log` or a JSON array, from the pack in `endpoint-agent/osquery/`. Runs the Sigma rules, host behavior rules (against the fleet baseline) and authentication rules. `normalizer_stats` counts rows from queries the normalizer doesn't recognize. |
| POST | `/api/v1/endpoint/demo?seed=2026` | — | A simulated fleet's osquery telemetry, labeled `SIMULATED`. |
| POST | `/api/v1/logs/analyze` | multipart `file` | Accepts Linux `auth.log`/`secure`, Windows Security events as JSON lines, or Wazuh `alerts.json`. Returns `parse_stats` and the Sigma and authentication findings; Wazuh alerts are passed through as Wazuh's verdict. |

Batch responses include an `analysis` object with per-layer detail: `sigma`, `auth` and `behavior`.

## Planned, not routed yet

These appear in the product brief (§25) and arrive with the Phase 7 connectors. They currently return `404`.

| Method | Path | Planned behavior |
|---|---|---|
| POST | `/api/v1/integrations/gmail/webhook` | Gmail Pub/Sub push, JWT-verified; mail fetched with the `gmail.readonly` scope only |
| POST | `/api/v1/integrations/telegram/webhook` | Telegram Bot API webhook with the `secret_token` header check; only messages sent to the bot |
| POST | `/api/v1/integrations/whatsapp/webhook` | WhatsApp Cloud API webhook with `X-Hub-Signature-256` HMAC verification (the helper exists in `backend/app/security/webhooks.py`) |
