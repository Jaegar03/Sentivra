# SENTIVRA API

Base URL: `http://localhost:8000`. Interactive OpenAPI docs are served by the running backend at `/docs`, and the machine-readable schema at `/openapi.json`. The route list below was generated from that schema.

**Security posture of this build.** The API has **no authentication** yet. Keep it bound to localhost, as `uvicorn app.main:app` does by default. Other protections are in place:
- CORS is restricted to `SENTIVRA_CORS_ORIGINS`.
- Every client IP is rate-limited to `SENTIVRA_RATE_LIMIT_PER_MINUTE` (default 300; excess requests get `429`).
- Uploads are capped (`SENTIVRA_MAX_UPLOAD_BYTES`, default 50 MB; larger ones get `413`).
- Every response carries secure headers.
- Every analysis and every alert status change is written to the append-only audit log.

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
| POST | `/api/v1/analyze/file` | multipart `file` | Detects the type from magic bytes, computes SHA-256 and entropy, and checks for archive bombs. Then runs YARA, ClamAV (when reachable) and structural heuristics. The file is never executed. Its bytes are held in memory for the request only; the hash, metadata and verdict are persisted. Returns `file_metadata`, `findings`, `risk_assessment` and `source_type`. |
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
