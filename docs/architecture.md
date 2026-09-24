# SENTIVRA Architecture

**Status:** Phase 1 design document. Written before implementation, per the mandated build order — this is the contract the code in `backend/`, `frontend/`, and `models/` is written against.

**Scope:** current demonstration build only. Everything under [Future Extension Points](#11-future-extension-points) is explicitly *not* implemented yet — see [docs/future-deployment.md](future-deployment.md) and [docs/future-automation.md](future-automation.md) for what changes later and why nothing here blocks that change.

---

## 1. Design Principles

1. **No single model makes a security decision.** Every detector is one opinion; the Risk Engine aggregates opinions. See §18 of the product brief, enforced in [§7](#7-risk-engine).
2. **Graceful degradation over fake results.** A missing engine (Suricata not installed, Gmail not connected) reports its own absence — it never silently returns `SAFE` pretending to have run, and never fabricates a finding.
3. **Detectors are independently swappable.** Adding, removing, or retraining a detector must not require touching the API layer, the frontend, or other detectors. Enforced by the `BaseDetector` interface ([§4](#4-detector-layer)) and the `ModelRegistry` ([§6](#6-model-registry)).
4. **Local-first, no forced infrastructure.** SQLite, in-process detectors, no Docker/Redis/Celery/Kafka in this phase (see [Environment Constraints](#2-environment-constraints)). The seams for that infrastructure exist without requiring it.
5. **Explainable by construction.** A `DetectionResult` without evidence is treated as a bug, not an edge case — the schema makes `evidence: []` require a non-empty list at the point severity exceeds `LOW`.
6. **Privacy is a first-class architectural concern**, not a policy bolt-on: raw file bytes and raw message bodies are processed in memory and are not retained by default — only hash + metadata + detection result persist (docs/privacy.md, per-integration detail, is written with the Phase 7 connectors).

---

## 2. Environment Constraints

This phase runs entirely with `uvicorn` (backend) and `next dev` / `next start` (frontend) on a single machine. No container runtime, no message broker, no external database server.

| Concern | Current (demo) | Future (see future-deployment.md) |
|---|---|---|
| Process model | Single FastAPI process, `asyncio` event loop; network scoring runs in a thread, the other detectors on the loop | Backend + worker(s) + dedicated ML inference service |
| Database | SQLite file (`sentivra.db`) via SQLAlchemy; tables created at startup, no migrations | PostgreSQL, same SQLAlchemy models, Alembic migrations |
| Background work | None: every analysis finishes inside its request | Job queue (Celery + Redis) for batch uploads and webhooks |
| Security engines | YARA in-process (`yara-python`); ClamAV over the clamd socket or TCP if configured; Suricata and Zeek not integrated | ClamAV as a sidecar container; Suricata/Zeek once their log ingestion exists |
| Model serving | In-process `ModelLoader`: ONNX Runtime, LightGBM text dumps, NPZ and JSON artifacts, all SHA-256 pinned (no pickle/joblib model is committed) | Dedicated ONNX Runtime inference service behind the same `ModelLoader` interface |
| Raw content | Uploads analyzed in memory and never stored; request-scoped handoff to detectors via `blob_store` / `flow_batches` / `event_batches` | Payload travels with the job, or via short-lived encrypted object storage with TTL and deletion |

The abstraction that makes this swap possible without rewriting the core is the **repository/service pattern**. Persistence goes through `EventRepository` and `AlertRepository` (`backend/app/services/`) and the audit service. Model artifacts are loaded only through `ModelLoader`. Swapping SQLite→PostgreSQL is a connection-string, driver and migration change; swapping local model files→a remote inference service is a second `ModelLoader` backend. Neither touches detector logic or the API layer. The full list of what must change first, with file references, is in [future-deployment.md](future-deployment.md) §3.

---

## 3. High-Level Data Flow

```
                    ┌─────────────────────────────────────────────────┐
                    │                     SOURCES                     │
                    │  Manual analyze API │ Gmail │ Telegram │ WhatsApp │
                    │  Endpoint sim │ Network/PCAP demo upload          │
                    └───────────────────────┬───────────────────────┘
                                            │  raw payload
                                            ▼
                            ┌───────────────────────────────┐
                            │      Event Normalizer         │
                            │  (backend/app/events/)        │
                            │  → SecurityEvent (§5)         │
                            └───────────────┬───────────────┘
                                            │
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │                Detector Layer                 │
                    │        (backend/app/detectors/, §4)           │
                    │                                                 │
                    │  NetworkAnomalyDetector   PromptInjectionDetector │
                    │  SQLInjectionDetector     PhishingDetector        │
                    │  URLDetector              MalwareDetector         │
                    │  YaraDetector             ClamAVDetector           │
                    │  BehavioralAnomalyDetector SigmaDetector           │
                    │  LogDetector                                       │
                    │                                                 │
                    │  each detector → DetectionResult (§5)          │
                    └───────────────────────┬───────────────────────┘
                                            │  DetectionResult[]
                                            ▼
                            ┌───────────────────────────────┐
                            │       Finding Aggregator      │
                            │  (backend/app/risk/)          │
                            └───────────────┬───────────────┘
                                            ▼
                            ┌───────────────────────────────┐
                            │         Risk Engine (§7)      │
                            │  SAFE·LOW·MEDIUM·HIGH·CRITICAL│
                            └───────────────┬───────────────┘
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │   Persistence (SQLAlchemy → SQLite)            │
                    │   events, detection_results, alerts, audit_log │
                    └───────────────────────┬───────────────────────┘
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │        FastAPI REST API (backend/app/api/)     │
                    └───────────────────────┬───────────────────────┘
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │     Next.js SOC Dashboard (frontend/)          │
                    └─────────────────────────────────────────────────┘
```

---

## 4. Detector Layer

All detectors implement one interface:

```python
# backend/app/detectors/base.py
class BaseDetector(ABC):
    name: str
    version: str
    category: DetectorCategory

    async def is_available(self) -> DetectorAvailability:
        """Reports Available / Not Configured / Degraded — never silently skips."""

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        ...
```

Detectors are registered in a `DetectorRegistry` at startup, each declaring which `SecurityEvent.event_type` values it applies to (a `file_created` event never reaches `SQLInjectionDetector`, for example). The registry is what `GET /api/v1/detectors` reflects — real, introspected state, not a hardcoded list.

### 4.1 Detector Matrix

| Detector | Applies to event types | Layers | ML? |
|---|---|---|---|
| `SQLInjectionDetector` | `browser_url`, `system_log`, text analyze | regex/signature → normalization → TF-IDF+classical ML → optional transformer | Yes, tier 3 of 3 |
| `PromptInjectionDetector` | prompt/text analyze, `gmail_message`, `telegram_message`, `whatsapp_message` | pattern → Unicode/confusable normalization → encoding/obfuscation → entropy → semantic → ML classifier | Yes, one of 6 signals |
| `PhishingDetector` | `gmail_message`, `telegram_message`, `whatsapp_message`, URL analyze | header/sender/body heuristics + `URLDetector` output + classical ML | Yes |
| `URLDetector` | any content containing URLs | lexical/structural features, no ML required (deterministic) | Optional scoring assist |
| `MalwareDetector` | `file_created`, `file_downloaded`, file analyze, attachments | orchestrates Yara/ClamAV/static-ML sub-results | Delegates |
| `YaraDetector` | files | native `yara-python`, rules in `detection-rules/yara/` | No (signature) |
| `ClamAVDetector` | files | local `clamd` socket, `Not Configured` if absent | No (signature) |
| `NetworkAnomalyDetector` | `network_flow`, `dns_event`, PCAP demo | signature (Suricata, optional) + statistical baseline + Isolation Forest + Autoencoder + supervised classifier | Yes, 3 of 5 layers |
| `BehavioralAnomalyDetector` | `process_started`, `process_network_connection`, endpoint sim events | Isolation Forest over simulated endpoint telemetry | Yes |
| `SigmaDetector` | `system_log`, `authentication_event` | pySigma rule evaluation against normalized log fields | No (rule engine) |
| `LogDetector` | `system_log`, `authentication_event` | heuristic log-anomaly rules (failed-login bursts, impossible travel where data allows) complementing Sigma | No |

### 4.2 Detector Output Contract

Every `analyze()` call returns exactly this shape (Pydantic-enforced, `backend/app/schemas/detection.py`):

```json
{
  "detector": "PromptInjectionDetector",
  "category": "prompt_injection",
  "severity": "HIGH",
  "score": 0.91,
  "confidence": 0.96,
  "evidence": [
    {"type": "pattern_match", "detail": "instruction override phrase detected", "excerpt": "ignore previous instructions"},
    {"type": "ml_classifier", "detail": "ONNX classifier flagged jailbreak class", "model_version": "prompt_injection-v0.1.0"}
  ],
  "recommended_action": "BLOCK",
  "model_version": "prompt_injection-v0.1.0",
  "mitre_attack": null
}
```

`evidence` is never empty when `severity` is `MEDIUM` or above — this is a schema-level invariant, not a convention, checked by a Pydantic validator.

---

## 5. Universal Security Event

`backend/app/events/schema.py` defines the single normalized shape every source converts into:

```python
class SecurityEvent(BaseModel):
    event_id: str            # UUIDv4
    event_type: SecurityEventType   # enum: gmail_message, telegram_message, ...
    timestamp: datetime
    source: str               # "gmail" | "telegram" | "whatsapp" | "endpoint_sim" | "network_demo" | "api"
    source_type: SourceType    # LIVE | SIMULATED | DEMO_DATA — see §26 of the brief, rendered in the UI
    user_id: str | None
    content: EventContent | None      # text body, subject, etc.
    attachments: list[AttachmentRef]
    network: NetworkContext | None
    process: ProcessContext | None
    metadata: dict[str, Any]
```

Every integration (`backend/app/integrations/gmail/normalizer.py`, `.../telegram/normalizer.py`, `.../whatsapp/normalizer.py`) and every demo-data generator produces this exact shape. Detectors only ever see `SecurityEvent` — they have no knowledge of Gmail/Telegram/WhatsApp-specific payload formats. This is what lets a detector written for `gmail_message` phishing detection also apply, unmodified, to a `whatsapp_message`.

`source_type` is mandatory and always rendered in the UI (§26 of the brief: LIVE vs SIMULATED vs DEMO DATA must never be ambiguous).

---

## 6. Model Registry

```
models/
  network/{isolation_forest,autoencoder,classifier}/
  prompt/prompt_injection/
  malware/ember/
  phishing/url_model/
  sql_injection/classifier/
```

Each model directory contains:

```
model.onnx | model.joblib          # the model artifact
metadata.json                       # version, training dataset, SHA-256, threshold, eval metrics, eval date
preprocessing.json                  # feature schema + preprocessing config (scaler params, vocab, etc.)
```

`ModelRegistry` (`backend/app/ml/registry.py`) reads `metadata.json` for every model directory at startup and exposes `GET /api/v1/models`. `ModelLoader` (`backend/app/ml/loader.py`) is the *only* code path that deserializes a model file, and it:

1. Recomputes the SHA-256 of the artifact and compares it to `metadata.json`'s pinned hash — refuses to load on mismatch.
2. Loads `.onnx` via ONNX Runtime and `.joblib` via `joblib.load` **only** for artifacts produced by Sentivra's own training pipeline under `research/` (never an arbitrary uploaded or runtime-writable file) — this is the boundary that satisfies "never load untrusted pickle/joblib" (brief §21).
3. Caches the loaded model in-process; a detector never touches the filesystem directly.

Replacing a model = replacing the directory contents and bumping `metadata.json`'s `version`. No backend code changes required — this is the concrete mechanism behind "the frontend/backend should not need to be rewritten when a model is replaced" (brief §20).

---

## 7. Risk Engine

`backend/app/risk/engine.py` takes `DetectionResult[]` for one `SecurityEvent` and produces:

```json
{
  "risk_score": 91,
  "severity": "HIGH",
  "classification": "PROMPT_INJECTION",
  "confidence": 0.94,
  "findings": [ "...DetectionResult objects..." ]
}
```

Scoring considers, per detector result: `score × confidence × detector_reliability_weight`, then applies **corroboration boosting** — independent detectors agreeing on the same event push the aggregate score up disproportionately (the "veto/corroboration" pattern documented in [repository-analysis.md](repository-analysis.md) §1). A single low-confidence detector alone cannot produce `CRITICAL`; `CRITICAL` requires either one very-high-confidence detector or corroboration across ≥2 independent detector categories. This logic is unit-tested directly (`backend/tests/test_risk_engine.py`) with fixed input/output pairs, since it's the one place a bug silently changes every alert in the system.

`risk_score` is explicitly documented as **not a calibrated probability** unless the underlying model has been Platt/isotonic-calibrated and evaluated as such (brief §18) — the API/UI never uses the word "probability" for it.

---

## 8. Backend Module Layout

```
backend/app/
  api/            FastAPI routers, one file per resource (analyze.py, events.py, alerts.py, models.py, ...)
  core/           settings (pydantic-settings), startup/dependency wiring, engine-availability probing
  detectors/      BaseDetector + one module per detector
  events/         SecurityEvent schema + normalizers
  integrations/   gmail/, telegram/, whatsapp/ — each: client.py, webhook.py, normalizer.py
  ml/             ModelRegistry, ModelLoader, feature extractors shared across detectors
  risk/           Finding aggregator + RiskEngine
  models/         SQLAlchemy ORM models (events, alerts, audit_log, ...)
  schemas/        Pydantic request/response schemas
  services/       Repository/adapter layer (EventRepository, AlertRepository, ...) — the DB-swap seam
  audit/          Audit logging middleware/service
  security/       Auth, rate limiting, SSRF guards, upload validation, webhook signature verification
```

Each detector is its own file under 300–400 lines; shared feature-extraction code (e.g., URL lexical features used by both `URLDetector` and `PhishingDetector`) lives in `ml/features/` so it isn't duplicated. This is the concrete mechanism behind "avoid giant Python files" (brief §38).

---

## 9. API Surface

See [docs/api.md](api.md) for full request/response schemas. Endpoint list matches brief §25 exactly:

```
POST /api/v1/analyze/{text,url,file,prompt,sql}
POST /api/v1/events              GET /api/v1/events        GET /api/v1/events/{id}
GET  /api/v1/alerts               GET /api/v1/alerts/{id}
GET  /api/v1/models                GET /api/v1/detectors
GET  /api/v1/health                GET /api/v1/metrics
POST /api/v1/integrations/{gmail,telegram,whatsapp}/webhook
```

---

## 10. Frontend Architecture

Next.js App Router, one route segment per page (brief §23): Overview, Threats, Network, Files, Messages, Prompt Security, Endpoint, Models, Rules, Integrations, Audit Log, Settings. Data fetching via typed API client (`frontend/lib/api.ts`) generated to match the backend Pydantic schemas — no `any`-typed API responses. Charts via Recharts, components via shadcn/ui, per the dataviz/design conventions documented separately.

Every page that can show simulated/demo/live data renders a `SourceTypeBadge` component sourced directly from `SecurityEvent.source_type` — this is a shared component precisely so "never present simulated data as live" (brief §26) is enforced once, not re-implemented per page.

---

## 11. Future Extension Points

These are **not implemented now**; the architecture reserves the seam so they don't require a rewrite later.

- **Automation**: the Detection → Policy Engine → Human Approval → Automation chain (brief §36) is specified, contracts and guardrails included, in [future-automation.md](future-automation.md). The attachment point is `run_pipeline` in `backend/app/services/pipeline.py`. No policy-engine code exists yet, by design: its contracts get added together with their first implementation and tests. Currently a `HIGH`/`CRITICAL` alert only ever *notifies* (persists and surfaces in the UI); nothing acts on it.
- **Docker/orchestration**: see [docs/future-deployment.md](future-deployment.md).
- **PostgreSQL**: add a driver and Alembic migrations (none exist yet; tables are created at startup), then swap the SQLAlchemy connection string. The repository layer means detector and API code are untouched.
- **Distributed model serving**: `ModelLoader` gets a second backend implementation (gRPC/HTTP to an inference service) behind the same interface; `ModelRegistry` is unaffected.
- **Native endpoint agent**: the simulated endpoint-event generator already emits osquery-compatible table/column names (per [repository-analysis.md](repository-analysis.md) §8) so a real agent's output can replace the simulator without changing `BehavioralAnomalyDetector`.
