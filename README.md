# SENTIVRA

**One Security Layer. Every Threat.**

SENTIVRA is a demonstration-quality, multi-layer cybersecurity detection platform: a single unified architecture where specialized detectors (file/malware, SQL injection, prompt injection, phishing/malicious URL, network anomaly, endpoint behavior, Sigma/log rules) each produce independent, evidence-backed findings that a risk engine aggregates into one explainable severity verdict — never a single model's opinion presented as a final decision.

This is a **local, demonstration build** — no Docker, no Kubernetes, no Redis/Celery/Kafka. It runs with normal development commands (`uvicorn`, `next dev`) and is architected so that infrastructure can be added later without a rewrite. The staged plan for that is in [docs/future-deployment.md](docs/future-deployment.md) (design only; no Docker files exist).

## Project status

Built in phases (see [docs/architecture.md](docs/architecture.md) § Implementation Order). Current state:

| Phase | Scope | Status |
|---|---|---|
| 1 | Repository analysis, architecture, threat model | ✅ Done |
| 2 | Core contracts — `SecurityEvent`, `DetectionResult`, `BaseDetector`, `ModelRegistry`, `RiskEngine` | ✅ Done |
| 3 | File detection — hashing, magic bytes, entropy, YARA, ClamAV | ✅ Done |
| 4 | SQL injection, phishing/URL, prompt injection detectors | 🔄 Groundwork only: rule packs, Unicode/decoding layers, SQL lexer, pickle-free model format, datasets fetched. Detectors not wired yet |
| 5 | Network anomaly detection: behavior rules, statistical, Isolation Forest, autoencoder, classifier; CSV/PCAP upload | ✅ Done. Models trained on **synthetic** data; see [docs/model-card.md](docs/model-card.md) |
| 6 | Endpoint telemetry: osquery pack + normalizer, simulator, Sigma engine, host behavior rules, auth/log rules, Wazuh alert ingestion | ✅ Done, rules only: no endpoint ML model in this version. See [endpoint-agent/README.md](endpoint-agent/README.md) |
| 7 | Gmail / Telegram / WhatsApp Business connectors | ⏳ Planned |
| 8 | Unified risk engine polish, alert management | 🔄 Engine, explanations and alert status (acknowledge/resolve, audited) done; policy engine reserved for later |
| 9 | Next.js SOC dashboard | ✅ Done: 14 pages, light and dark; see [frontend/README.md](frontend/README.md) |
| 10 | Security hardening | ✅ OAuth2 client-credentials with per-route scopes, dashboard sign-in, request-body limits, token-endpoint rate limit, strict response headers and a dashboard CSP. See [docs/api.md](docs/api.md#authentication) and the known gaps in [docs/threat-model.md](docs/threat-model.md) |
| 11 | Future deployment and automation design | ✅ Documentation only, as the brief requires: [docs/future-deployment.md](docs/future-deployment.md) (what already carries over, what must change first, staged container architecture) and [docs/future-automation.md](docs/future-automation.md) (policy engine → human approval → executor contracts and guardrails). No Dockerfile, compose file, manifest or automation code |

## Quick start

### Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    |    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example ../.env   # optional: the defaults work for local development
uvicorn app.main:app --reload
```

**First start.** Every API route needs a token, and on first start the backend creates an API client for you. Its secret appears once in the log:

```
  SENTIVRA generated an API client for the dashboard (development only).
  client_id:     dashboard
  client_secret: <copy this>
```

Keep that secret. It's what you paste into the dashboard's sign-in screen. Only its hash is stored, in `.sentivra/clients.json`; to get a new secret, delete that file and restart. Outside development, the backend doesn't generate anything: set `SENTIVRA_SECRET_KEY` and `SENTIVRA_OAUTH_CLIENTS` yourself (see `.env.example`).

Exchange the secret for a token and call the API:

```bash
SECRET='<the client_secret from the log>'
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d grant_type=client_credentials -d client_id=dashboard -d "client_secret=$SECRET" \
  | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
AUTH="Authorization: Bearer $TOKEN"

curl -H "$AUTH" http://localhost:8000/api/v1/health
curl -H "$AUTH" http://localhost:8000/api/v1/detectors
```

Tokens last an hour. The examples below assume `$AUTH` is set. Interactive API docs are at `http://localhost:8000/docs` (development only). To call routes from there, paste `$TOKEN` into **Authorize**.

Run the test suite:

```bash
cd backend
pytest -q
```

## Try the file detector right now

```bash
# The EICAR test string — a standard, harmless antivirus test file, not real malware
curl -H "$AUTH" -X POST http://localhost:8000/api/v1/analyze/file \
  -F "file=@eicar.txt;type=text/plain"
```

(Create `eicar.txt` with contents `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*` to try it.)

## Try the network detector

```bash
# Bundled synthetic sample (tagged DEMO_DATA in the response)
curl -H "$AUTH" -X POST http://localhost:8000/api/v1/network/demo

# Your own capture or flow export: PCAP/PCAPNG, Sentivra flow CSV, or CICFlowMeter CSV
curl -H "$AUTH" -X POST http://localhost:8000/api/v1/network/analyze -F "file=@capture.pcap"
```

The response lists which behavior rules fired (with verified ATT&CK mappings where one applies), which flows at least two model layers agreed on, and why. Uploaded traffic is parsed in memory and discarded after the request.

## Try the endpoint and log detectors

```bash
# Simulated fleet as osquery telemetry (tagged SIMULATED in the response)
curl -H "$AUTH" -X POST http://localhost:8000/api/v1/endpoint/demo

# Real osquery results from the pack in endpoint-agent/osquery/
curl -H "$AUTH" -X POST http://localhost:8000/api/v1/endpoint/osquery -F "file=@osqueryd.results.log"

# auth.log / secure, Windows Security events as JSON lines, or Wazuh alerts.json
curl -H "$AUTH" -X POST http://localhost:8000/api/v1/logs/analyze -F "file=@auth.log"

# Which rule packs are loaded, and which Sigma rules couldn't be supported
curl -H "$AUTH" http://localhost:8000/api/v1/rules
```

## Dashboard

```bash
cd frontend
npm install
npm run dev      # http://localhost:3000 (the backend must be running)
```

Sign in with client ID `dashboard` and the secret from the backend's first-start log. The dashboard exchanges the secret for a token and keeps only the token, in this browser tab's `sessionStorage`. When the token expires, you're returned to the sign-in screen.

Open **Demo mode** in the sidebar and choose *Run all scenarios* to see the whole pipeline: an EICAR test file, a synthetic network sample and a simulated endpoint fleet, each labeled as live, simulated or demo data everywhere it appears.

## Documentation

- [docs/repository-analysis.md](docs/repository-analysis.md) — survey of every reference repository named in the project brief, with license/maintenance/decision per repo
- [docs/architecture.md](docs/architecture.md) — system design, data flow, detector matrix, model registry
- [docs/threat-model.md](docs/threat-model.md) — STRIDE analysis of Sentivra itself, plus stated per-detector limitations
- [docs/api.md](docs/api.md) — authentication and scopes, request limits, every endpoint (including the ones that answer 501) and the webhooks still to come
- [docs/model-card.md](docs/model-card.md) — every model's data, splits, metrics, evaluation date and limitations
- [endpoint-agent/README.md](endpoint-agent/README.md) — osquery pack deployment, Wazuh ingestion, future native agent
- [docs/future-deployment.md](docs/future-deployment.md) — staged container/cloud architecture, the code changes each stage needs, and the security requirements that carry over (design only)
- [docs/future-automation.md](docs/future-automation.md) — Detection → Policy Engine → Human Approval → Automation: reserved contracts, action catalog, guardrails (design only)
- docs/privacy.md — per-integration data handling; not written yet (arrives with the Phase 7 connectors)

## Principles

1. No single detector or ML model makes a final security decision.
2. A missing engine (ClamAV not installed, Gmail not connected) says so — it never fakes a clean result.
3. Every alert answers: what happened, why, what evidence, how confident, what to do.
4. Files are never executed. Raw file bytes and message bodies are not retained by default — hash + metadata + result are.
5. No fabricated ML metrics — every reported number is tied to a dataset, split, and evaluation date.

## License

Apache-2.0 — see [LICENSE](LICENSE). Third-party rule packs (e.g. Sigma under DRL 1.1) retain their own licenses; see [docs/repository-analysis.md](docs/repository-analysis.md) for details.
