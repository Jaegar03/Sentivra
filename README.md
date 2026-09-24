# SENTIVRA

**One Security Layer. Every Threat.**

SENTIVRA is a demonstration-quality, multi-layer cybersecurity detection platform: a single unified architecture where specialized detectors (file/malware, SQL injection, prompt injection, phishing/malicious URL, network anomaly, endpoint behavior, Sigma/log rules) each produce independent, evidence-backed findings that a risk engine aggregates into one explainable severity verdict — never a single model's opinion presented as a final decision.

This is a **local, demonstration build** — no Docker, no Kubernetes, no Redis/Celery/Kafka. It runs with normal development commands (`uvicorn`, `next dev`) and is architected so that infrastructure can be added later without a rewrite. See [docs/future-deployment.md](docs/future-deployment.md).

## Project status

Built in phases (see [docs/architecture.md](docs/architecture.md) § Implementation Order). Current state:

| Phase | Scope | Status |
|---|---|---|
| 1 | Repository analysis, architecture, threat model | ✅ Done |
| 2 | Core contracts — `SecurityEvent`, `DetectionResult`, `BaseDetector`, `ModelRegistry`, `RiskEngine` | ✅ Done |
| 3 | File detection — hashing, magic bytes, entropy, YARA, ClamAV | ✅ Done |
| 4 | SQL injection, phishing/URL, prompt injection detectors | 🔄 Groundwork only: rule packs, Unicode/decoding layers, SQL lexer, pickle-free model format, datasets fetched. Detectors not wired yet |
| 5 | Network anomaly detection: behavior rules, statistical, Isolation Forest, autoencoder, classifier; CSV/PCAP upload | ✅ Done. Models trained on **synthetic** data; see [docs/model-card.md](docs/model-card.md) |
| 6 | Endpoint-event simulation | ⏳ Planned |
| 7 | Gmail / Telegram / WhatsApp Business connectors | ⏳ Planned |
| 8 | Unified risk engine polish, alert management | ⏳ Partially done (engine exists, §7 of architecture.md) |
| 9 | Next.js SOC dashboard | ⏳ Planned |
| 10 | Testing & hardening | 🔄 Ongoing per-phase |

## Quick start (backend)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    |    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example ../.env   # edit as needed — safe demo defaults work out of the box
uvicorn app.main:app --reload
```

Then visit `http://localhost:8000/docs` for interactive API docs, or:

```bash
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/detectors
```

Run the test suite:

```bash
cd backend
pytest -q
```

## Try the file detector right now

```bash
# The EICAR test string — a standard, harmless antivirus test file, not real malware
curl -X POST http://localhost:8000/api/v1/analyze/file \
  -F "file=@eicar.txt;type=text/plain"
```

(Create `eicar.txt` with contents `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*` to try it.)

## Try the network detector

```bash
# Bundled synthetic sample (tagged DEMO_DATA in the response)
curl -X POST http://localhost:8000/api/v1/network/demo

# Your own capture or flow export: PCAP/PCAPNG, Sentivra flow CSV, or CICFlowMeter CSV
curl -X POST http://localhost:8000/api/v1/network/analyze -F "file=@capture.pcap"
```

The response lists which behavior rules fired (with verified ATT&CK mappings where one applies), which flows at least two model layers agreed on, and why. Uploaded traffic is parsed in memory and discarded after the request.

## Documentation

- [docs/repository-analysis.md](docs/repository-analysis.md) — survey of every reference repository named in the project brief, with license/maintenance/decision per repo
- [docs/architecture.md](docs/architecture.md) — system design, data flow, detector matrix, model registry
- [docs/threat-model.md](docs/threat-model.md) — STRIDE analysis of Sentivra itself, plus stated per-detector limitations
- [docs/future-deployment.md](docs/future-deployment.md) — planned Docker/Kubernetes/Redis architecture (not implemented yet)
- [docs/privacy.md](docs/privacy.md), [docs/model-card.md](docs/model-card.md), [docs/api.md](docs/api.md) — added as their corresponding phases land

## Principles

1. No single detector or ML model makes a final security decision.
2. A missing engine (ClamAV not installed, Gmail not connected) says so — it never fakes a clean result.
3. Every alert answers: what happened, why, what evidence, how confident, what to do.
4. Files are never executed. Raw file bytes and message bodies are not retained by default — hash + metadata + result are.
5. No fabricated ML metrics — every reported number is tied to a dataset, split, and evaluation date.

## License

Apache-2.0 — see [LICENSE](LICENSE). Third-party rule packs (e.g. Sigma under DRL 1.1) retain their own licenses; see [docs/repository-analysis.md](docs/repository-analysis.md) for details.
