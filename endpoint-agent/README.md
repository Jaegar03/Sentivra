# SENTIVRA endpoint telemetry

Sentivra doesn't ship its own endpoint agent yet. Today it takes endpoint telemetry from **osquery**, using the query pack in this directory, and alerts from a **Wazuh** manager. A native agent is planned; its architecture is described below. It isn't implemented.

## 1. osquery (works today)

`osquery/sentivra-pack.conf` is a standard osquery query pack. It covers:

| Telemetry | osquery tables |
|---|---|
| Process starts | `process_events` (Linux/macOS), `process_etw_events` (Windows) |
| Outbound connections | `socket_events`, `process_open_sockets` |
| Listening ports | `listening_ports` |
| File changes | `file_events` |
| Persistence | `startup_items`, `scheduled_tasks`, `services`, `crontab` |
| Logons and Security events | `windows_eventlog` (4624, 4625, 4720, 4732, 1102), `last` |

The normalizer (`backend/app/events/osquery.py`) recognizes rows by these query names, so keep them if you edit the pack.

### Deploy

1. Add the pack to your osquery config:
   ```json
   { "packs": { "sentivra": "/etc/osquery/packs/sentivra-pack.conf" } }
   ```
2. Enable the evented tables the pack uses:
   - Linux: `--disable_audit=false --audit_allow_process_events=true --audit_allow_sockets=true`
   - Windows: `--enable_process_etw_events=true`
   - For `file_events`, list the paths to watch under `file_paths`.
3. Add decorators so every row carries the host and OS:
   ```json
   { "decorators": { "load": [
       "SELECT hostname FROM system_info;",
       "SELECT CASE WHEN platform = 'windows' THEN 'windows' WHEN platform = 'darwin' THEN 'darwin' ELSE 'linux' END AS os FROM os_version;"
   ] } }
   ```
4. Send the results log to Sentivra. With the default filesystem logger, that file is `osqueryd.results.log` (NDJSON). The API needs a token with the `ingest` scope. Give each forwarder its own client (for example `osquery-agent:<secret>:ingest` in `SENTIVRA_OAUTH_CLIENTS`) so it can submit telemetry but can't read alerts; see [docs/api.md](../docs/api.md#authentication):
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
     -d grant_type=client_credentials -d client_id=osquery-agent -d "client_secret=$SECRET" \
     | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
   curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8000/api/v1/endpoint/osquery \
     -F "file=@/var/log/osquery/osqueryd.results.log"
   ```

A demonstration fleet runs through the same code path, and its telemetry is tagged SIMULATED:

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8000/api/v1/endpoint/demo   # needs the analyze scope
```

### What happens to the data

Uploaded rows are normalized and analyzed in memory: Sigma rules, host behavior rules against the fleet baseline, and authentication rules. After that, only the batch summary, the detection results and the audit record are persisted; the raw rows are discarded when the request ends. Per-integration data handling is in [docs/privacy.md](../docs/privacy.md), written with the Phase 7 connectors (it covers the Gmail, Telegram and WhatsApp webhooks; the osquery rule is the sentence above).

## 2. Wazuh (works today, alerts only)

Sentivra accepts Wazuh's `alerts.json` (one alert per line) on the log endpoint:

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8000/api/v1/logs/analyze \
  -F "file=@/var/ossec/logs/alerts/alerts.json"
```

Wazuh alerts are treated as **another engine's verdict**. Each one is passed through as evidence, labeled with Wazuh's own rule ID and level. Wazuh MITRE tags are resolved against the ATT&CK index, and revoked IDs are remapped. Alerts that carry Windows event data or authentication groups also feed Sentivra's own Sigma and authentication rules.

## 3. Native Sentivra agent (future: not implemented)

The planned agent keeps the event contract osquery already satisfies, so the detectors don't change when it arrives.

```
┌──────────────────────── endpoint ────────────────────────┐
│  collectors (ETW / eBPF / EndpointSecurity)              │
│      │  process, network, file, persistence, auth events │
│      ▼                                                    │
│  local normalizer ──► osquery-compatible rows            │
│      │                (same table and column names)       │
│      ▼                                                    │
│  bounded on-disk queue (survives restarts, capped size)   │
│      │                                                    │
│      ▼                                                    │
│  uploader: mTLS, per-agent enrollment key, batching,      │
│            backoff; no inbound ports on the endpoint       │
└──────────────────────────┬───────────────────────────────┘
                           ▼
            Sentivra ingestion API (the /endpoint/osquery contract)
```

Design commitments:
- **Read-only.** The agent observes and never acts on the host. Isolation, killing processes, deleting files and similar actions belong to the future automation layer behind human approval ([docs/future-automation.md](../docs/future-automation.md)), not to the agent.
- **Least privilege.** The agent gets only the OS permissions each collector needs, and each collector can be disabled.
- **Enrollment and transport.** Each agent enrolls with a one-time secret and receives its own key, which can be revoked on its own. Uploads use mutual TLS. The agent opens no listening port.
- **Privacy.** Command lines and file paths can contain personal data, so collection is configurable per table, and the same retention limits as other telemetry apply.
- **Compatibility.** Rows keep osquery's table and column names, so an organization can run osquery, the Sentivra agent, or both, and Sigma rules keep working.
