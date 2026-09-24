"""GET /api/v1/integrations — what is actually connected, as opposed to what
is planned (brief §32: "Gmail — Not Connected", never a fake green light).

Status values:
  Connected       a live integration is receiving data (none in this version)
  Available       an ingestion path that works today (upload endpoints)
  Not configured  an optional engine that isn't installed or pointed at
  Not implemented a connector that doesn't exist yet
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_detector_registry
from app.core.config import get_settings
from app.detectors.registry import DetectorRegistry
from app.security.auth import require_scopes

router = APIRouter(prefix="/api/v1", tags=["integrations"], dependencies=[Depends(require_scopes("read"))])


@router.get("/integrations")
async def list_integrations(registry: DetectorRegistry = Depends(get_detector_registry)) -> list[dict]:
    s = get_settings()

    def connector(name: str, credentials: bool, scope: str) -> dict:
        return {
            "name": name, "kind": "messaging", "status": "Not implemented",
            "credentials_configured": credentials,
            "detail": (f"Connector not built yet (planned: {scope}). "
                       + ("Credentials are set in the environment but nothing uses them yet."
                          if credentials else "No credentials configured.")),
        }

    async def engine(detector_name: str, label: str) -> dict:
        detector = registry.get(detector_name)
        if detector is None:
            return {"name": label, "kind": "engine", "status": "Not configured", "detail": "Detector not registered"}
        availability = await detector.is_available()
        status = "Available" if availability.status.value == "Available" else "Not configured"
        return {"name": label, "kind": "engine", "status": status, "detail": availability.detail,
                "engine_version": availability.engine_version}

    return [
        connector("Gmail", bool(s.gmail_oauth_client_id), "OAuth2 with gmail.readonly, Pub/Sub watch"),
        connector("Telegram", bool(s.telegram_bot_token), "official Bot API webhook, messages sent to the bot only"),
        connector("WhatsApp Business", bool(s.whatsapp_app_secret),
                  "official Cloud API webhook with X-Hub-Signature-256 verification"),
        {"name": "osquery", "kind": "telemetry", "status": "Available",
         "detail": "Upload osqueryd.results.log to POST /api/v1/endpoint/osquery (pack in endpoint-agent/osquery/)"},
        {"name": "Wazuh", "kind": "telemetry", "status": "Available",
         "detail": "Upload alerts.json to POST /api/v1/logs/analyze"},
        {"name": "Suricata", "kind": "engine", "status": "Available" if s.suricata_eve_log else "Not configured",
         "detail": "EVE JSON ingestion is planned; no Suricata alerts are read in this version"
                   if not s.suricata_eve_log else f"EVE log path set: {s.suricata_eve_log}"},
        {"name": "Zeek", "kind": "engine", "status": "Available" if s.zeek_log_dir else "Not configured",
         "detail": "Zeek log ingestion is planned; flows come from uploads" if not s.zeek_log_dir
                   else f"Log directory set: {s.zeek_log_dir}"},
        await engine("YaraDetector", "YARA"),
        await engine("ClamAVDetector", "ClamAV"),
    ]
