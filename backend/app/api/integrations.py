"""GET /api/v1/integrations — what is actually connected, as opposed to what
is planned (brief §32: "Gmail — Not Connected", never a fake green light).

Status values:
  Connected       a configured webhook that has already delivered at least one
                  event (counted from the events table, not assumed)
  Available       an ingestion path that works today: the upload endpoints,
                  and a configured connector whose endpoint is ready but has
                  received nothing yet
  Not configured  an engine or connector missing its credentials or paths
  Not implemented a connector that doesn't exist yet
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.core.config import get_settings
from app.detectors.registry import DetectorRegistry
from app.security.auth import require_scopes
from app.services.event_repository import EventRepository

router = APIRouter(prefix="/api/v1", tags=["integrations"], dependencies=[Depends(require_scopes("read"))])


@router.get("/integrations")
async def list_integrations(db: Session = Depends(get_db),
                            registry: DetectorRegistry = Depends(get_detector_registry)) -> list[dict]:
    s = get_settings()

    def messaging(name: str, source: str, configured: bool, missing: list[str], scope: str) -> dict:
        """A webhook connector: configured + never heard from is 'Available';
        configured + delivered events is 'Connected'; anything less says
        exactly which variable is missing rather than claiming coverage."""
        received = EventRepository(db).count_by_source(source) if configured else 0
        endpoint = f"POST /api/v1/integrations/{source}/webhook"
        if not configured:
            status, detail = "Not configured", (
                f"The endpoint exists ({endpoint}) but the connector is not configured: set "
                + ", ".join(missing) + f". {scope}.")
        elif received:
            status, detail = "Connected", (
                f"Verified webhooks accepted at {endpoint}; {received} message event(s) stored. {scope}.")
        else:
            status, detail = "Available", (
                f"Webhook endpoint ready at {endpoint}; no messages received yet. {scope}.")
        return {"name": name, "kind": "messaging", "status": status,
                "credentials_configured": configured, "detail": detail}

    async def engine(detector_name: str, label: str) -> dict:
        detector = registry.get(detector_name)
        if detector is None:
            return {"name": label, "kind": "engine", "status": "Not configured", "detail": "Detector not registered"}
        availability = await detector.is_available()
        status = "Available" if availability.status.value == "Available" else "Not configured"
        return {"name": label, "kind": "engine", "status": status, "detail": availability.detail,
                "engine_version": availability.engine_version}

    return [
        messaging("Gmail", "gmail",
                  configured=bool(s.gmail_oauth_client_id and s.gmail_oauth_client_secret
                                  and s.gmail_oauth_refresh_token),
                  missing=["SENTIVRA_GMAIL_OAUTH_CLIENT_ID", "SENTIVRA_GMAIL_OAUTH_CLIENT_SECRET",
                           "SENTIVRA_GMAIL_OAUTH_REFRESH_TOKEN"],
                  scope="OAuth2 with gmail.readonly; the Pub/Sub push is JWT-verified against Google's "
                        "certificates, and message bodies are hashed, not stored"),
        messaging("Telegram", "telegram",
                  configured=bool(s.telegram_bot_token and s.telegram_webhook_secret_token),
                  missing=["SENTIVRA_TELEGRAM_BOT_TOKEN", "SENTIVRA_TELEGRAM_WEBHOOK_SECRET_TOKEN"],
                  scope="official Bot API webhook authenticated with the secret_token header; only "
                        "messages sent to the bot are ever received"),
        messaging("WhatsApp Business", "whatsapp",
                  configured=bool(s.whatsapp_app_secret and s.whatsapp_webhook_verify_token),
                  missing=["SENTIVRA_WHATSAPP_APP_SECRET", "SENTIVRA_WHATSAPP_WEBHOOK_VERIFY_TOKEN"],
                  scope="official Cloud API webhook with X-Hub-Signature-256 verification, direct to "
                        "Meta's Graph API; media bytes are never fetched"),
        {"name": "osquery", "kind": "telemetry", "status": "Available",
         "detail": "Upload osqueryd.results.log to POST /api/v1/endpoint/osquery (pack in endpoint-agent/osquery/)"},
        {"name": "Wazuh", "kind": "telemetry", "status": "Available",
         "detail": "Upload alerts.json to POST /api/v1/logs/analyze"},
        # Setting a path doesn't make these work: nothing reads EVE or Zeek
        # logs yet, so reporting "Available" would claim signature coverage
        # that doesn't exist. Same rule as the messaging connectors above.
        {"name": "Suricata", "kind": "engine", "status": "Not implemented",
         "credentials_configured": bool(s.suricata_eve_log),
         "detail": "EVE JSON ingestion is planned; no Suricata alerts are read in this version. "
                   + ("SENTIVRA_SURICATA_EVE_LOG is set but nothing reads it yet." if s.suricata_eve_log
                      else "No EVE log path configured.")},
        {"name": "Zeek", "kind": "engine", "status": "Not implemented",
         "credentials_configured": bool(s.zeek_log_dir),
         "detail": "Zeek log ingestion is planned; flows come from uploads. "
                   + ("SENTIVRA_ZEEK_LOG_DIR is set but nothing reads it yet." if s.zeek_log_dir
                      else "No Zeek log directory configured.")},
        await engine("YaraDetector", "YARA"),
        await engine("ClamAVDetector", "ClamAV"),
    ]