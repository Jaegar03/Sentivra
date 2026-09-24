"""Application settings.

All configuration is sourced from environment variables (optionally via a
.env file), never hardcoded — see .env.example at the repo root. Nothing in
this module contains a real secret; SENTIVRA_SECRET_KEY etc. must be
overridden per-deployment.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> repo root is three parents up
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTIVRA_",
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "development"
    secret_key: str = "insecure-development-key-override-me"
    database_url: str = f"sqlite:///{REPO_ROOT / 'sentivra.db'}"
    cors_origins: list[str] = ["http://localhost:3000"]
    log_level: str = "INFO"
    rate_limit_per_minute: int = 60

    # Security engines — empty/unset means "probe default location, report
    # Not Configured if absent". Never assumed present.
    yara_rules_dir: Path = REPO_ROOT / "detection-rules" / "yara"
    clamd_socket: str = ""
    clamd_host: str = ""
    clamd_port: int = 3310
    suricata_eve_log: str = ""
    zeek_log_dir: str = ""

    # Model registry root
    models_dir: Path = REPO_ROOT / "models"

    # Rule packs (YARA, Sigma, custom text/URL rules) — kept out of app code
    rules_dir: Path = REPO_ROOT / "detection-rules"

    # Upload limits (security §29)
    max_upload_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_archive_entries: int = 2000
    max_archive_depth: int = 4
    max_archive_uncompressed_bytes: int = 500 * 1024 * 1024  # decompression-bomb cap

    # Text analysis limits. Inputs longer than this are rejected by the API,
    # and every rule regex runs with a per-match timeout, so no single input
    # can pin a worker on a pathological pattern.
    max_text_chars: int = 100_000
    regex_timeout_s: float = 0.05

    # Network uploads (CSV flows or PCAP): hard caps on work per request.
    max_network_flows: int = 200_000
    max_pcap_packets: int = 500_000

    # Opt-in URL enrichment (redirect chain, TLS certificate, RDAP domain
    # age). Off unless a request asks for it: fetching a phishing URL can
    # confirm to its operator that the recipient opened the message.
    url_enrichment_timeout_s: float = 8.0
    url_enrichment_max_redirects: int = 5

    # Gmail (least privilege: gmail.readonly only — see docs/privacy.md)
    gmail_oauth_client_id: str = ""
    gmail_oauth_client_secret: str = ""
    gmail_pubsub_topic: str = ""
    gmail_pubsub_verification_token: str = ""

    # Telegram (official Bot API only)
    telegram_bot_token: str = ""
    telegram_webhook_secret_token: str = ""

    # WhatsApp Business Cloud API (direct to Meta Graph API, no proxy)
    whatsapp_app_secret: str = ""
    whatsapp_access_token: str = ""
    whatsapp_phone_number_id: str = ""
    whatsapp_webhook_verify_token: str = ""

    @property
    def is_demo_secret(self) -> bool:
        return self.secret_key == "insecure-development-key-override-me"


@lru_cache
def get_settings() -> Settings:
    return Settings()
