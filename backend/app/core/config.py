"""Application settings.

All configuration is sourced from environment variables (optionally via a
.env file), never hardcoded — see .env.example at the repo root. Nothing in
this module contains a real secret; SENTIVRA_SECRET_KEY etc. must be
overridden per-deployment.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# backend/app/core/config.py -> repo root is three parents up
REPO_ROOT = Path(__file__).resolve().parents[3]

# Signing secrets that appear in this repository (old defaults, template
# placeholders). Anyone can read them, so a token signed with one proves nothing.
PUBLISHED_SECRETS = frozenset({
    "insecure-development-key-override-me",
    "changeme-generate-a-real-secret",
    "changeme",
})
# RFC 7518 §3.2: an HS256 key must be at least 256 bits. 32 characters of
# token_urlsafe output carry more than that.
MIN_SECRET_KEY_CHARS = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTIVRA_",
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "development"
    # JWT signing secret. Leave unset in development: a random per-install key
    # is generated in state_dir. Required outside development.
    secret_key: str = ""
    database_url: str = f"sqlite:///{REPO_ROOT / 'sentivra.db'}"
    # Browsers treat localhost and 127.0.0.1 as different origins, so both
    # local spellings of the dashboard are allowed by default.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    log_level: str = "INFO"
    # Per client IP. The dashboard makes several requests per page view (plus
    # health polling), so 60/min was reachable by one person clicking around.
    rate_limit_per_minute: int = 300

    # ---- API authentication (OAuth2 client-credentials; app.security.auth) ----
    # "client_id:secret:scope scope;client_id2:secret2:scope" or a JSON list of
    # {"client_id", "client_secret", "scopes"}. When empty in development, a
    # dashboard client is generated on first start (see state_dir).
    oauth_clients: str = ""
    token_ttl_s: int = 3600
    # The token endpoint gets a much tighter limit than the rest of the API:
    # it's the one place a client secret can be guessed.
    token_rate_limit_per_minute: int = 10
    # Local, gitignored state: generated signing key and client-secret hashes.
    state_dir: Path = REPO_ROOT / ".sentivra"

    # Request body caps, enforced while the body is received (before parsing).
    max_json_bytes: int = 1 * 1024 * 1024

    @property
    def is_development(self) -> bool:
        return self.env.lower() in ("development", "dev", "test")

    @field_validator("yara_rules_dir", "models_dir", "rules_dir", "state_dir", mode="after")
    @classmethod
    def _resolve_against_repo(cls, value: Path) -> Path:
        """Relative directories in .env mean "relative to the repo", not to
        whatever directory uvicorn happened to be started from."""
        return value if value.is_absolute() else REPO_ROOT / value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        """Accept "a,b" (what people write in .env files) as well as a JSON list."""
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                return json.loads(text)
            return [origin.strip() for origin in text.split(",") if origin.strip()]
        return value

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

    # Endpoint telemetry (osquery results) and log uploads.
    max_endpoint_rows: int = 200_000
    max_log_lines: int = 200_000

    # Opt-in URL enrichment (redirect chain, TLS certificate, RDAP domain
    # age). Off unless a request asks for it: fetching a phishing URL can
    # confirm to its operator that the recipient opened the message.
    url_enrichment_timeout_s: float = 8.0
    url_enrichment_max_redirects: int = 5

    # Gmail (least privilege: gmail.readonly only — see docs/privacy.md)
    # The push endpoint proves the request is Google's (RS256 JWT against
    # Google's published certs). The refresh token is how the connector then
    # reads the mailbox it was watching, always with gmail.readonly.
    gmail_oauth_client_id: str = ""
    gmail_oauth_client_secret: str = ""
    gmail_oauth_refresh_token: str = ""
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
    def secret_key_is_unsafe(self) -> bool:
        """Unset, published in this repo, or too short to be an HS256 key."""
        key = self.secret_key.strip()
        return key in PUBLISHED_SECRETS or len(key) < MIN_SECRET_KEY_CHARS


@lru_cache
def get_settings() -> Settings:
    return Settings()
