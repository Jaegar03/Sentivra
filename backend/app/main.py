"""SENTIVRA FastAPI application factory.

Run locally with:
    cd backend
    pip install -e .[dev]
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, analyze, detectors, events, health, models
from app.core.config import get_settings
from app.core.database import init_db
from app.detectors.clamav_detector import ClamAVDetector
from app.detectors.malware_detector import MalwareDetector
from app.detectors.registry import registry as detector_registry
from app.detectors.yara_detector import YaraDetector
from app.security.headers import SecureHeadersMiddleware
from app.security.rate_limit import RateLimitMiddleware

logging.basicConfig(level=get_settings().log_level)
logger = logging.getLogger("sentivra")


def _register_detectors() -> None:
    """Phase 3 detectors. Phase 4+ detectors (SQLi/Phishing/URL/PromptInjection/
    NetworkAnomaly/Behavioral/Sigma/Log) register here as they land — this
    function is the single place BaseDetector implementations are wired up
    (docs/architecture.md §4)."""
    # Idempotent: a fresh registry state on every startup. In production
    # this runs once; test suites that spin up multiple TestClient(app)
    # instances against the same module-level app trigger startup more
    # than once, and re-registering must not raise.
    detector_registry.clear()
    for detector in (MalwareDetector(), YaraDetector(), ClamAVDetector()):
        detector_registry.register(detector)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = get_settings()
    if settings.is_demo_secret:
        logger.warning(
            "SENTIVRA_SECRET_KEY is unset — using the insecure development default. "
            "Set a real secret before exposing this instance beyond localhost."
        )
    init_db()
    _register_detectors()
    logger.info("SENTIVRA backend started (env=%s)", settings.env)
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="SENTIVRA API",
        description="One Security Layer. Every Threat.",
        version="0.1.0",
        lifespan=_lifespan,
    )

    app.add_middleware(SecureHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(detectors.router)
    app.include_router(models.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(analyze.router)

    return app


app = create_app()
