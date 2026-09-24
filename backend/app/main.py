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

from app.api import (
    alerts,
    analyze,
    audit,
    detectors,
    endpoint,
    events,
    health,
    integrations,
    logs,
    metrics,
    models,
    network,
    rules,
)
from app.core.config import get_settings
from app.core.database import init_db
from app.detectors.behavioral_anomaly_detector import BehavioralAnomalyDetector
from app.detectors.clamav_detector import ClamAVDetector
from app.detectors.log_detector import LogDetector
from app.detectors.malware_detector import MalwareDetector
from app.detectors.network.suite import get_suite
from app.detectors.network_anomaly_detector import NetworkAnomalyDetector
from app.detectors.registry import registry as detector_registry
from app.detectors.sigma_detector import SigmaDetector
from app.detectors.yara_detector import YaraDetector
from app.security.headers import SecureHeadersMiddleware
from app.security.rate_limit import RateLimitMiddleware

logging.basicConfig(level=get_settings().log_level)
logger = logging.getLogger("sentivra")


def _register_detectors() -> None:
    """The single place BaseDetector implementations are wired up
    (docs/architecture.md §4). Detectors still to come (SQLi, phishing/URL,
    prompt injection) register here as they land."""
    # Idempotent: a fresh registry state on every startup. In production
    # this runs once; test suites that spin up multiple TestClient(app)
    # instances against the same module-level app trigger startup more
    # than once, and re-registering must not raise.
    detector_registry.clear()
    for detector in (MalwareDetector(), YaraDetector(), ClamAVDetector(), NetworkAnomalyDetector(),
                     SigmaDetector(), LogDetector(), BehavioralAnomalyDetector()):
        detector_registry.register(detector)
    # Load (and SHA-256-verify) the network models now rather than on the
    # first request, so /health reports their real state immediately.
    get_suite()


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
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(detectors.router)
    app.include_router(models.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(analyze.router)
    app.include_router(network.router)
    app.include_router(endpoint.router)
    app.include_router(logs.router)
    app.include_router(rules.router)
    app.include_router(metrics.router)
    app.include_router(audit.router)
    app.include_router(integrations.router)

    return app


app = create_app()
