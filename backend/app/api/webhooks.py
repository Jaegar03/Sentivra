"""Webhook ingress: POST /api/v1/integrations/{gmail,telegram,whatsapp}/webhook
(brief §25, Phase 7).

These four routes are the only ones on this API without a SENTIVRA bearer
token — the callers are Google, Telegram and Meta, which cannot hold one.
They authenticate with provider secrets instead, verified *before* anything
is parsed (`app/security/webhooks.py`, `docs/threat-model.md` Boundary A),
and the routes are otherwise ordinary: the verified payload is normalized
into a `SecurityEvent` and handed to the same pipeline every other source
uses.

What happens to a message once it arrives (docs/privacy.md):
  * the detectors see the full body, in memory, for this request only;
  * the stored event carries hash + metadata, never the body
    (`integrations.common.without_body`);
  * a redelivery is recognized by its deterministic event id and counted as
    a duplicate instead of analyzed twice.

The response says only what was accepted — no findings are echoed back to
the provider.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.core.config import get_settings
from app.detectors.registry import DetectorRegistry
from app.integrations.common import WebhookOutcome, WebhookRejected, without_body
from app.integrations.gmail.webhook import collect as gmail_collect
from app.integrations.telegram.webhook import collect as telegram_collect
from app.integrations.whatsapp.webhook import collect as whatsapp_collect
from app.integrations.whatsapp.webhook import verify_subscription
from app.services.event_repository import EventRepository
from app.services.pipeline import run_pipeline

logger = logging.getLogger("sentivra.webhooks")

router = APIRouter(prefix="/api/v1/integrations", tags=["webhooks"])

NO_COVERAGE_NOTE = (
    "No detector in this build analyzes message content yet (the phishing, URL and prompt-injection "
    "detectors are Phase 4), so no detection verdict was produced — the event was stored as-is."
)


async def _ingest(provider: str, outcome: WebhookOutcome, *, db: Session,
                  registry: DetectorRegistry) -> dict:
    repo = EventRepository(db)
    accepted = duplicates = 0
    event_ids: list[str] = []
    detectors: list[str] = []
    for event in outcome.events:
        if repo.get(event.event_id) is not None:
            duplicates += 1  # provider redelivery: same event, not a second alert
            continue
        if not detectors:
            detectors = [d.name for d in registry.applicable_to(event)]
        # Detectors analyze the body; the redacted copy is what gets stored.
        await run_pipeline(event, db=db, registry=registry,
                           actor=f"webhook:{provider}", persist=without_body(event))
        event_ids.append(event.event_id)
        accepted += 1

    notes = [n for n in (outcome.note, NO_COVERAGE_NOTE if outcome.events and not detectors else None) if n]
    logger.info("webhook %s: accepted=%d duplicates=%d ignored=%d",
                provider, accepted, duplicates, outcome.ignored)
    return {
        "status": "ok",
        "provider": provider,
        "accepted": accepted,
        "duplicates": duplicates,
        "ignored": outcome.ignored,
        "event_ids": event_ids,
        "detectors": detectors,
        "note": " ".join(notes) if notes else None,
    }


def _reject(exc: WebhookRejected) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/gmail/webhook")
async def gmail_webhook(request: Request, db: Session = Depends(get_db),
                        registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    settings = get_settings()
    try:
        outcome = await gmail_collect(await request.body(), headers=request.headers,
                                      query=request.query_params, settings=settings)
    except WebhookRejected as exc:
        raise _reject(exc) from exc
    return await _ingest("gmail", outcome, db=db, registry=registry)


@router.post("/telegram/webhook")
async def telegram_webhook(request: Request, db: Session = Depends(get_db),
                           registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    settings = get_settings()
    try:
        outcome = telegram_collect(await request.body(), headers=request.headers,
                                   query=request.query_params, settings=settings)
    except WebhookRejected as exc:
        raise _reject(exc) from exc
    return await _ingest("telegram", outcome, db=db, registry=registry)


@router.get("/whatsapp/webhook")
async def whatsapp_webhook_verify(request: Request) -> PlainTextResponse:
    """Meta's subscription handshake: echo the challenge when the token matches."""
    try:
        challenge = verify_subscription(query=request.query_params, settings=get_settings())
    except WebhookRejected as exc:
        raise _reject(exc) from exc
    return PlainTextResponse(content=challenge)


@router.post("/whatsapp/webhook")
async def whatsapp_webhook(request: Request, db: Session = Depends(get_db),
                           registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    settings = get_settings()
    try:
        outcome = whatsapp_collect(await request.body(), headers=request.headers,
                                   query=request.query_params, settings=settings)
    except WebhookRejected as exc:
        raise _reject(exc) from exc
    return await _ingest("whatsapp", outcome, db=db, registry=registry)
