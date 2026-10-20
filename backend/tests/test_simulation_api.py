"""Command-center guarantees, with real detectors and isolated in-memory DBs.

No test starts the application against a configured/local user database.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api import alerts, audit, events, metrics, simulation
from app.api.deps import get_db, get_detector_registry
from app.core.database import Base
from app.detectors.base import AvailabilityStatus, DetectorAvailability
from app.detectors.clamav_detector import ClamAVDetector
from app.detectors.malware_detector import MalwareDetector
from app.detectors.network_anomaly_detector import NetworkAnomalyDetector
from app.detectors.prompt_detector import PromptInjectionDetector
from app.detectors.registry import DetectorRegistry
from app.detectors.sqli_detector import SQLInjectionDetector
from app.detectors.url_detector import URLDetector
from app.events.schema import EventContent, SecurityEvent, SecurityEventType, SourceType
from app.models.orm import AlertORM, AuditLogORM, EventORM
from app.models.simulation import SimulationExecutionORM
from app.risk.engine import RiskEngine
from app.schemas.detection import FindingStatus
from app.security import auth
from app.services import simulation as service
from app.services.alert_repository import AlertRepository
from app.services.event_repository import EventRepository
from app.services.local_target import synthetic_search_target

REQUIRED = {
    "sqli-indicator", "prompt-injection-indicator", "network-anomaly",
    "suspicious-url", "suspicious-file", "benign-control",
}


@pytest.fixture()
def local_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


@pytest.fixture()
def registry():
    result = DetectorRegistry()
    for detector in (
        SQLInjectionDetector(), PromptInjectionDetector(), URLDetector(),
        MalwareDetector(), NetworkAnomalyDetector(), ClamAVDetector(),
    ):
        result.register(detector)
    return result


@pytest.fixture()
def lab(local_db, registry, monkeypatch):
    app = FastAPI()
    for router in (simulation.router, alerts.router, events.router, metrics.router, audit.router):
        app.include_router(router)
    app.dependency_overrides[get_db] = lambda: local_db
    app.dependency_overrides[get_detector_registry] = lambda: registry
    clients = {
        "alice": auth.Client("alice", "unused", frozenset(auth.SCOPES)),
        "bob": auth.Client("bob", "unused", frozenset(auth.SCOPES)),
        "reader": auth.Client("reader", "unused", frozenset({"read"})),
    }
    monkeypatch.setattr(auth, "load_clients", lambda: clients)
    tokens = {name: auth.issue_token(client)[0] for name, client in clients.items()}
    with TestClient(app) as client:
        client.headers["Authorization"] = f"Bearer {tokens['alice']}"
        yield client, tokens


def run(client, scenario="sqli-indicator", key=None):
    payload = {"scenario_id": scenario, "mode": "simulation"}
    if key is not None:
        payload["request_key"] = key
    return client.post("/api/simulation/run", json=payload)


def test_scenario_registry_is_trusted_and_complete(lab):
    client, _ = lab
    response = client.get("/api/simulation/scenarios")
    assert response.status_code == 200
    rows = response.json()
    assert {row["scenario_id"] for row in rows} == REQUIRED
    assert all(row["simulation_warning"] and row["detector_availability"] for row in rows)
    assert all("ClamAVDetector" not in row["detector_allowlist"] for row in rows)
    assert next(row for row in rows if row["scenario_id"] == "sqli-indicator")["target_endpoint"] == synthetic_search_target.endpoint


@pytest.mark.parametrize("extra", [
    {"mode": "live"}, {"text": "arbitrary"}, {"event": {}}, {"actor_id": "bob"},
    {"detector_allowlist": ["ClamAVDetector"]}, {"request_key": ""},
    {"request_key": "bad key"}, {"request_key": "x" * 129}, {"scenario_id": 1},
])
def test_untrusted_payload_is_rejected(lab, extra):
    client, _ = lab
    payload = {"scenario_id": "sqli-indicator", "mode": "simulation", **extra}
    assert client.post("/api/simulation/run", json=payload).status_code == 422


def test_unknown_scenario_and_bounded_history(lab):
    client, _ = lab
    assert run(client, "nope").status_code == 404
    for query in ("limit=101", "limit=0", "offset=-1", "offset=10001"):
        assert client.get(f"/api/simulation/runs?{query}").status_code == 422


def test_sql_attack_is_rejected_before_protected_operation_and_benign_control_executes(lab):
    client, _ = lab
    synthetic_search_target.reset()
    attack = run(client, "sqli-indicator").json()
    assert attack["detection_state"] == "DETECTED"
    assert attack["enforcement_decision"] == "BLOCKED"
    assert attack["target"]["target_execution_state"] == "REJECTED_BEFORE_EXECUTION"
    assert attack["target"]["protected_operation_executed"] is False
    assert attack["target"]["status_code"] == 403
    attack_stages = [item["stage"] for item in attack["timeline"]]
    assert attack_stages.index("target_request_created") < attack_stages.index("target_handler_entered") < attack_stages.index("protected_operation_not_executed") < attack_stages.index("target_response")
    assert synthetic_search_target.protected_operation_count == 0

    benign = run(client, "benign-control").json()
    assert benign["detection_state"] == "NOT_DETECTED"
    assert benign["enforcement_decision"] == "ALLOWED"
    assert benign["target"]["target_execution_state"] == "EXECUTED"
    assert benign["target"]["protected_operation_executed"] is True
    benign_stages = [item["stage"] for item in benign["timeline"]]
    assert benign_stages.index("target_handler_entered") < benign_stages.index("protected_operation_entered") < benign_stages.index("protected_operation_completed") < benign_stages.index("target_response")
    assert synthetic_search_target.protected_operation_count == 1


def test_target_reset_does_not_delete_simulation_history(lab):
    client, _ = lab
    run(client, "sqli-indicator")
    before = len(client.get("/api/simulation/runs").json())
    reset = client.post("/api/simulation/target/reset")
    assert reset.status_code == 200 and reset.json()["reset"] is True
    assert len(client.get("/api/simulation/runs").json()) == before


@pytest.mark.parametrize("scenario_id", sorted(REQUIRED))
def test_six_real_detector_fixtures_persist_and_match_risk_engine(lab, local_db, registry, scenario_id):
    client, _ = lab
    result = run(client, scenario_id)
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["status"] in {"COMPLETED", "PARTIALLY_COMPLETED"}
    assert body["simulation_marker"] == "SIMULATED EVENT"
    assert body["source_type"] == "SIMULATED"
    assert body["enforcement"]["mode"] == "simulation"
    assert body["enforcement"]["real_world_action_taken"] is False
    assert body["event_id"] and body["risk_assessment"]
    assert body["detector_results"]
    assert {r["detector"] for r in body["detector_results"]} == set(service.SCENARIO_MAP[scenario_id].detector_allowlist)
    # Scores and evidence come from the actual registry implementations, not
    # preset scenario labels or expected outcomes.
    stored_event = EventRepository(local_db).get(body["event_id"])
    event = EventRepository(local_db).to_domain(stored_event)
    detector = registry.get(service.SCENARIO_MAP[scenario_id].detector)
    actual = asyncio.run(detector.analyze(event))
    actual_body = actual.model_dump(mode="json")
    assert body["detector_results"][0]["score"] == actual_body["score"]
    assert body["detector_results"][0]["evidence"] == actual_body["evidence"]
    findings = [actual] if actual.severity.rank else []
    assessment = RiskEngine().assess(event.event_id, findings)
    assert body["risk_assessment"]["risk_score"] == assessment.risk_score
    assert body["risk_assessment"]["severity"] == assessment.severity.value
    if scenario_id == "benign-control":
        assert body["findings"] == []
        assert body["detector_results"][0]["status"] == "no_finding_observed"
        assert body["enforcement_decision"] == "ALLOWED"
    assert client.get(f"/api/simulation/runs/{body['execution_id']}").json() == body
    assert client.get("/api/simulation/runs").json() == [body]
    assert len(local_db.execute(select(AuditLogORM)).scalars().all()) == 1
    if body["alert_id"]:
        alert = AlertRepository(local_db).get(body["alert_id"])
        assert alert.event_id == body["event_id"]
    stamps = [datetime.fromisoformat(item["timestamp"]) for item in body["timeline"]]
    assert stamps == sorted(stamps)
    assert stamps[0] == datetime.fromisoformat(body["started_at"])
    assert stamps[-1] == datetime.fromisoformat(body["completed_at"])
    assert all(stamp.tzinfo is not None for stamp in stamps)
    assert body["duration_ms"] >= 0


def test_no_network_scanner_dns_http_or_process_for_any_fixture(lab, registry, monkeypatch):
    client, _ = lab
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("forbidden")
        raise AssertionError("Simulation attempted an external operation")

    async def forbidden_async(*args, **kwargs):
        return forbidden()

    # Guard actual sockets/DNS/process launches, not just scenario payloads.
    import httpx
    # TestClient uses its own transport through Client.send; patch HTTP network
    # transports instead so in-process API requests are still exercised.
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden_async)
    clamav = registry.get("ClamAVDetector")
    monkeypatch.setattr(clamav, "analyze", forbidden_async)
    monkeypatch.setattr(clamav, "is_available", forbidden_async)
    assert client.get("/api/simulation/scenarios").status_code == 200
    for scenario_id in REQUIRED:
        assert run(client, scenario_id).status_code == 200
    assert calls == []


def test_requires_read_and_analyze_scopes(lab):
    client, tokens = lab
    client.headers.pop("Authorization")
    for path in ("scenarios", "runs", "stats", f"runs/{uuid.uuid4()}"):
        assert client.get(f"/api/simulation/{path}").status_code == 401
    assert run(client).status_code == 401
    client.headers["Authorization"] = f"Bearer {tokens['reader']}"
    assert run(client).status_code == 403
    assert client.get("/api/simulation/stats").status_code == 200


def test_actor_isolation_including_linked_event_alert_and_audit(lab):
    client, tokens = lab
    body = run(client).json()
    assert body["alert_id"]
    for kind, key in (("events", "event_id"), ("alerts", "alert_id")):
        assert client.get(f"/api/v1/{kind}/{body[key]}").status_code == 200
    assert client.get("/api/simulation/stats").json()["totals"]["runs"] == 1
    client.headers["Authorization"] = f"Bearer {tokens['bob']}"
    assert client.get(f"/api/simulation/runs/{body['execution_id']}").status_code == 404
    assert client.get("/api/simulation/runs").json() == []
    assert client.get("/api/simulation/stats").json()["totals"]["runs"] == 0
    for kind, key in (("events", "event_id"), ("alerts", "alert_id")):
        assert client.get(f"/api/v1/{kind}/{body[key]}").status_code == 404
        assert client.get(f"/api/v1/{kind}?limit=1").json() == []
    assert client.get("/api/v1/audit").json()["total"] == 0
    assert client.patch(f"/api/v1/alerts/{body['alert_id']}", json={"status": "RESOLVED"}).status_code == 404
    assert client.get("/api/v1/metrics").json()["window"]["simulation_alerts_excluded"] == 0
    other = run(client, "benign-control").json()
    assert other["execution_id"] != body["execution_id"]
    assert client.get("/api/simulation/runs?limit=1").json()[0]["execution_id"] == other["execution_id"]
    # Re-ingestion cannot return another actor's persisted alert by event ID.
    event = SecurityEvent(
        event_id=body["event_id"], event_type=SecurityEventType.SQL_ANALYSIS,
        source="ingest", source_type=SourceType.LIVE, content=EventContent(body="test"),
    )
    assert client.post("/api/v1/events", json=event.model_dump(mode="json")).status_code == 409
    event.event_id, event.source = str(uuid.uuid4()), "cyber-defense-lab"
    assert client.post("/api/v1/events", json=event.model_dump(mode="json")).status_code == 422


def test_idempotency_is_actor_scoped_and_conflicting_payload_rejected(lab, local_db):
    client, tokens = lab
    first = run(client, key="one-click").json()
    assert run(client, key="one-click").json() == first
    assert run(client, "benign-control", "one-click").status_code == 409
    assert local_db.scalar(select(func.count()).select_from(EventORM)) == 1
    assert local_db.scalar(select(func.count()).select_from(AlertORM)) == 1
    client.headers["Authorization"] = f"Bearer {tokens['bob']}"
    assert run(client, key="one-click").json()["execution_id"] != first["execution_id"]
    assert local_db.scalar(select(func.count()).select_from(SimulationExecutionORM)) == 2
    row = SimulationExecutionORM(
        actor_id="alice", request_key="one-click", scenario_id="sqli-indicator", scenario_version="1",
        status="FAILED", detection_state="ANALYSIS_FAILED", enforcement_decision="SIMULATED_UNAVAILABLE",
        result_json="{}",
    )
    local_db.add(row)
    with pytest.raises(IntegrityError):
        local_db.commit()
    local_db.rollback()


def test_sql_statistics_are_not_a_history_page(lab, local_db):
    client, _ = lab
    start = datetime.now(UTC) - timedelta(days=2)
    for index in range(135):
        local_db.add(SimulationExecutionORM(
            actor_id="alice", request_key=str(index), scenario_id="benign-control", scenario_version="1",
            status="COMPLETED", detection_state="NOT_DETECTED", enforcement_decision="SIMULATED_ALLOW",
            result_json="deliberately not loaded as JSON by statistics", duration_ms=index,
            started_at=start + timedelta(minutes=index),
        ))
    local_db.commit()
    statements = []

    def capture(conn, cursor, statement, params, context, executemany):
        statements.append(statement)

    sqlalchemy_event.listen(local_db.bind, "before_cursor_execute", capture)
    try:
        body = client.get("/api/simulation/stats").json()
    finally:
        sqlalchemy_event.remove(local_db.bind, "before_cursor_execute", capture)
    assert body["totals"]["runs"] == body["totals"]["completed"] == 135
    assert body["by_scenario"][0]["avg_duration_ms"] == 67
    assert len(body["timeline"]) == 100 and body["timeline_truncated"] is True
    assert datetime.fromisoformat(body["timeline"][-1]["timestamp"]) == start + timedelta(minutes=134)
    assert any("GROUP BY" in statement for statement in statements)
    assert all("result_json" not in statement for statement in statements)


@pytest.mark.parametrize("failure", ["exception", "timeout", "unavailable", "partial", "availability_error"])
def test_failure_never_claims_allow_or_block_and_sanitizes(lab, registry, monkeypatch, failure):
    client, _ = lab
    detector = registry.get("SQLInjectionDetector")
    secret = "SECRET=do-not-store C:/private/credentials.sqlite"
    if failure == "exception":
        monkeypatch.setattr(detector, "analyze", AsyncMock(side_effect=RuntimeError(secret)))
    elif failure == "timeout":
        async def slow(event):
            await asyncio.sleep(10)
        monkeypatch.setattr(detector, "analyze", slow)
        monkeypatch.setattr(service, "SIMULATION_TIMEOUT_SECONDS", 0.01)
    elif failure == "unavailable":
        registry.clear()
    elif failure == "availability_error":
        monkeypatch.setattr(detector, "is_available", AsyncMock(side_effect=RuntimeError(secret)))
    else:
        original = detector.analyze
        async def partial(event):
            result = await original(event)
            return result.model_copy(update={"status": FindingStatus.PARTIAL_ANALYSIS})
        monkeypatch.setattr(detector, "analyze", partial)
    response = run(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] in {"FAILED", "PARTIALLY_COMPLETED"}
    assert body["enforcement_decision"] in {"ENFORCEMENT_UNAVAILABLE", "SIMULATED_UNAVAILABLE", "SIMULATED_REVIEW"}
    assert body["enforcement"]["real_world_action_taken"] is False
    assert body["errors"]
    assert secret not in json.dumps(body)
    if failure == "partial":
        assert body["findings"] and body["detector_results"]
        assert body["risk_assessment"]["analysis_status"] == "partial_analysis"
    if failure == "exception":
        assert body["detector_results"][0]["status"] == "internal_error"
    assert client.get(f"/api/simulation/runs/{body['execution_id']}").json() == body


def test_partial_results_and_safe_results_survive_sibling_timeout(lab, registry, monkeypatch):
    client, _ = lab
    scenario = service.SCENARIO_MAP["benign-control"]
    monkeypatch.setitem(service.SCENARIO_MAP, "benign-control", replace(
        scenario, detector_allowlist=("PromptInjectionDetector", "SQLInjectionDetector"),
    ))
    async def slow(event):
        await asyncio.sleep(10)
    monkeypatch.setattr(registry.get("SQLInjectionDetector"), "analyze", slow)
    monkeypatch.setattr(service, "SIMULATION_TIMEOUT_SECONDS", 0.01)
    body = run(client, "benign-control").json()
    assert body["status"] == "FAILED"
    assert body["enforcement_decision"] == "SIMULATED_UNAVAILABLE"
    assert body["detector_results"][0]["detector"] == "PromptInjectionDetector"
    assert body["detector_results"][0]["status"] == "no_finding_observed"


def test_degraded_availability_preserves_findings_without_block(lab, registry, monkeypatch):
    client, _ = lab
    detector = registry.get("SQLInjectionDetector")
    monkeypatch.setattr(detector, "is_available", AsyncMock(return_value=DetectorAvailability(
        status=AvailabilityStatus.DEGRADED, detail="private raw model error",
    )))
    body = run(client).json()
    assert body["status"] == "PARTIALLY_COMPLETED" and body["findings"]
    assert body["enforcement_decision"] == "ENFORCEMENT_UNAVAILABLE"
    assert "private raw model error" not in json.dumps(body)


def test_storage_failure_rolls_back_event_alert_and_audit_then_records_failure(lab, local_db, monkeypatch):
    client, _ = lab
    def broken_create(self, assessment, **kwargs):
        raise OperationalError("INSERT secret-path", {}, RuntimeError("secret"))
    monkeypatch.setattr(AlertRepository, "create", broken_create)
    body = run(client, key="retry-failure").json()
    assert body["status"] == "FAILED"
    assert body["event_id"] is None and body["alert_id"] is None
    assert body["detector_results"] and body["findings"]
    assert body["enforcement_decision"] == "SIMULATED_UNAVAILABLE"
    assert "secret" not in json.dumps(body)
    assert local_db.scalar(select(func.count()).select_from(EventORM)) == 0
    assert local_db.scalar(select(func.count()).select_from(AlertORM)) == 0
    assert local_db.scalar(select(func.count()).select_from(AuditLogORM)) == 0
    assert run(client, key="retry-failure").json() == body


def test_commit_failure_returns_sanitized_service_error(lab, local_db, monkeypatch):
    client, _ = lab
    monkeypatch.setattr(local_db, "commit", lambda: (_ for _ in ()).throw(
        OperationalError("SECRET SQL", {}, RuntimeError("private db path")),
    ))
    response = run(client)
    assert response.status_code == 503
    assert "SECRET" not in response.text and "private" not in response.text
    # The session has been explicitly rolled back and is usable again.
    assert local_db.scalar(select(func.count()).select_from(SimulationExecutionORM)) == 0


def test_bounded_capacity_rejects_without_writing(lab, local_db, monkeypatch):
    client, _ = lab
    import threading
    monkeypatch.setattr(service, "_RUN_SLOTS", threading.BoundedSemaphore(0))
    assert run(client).status_code == 429
    assert local_db.scalar(select(func.count()).select_from(SimulationExecutionORM)) == 0


def test_final_commit_failure_is_atomic(lab, local_db, monkeypatch):
    client, _ = lab
    original = local_db.commit
    count = 0

    def commit():
        nonlocal count
        count += 1
        if count == 2:
            raise OperationalError("SECRET INSERT", {}, RuntimeError("private"))
        original()

    monkeypatch.setattr(local_db, "commit", commit)
    body = run(client, key="commit-failure").json()
    assert body["status"] == "FAILED" and body["enforcement_decision"] == "SIMULATED_UNAVAILABLE"
    assert body["event_id"] is None and body["alert_id"] is None
    assert body["findings"] and body["risk_assessment"]["analysis_status"] == "partial_analysis"
    for model in (EventORM, AlertORM, AuditLogORM):
        assert local_db.scalar(select(func.count()).select_from(model)) == 0
    assert run(client, key="commit-failure").json() == body


@pytest.mark.asyncio
async def test_concurrent_retry_reuses_running_reservation(local_db, registry, monkeypatch):
    entered, finish = asyncio.Event(), asyncio.Event()
    detector = registry.get("PromptInjectionDetector")
    original = detector.analyze
    calls = 0

    async def delayed(event):
        nonlocal calls
        calls += 1
        entered.set()
        await finish.wait()
        return await original(event)

    monkeypatch.setattr(detector, "analyze", delayed)
    with Session(local_db.bind) as first_db, Session(local_db.bind) as retry_db:
        pending = asyncio.create_task(service.run_simulation(
            first_db, registry, "benign-control", actor="alice", request_key="concurrent",
        ))
        await asyncio.wait_for(entered.wait(), 2)
        replay = await service.run_simulation(
            retry_db, registry, "benign-control", actor="alice", request_key="concurrent",
        )
        assert replay.status == "RUNNING" and replay.enforcement_decision == "SIMULATED_REVIEW"
        finish.set()
        completed = await pending
        assert completed.execution_id == replay.execution_id
        assert completed.status == "COMPLETED"
    assert calls == 1
    assert local_db.scalar(select(func.count()).select_from(EventORM)) == 1


@pytest.mark.asyncio
async def test_unique_constraint_race_replays_winner(local_db, registry, monkeypatch):
    first = await service.run_simulation(local_db, registry, "benign-control", actor="alice", request_key="race")
    identifier = first.execution_id
    original = service._existing
    calls = 0

    def miss_once(*args):
        nonlocal calls
        calls += 1
        return None if calls == 1 else original(*args)

    monkeypatch.setattr(service, "_existing", miss_once)
    replay = await service.run_simulation(local_db, registry, "benign-control", actor="alice", request_key="race")
    assert replay.execution_id == identifier
    assert local_db.scalar(select(func.count()).select_from(EventORM)) == 1


@pytest.mark.asyncio
async def test_cancellation_records_terminal_failure(local_db, registry, monkeypatch):
    entered = asyncio.Event()

    async def delayed(event):
        entered.set()
        await asyncio.sleep(10)

    monkeypatch.setattr(registry.get("PromptInjectionDetector"), "analyze", delayed)
    pending = asyncio.create_task(service.run_simulation(
        local_db, registry, "benign-control", actor="alice", request_key="cancelled",
    ))
    await asyncio.wait_for(entered.wait(), 2)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    row = service.recent(local_db, 1, 0, actor="alice")[0]
    assert row.status == "FAILED" and row.enforcement_decision == "SIMULATED_UNAVAILABLE"
    assert row.event_id is None


def test_rule_timeout_is_partial_even_when_other_rules_detect(lab, registry, monkeypatch):
    from types import SimpleNamespace

    from app.core.rules import RuleTimeout

    client, _ = lab
    detector = registry.get("SQLInjectionDetector")

    def timed_out(text):
        raise RuleTimeout("private regexp details")

    monkeypatch.setattr(detector, "rules", [
        SimpleNamespace(id="timeout-test", extra={}, search=timed_out), *detector.rules,
    ])
    body = run(client).json()
    assert body["status"] == "PARTIALLY_COMPLETED" and body["findings"]
    assert body["enforcement_decision"] == "ENFORCEMENT_UNAVAILABLE"
    assert body["detector_results"][0]["status"] == "partial_analysis"
    assert "private regexp details" not in json.dumps(body)


def test_availability_timeout_and_error_do_not_break_scenario_listing(lab, registry, monkeypatch):
    client, _ = lab
    monkeypatch.setattr(registry.get("SQLInjectionDetector"), "is_available", AsyncMock(
        side_effect=RuntimeError("SECRET path"),
    ))
    async def slow():
        await asyncio.sleep(10)
    monkeypatch.setattr(registry.get("PromptInjectionDetector"), "is_available", slow)
    monkeypatch.setattr(service, "AVAILABILITY_TIMEOUT_SECONDS", 0.01)
    response = client.get("/api/simulation/scenarios")
    assert response.status_code == 200
    rows = {row["scenario_id"]: row for row in response.json()}
    assert rows["sqli-indicator"]["detector_availability"]["status"] == "Error"
    assert rows["benign-control"]["detector_availability"]["status"] == "Error"
    assert "SECRET" not in response.text


def test_legacy_schema_upgrade_is_additive_and_does_not_guess_owner(monkeypatch):
    from sqlalchemy import inspect, text

    from app.core import database

    engine = create_engine("sqlite://", poolclass=StaticPool)
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE simulation_executions (
                execution_id VARCHAR(36) PRIMARY KEY, scenario_id VARCHAR(64), scenario_version VARCHAR(32),
                status VARCHAR(32), source_type VARCHAR(16), event_id VARCHAR(36), alert_id VARCHAR(36),
                detection_state VARCHAR(32), enforcement_decision VARCHAR(32), duration_ms FLOAT,
                result_json TEXT, error_detail TEXT, started_at DATETIME, completed_at DATETIME, created_at DATETIME
            )
        """))
        connection.execute(text("""
            INSERT INTO simulation_executions (execution_id, scenario_id, scenario_version,
                status, detection_state, enforcement_decision, result_json, started_at, created_at)
            VALUES ('legacy-id', 'benign-control', '1', 'COMPLETED', 'NOT_DETECTED',
                'SIMULATED_ALLOW', '{}', '2025-01-01', '2025-01-01')
        """))
    monkeypatch.setattr(database, "engine", engine)
    database.init_db()
    database.init_db()  # restarting does not rewrite or duplicate records
    with Session(engine) as session:
        old = session.get(SimulationExecutionORM, "legacy-id")
        assert old.actor_id is None
        assert old.request_key == "legacy-id"
        assert service.get_execution(session, "legacy-id", actor="system") is None
    indexes = inspect(engine).get_indexes("simulation_executions")
    assert any(index["unique"] and index["column_names"] == ["actor_id", "request_key"] for index in indexes)
    engine.dispose()


def test_command_center_excluded_from_every_operational_metric_preserving_old_demos(lab, local_db, registry):
    client, _ = lab
    # Existing endpoint SIMULATED and bundled DEMO_DATA records must retain
    # their pre-command-center contribution to operational metrics.
    for source_type in (SourceType.SIMULATED, SourceType.DEMO_DATA):
        event = SecurityEvent(
            event_type=SecurityEventType.SQL_ANALYSIS, source="older-demo", source_type=source_type,
            content=EventContent(body="' OR '1'='1"),
        )
        finding = asyncio.run(registry.get("SQLInjectionDetector").analyze(event))
        EventRepository(local_db).create_if_absent(event)
        AlertRepository(local_db).create(RiskEngine().assess(event.event_id, [finding]))
    before = client.get("/api/v1/metrics").json()
    assert before["totals"] == {"events": 2, "alerts": 2}
    assert before["window"]["by_source_type"] == {"SIMULATED": 1, "DEMO_DATA": 1}
    run(client)
    run(client, "benign-control")
    after = client.get("/api/v1/metrics").json()
    assert after["totals"] == before["totals"]
    assert after["security_score"] == before["security_score"]
    for key in ("alerts", "open_alerts", "by_severity", "open_by_severity", "by_status", "by_classification",
                "by_detector", "by_domain", "by_source_type", "alert_quality"):
        assert after["window"][key] == before["window"][key], key
    assert after["window"]["timeline"]["counts"] == before["window"]["timeline"]["counts"]
    assert after["window"]["simulation_alerts_excluded"] == 1
