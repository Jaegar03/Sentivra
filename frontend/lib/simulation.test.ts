import { describe, expect, it } from "vitest";

import { comparisonSummary, createRequestKey, durationMs, hasConfirmedAllow, hasConfirmedBlock, playbackCheckpoint, presentationStage, runOutcome, topologyRoute } from "@/lib/simulation";
import type { SimulationRun } from "@/types/api";

function run(overrides: Partial<SimulationRun> = {}): SimulationRun {
  return {
    execution_id: "exec-1",
    scenario_id: "sqli-indicator",
    scenario_version: "1.0",
    status: "COMPLETED",
    simulation_marker: "SIMULATED EVENT",
    source_type: "SIMULATED",
    detection_state: "DETECTED",
    enforcement_decision: "SIMULATED_BLOCK",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:00:01Z",
    duration_ms: 1000,
    ...overrides,
  };
}

describe("simulation presentation rules", () => {
  it("uses a unique local request key without requiring UUID support", () => {
    const first = createRequestKey();
    const second = createRequestKey();
    expect(first).toBeTruthy();
    expect(second).not.toBe(first);
  });

  it("keeps detection and enforcement outcomes separate", () => {
    expect(runOutcome(run()).kind).toBe("block");
    expect(runOutcome(run({ enforcement_decision: "SIMULATED_ALLOW", detection_state: "NOT_DETECTED" })).kind).toBe("allow");
    expect(runOutcome(run({ status: "PARTIALLY_COMPLETED", enforcement_decision: "SIMULATED_UNAVAILABLE" })).kind).toBe("unavailable");
    expect(runOutcome(run({ status: "FAILED", detection_state: "ANALYSIS_FAILED", enforcement_decision: "SIMULATED_UNAVAILABLE" })).kind).toBe("failed");
  });

  it("routes running and terminal decisions without treating unavailable analysis as allow", () => {
    expect(topologyRoute("allow")?.endpoint).toBe("resource");
    expect(topologyRoute("block")?.endpoint).toBe("enforce");
    expect(topologyRoute("unavailable")?.endpoint).toBe("detector");
    expect(topologyRoute("running")?.endpoint).toBe("detector");
    expect(topologyRoute("running", "network-anomaly")?.nodes).toEqual(["source", "engine", "detector"]);
  });

  it("exposes a visible presentation stage before the backend result arrives", () => {
    expect(presentationStage(0, "running")).toBe("EVENT MOVING TO GATEWAY");
    expect(presentationStage(.7, "block")).toBe("RISK ASSESSMENT");
    expect(presentationStage(.9, "block")).toBe("SIMULATED BLOCK");
  });

  it("derives duration from trusted timestamps when duration is absent", () => {
    expect(durationMs(run({ duration_ms: null }))).toBe(1000);
    expect(durationMs(run({ completed_at: "not-a-timestamp", duration_ms: null }))).toBeNull();
  });

  it("replays recorded lifecycle stages and stops at the verified terminal node", () => {
    const timeline = [
      "fixture_created", "target_request_created", "detectors_started", "detection_completed",
      "risk_assessed", "enforcement_decision", "protected_operation_not_executed", "target_response", "execution_completed",
    ].map((stage) => ({ stage, timestamp: "2026-01-01T00:00:00Z" }));
    expect(playbackCheckpoint(timeline, 0, "block")).toEqual({ label: "STARTED", node: "source" });
    expect(playbackCheckpoint(timeline, .38, "block").label).toBe("DETECTION COMPLETED");
    expect(playbackCheckpoint(timeline, 1, "block")).toEqual({ label: "COMPLETED", node: "enforce" });
    expect(playbackCheckpoint(timeline, 1, "allow").node).toBe("resource");
    expect(playbackCheckpoint(timeline, 1, "unavailable").node).toBe("detector");
  });

  it("counts comparison outcomes only when enforcement and target execution agree", () => {
    const blocked = run({ enforcement_decision: "BLOCKED", target: { endpoint: "synthetic://target", status_code: 403, response: {}, protected_operation_executed: false, target_execution_state: "REJECTED_BEFORE_EXECUTION", request_id: "evt-1" } });
    const allowed = run({ scenario_id: "benign-control", detection_state: "NOT_DETECTED", enforcement_decision: "ALLOWED", target: { endpoint: "synthetic://target", status_code: 200, response: {}, protected_operation_executed: true, target_execution_state: "EXECUTED", request_id: "evt-2" } });
    const failed = run({ status: "FAILED", enforcement_decision: "BLOCKED", target: { endpoint: "synthetic://target", status_code: 403, response: {}, protected_operation_executed: false, target_execution_state: "REJECTED_BEFORE_EXECUTION", request_id: "evt-3" } });
    expect(hasConfirmedBlock(blocked)).toBe(true);
    expect(hasConfirmedAllow(allowed)).toBe(true);
    expect(hasConfirmedBlock(failed)).toBe(false);
    expect(comparisonSummary([blocked, allowed, failed])).toEqual({ executed: 3, blocked: 1, allowed: 1, unverified: 1, complete: false });
  });
});
