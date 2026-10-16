import { describe, expect, it } from "vitest";

import { createRequestKey, durationMs, presentationStage, runOutcome, topologyRoute } from "@/lib/simulation";
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
});
