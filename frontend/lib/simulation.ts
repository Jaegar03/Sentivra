import type { SimulationRun, SimulationScenario } from "@/types/api";

export const SIMULATION_NOTICE = "SIMULATION ONLY. No real network traffic, system processes, or external applications were blocked.";
export const HISTORY_PAGE_SIZE = 8;

export function createRequestKey() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  }
  return `simulation-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export type OutcomeKind = "idle" | "running" | "block" | "allow" | "review" | "unavailable" | "failed";
export type OutcomeTone = "neutral" | "cyan" | "violet" | "amber" | "red" | "green";

const outcomes: Record<OutcomeKind, { label: string; tone: OutcomeTone; explanation: string }> = {
  idle: { label: "Awaiting execution", tone: "neutral", explanation: "Select a trusted fixture to inspect the local detection pipeline." },
  running: { label: "Analysis in progress", tone: "cyan", explanation: "Waiting for the recorded result. No decision has been made." },
  block: { label: "Simulated block", tone: "red", explanation: "The synthetic event stops at simulation enforcement. The resource is not reached." },
  allow: { label: "Simulated allow", tone: "green", explanation: "The synthetic event reaches the conceptual resource. This is not a real-world safety guarantee." },
  review: { label: "Review required", tone: "violet", explanation: "The decision is held for review. No allow or block is claimed." },
  unavailable: { label: "Analysis unavailable", tone: "amber", explanation: "Local analysis is incomplete or unavailable. No successful allow or block is claimed." },
  failed: { label: "Analysis failed", tone: "amber", explanation: "The execution failed. No successful allow or block is claimed." },
};

export function runOutcome(run: SimulationRun | null) {
  let kind: OutcomeKind = "idle";
  if (run) {
    const incomplete = Boolean(run.error || run.errors?.length || run.risk_assessment?.analysis_status === "partial_analysis" ||
      Object.values(run.detector_availability ?? {}).some((item) => item.status !== "Available") ||
      run.detector_results?.some((item) => item.status && !["suspicious", "no_finding_observed"].includes(item.status)));
    if (run.status === "RUNNING") kind = "running";
    else if (run.status === "FAILED" || run.detection_state === "ANALYSIS_FAILED") kind = "failed";
    else if (incomplete || run.status === "PARTIALLY_COMPLETED" || run.enforcement_decision === "SIMULATED_UNAVAILABLE" || run.detection_state === "DETECTOR_UNAVAILABLE") kind = "unavailable";
    else if (run.status === "COMPLETED" && run.enforcement_decision === "SIMULATED_BLOCK") kind = "block";
    else if (run.status === "COMPLETED" && run.enforcement_decision === "SIMULATED_ALLOW") kind = "allow";
    else kind = "review";
  }
  return { kind, ...outcomes[kind] };
}

/** Result metadata always follows the run, never the launcher selection. */
export function displayedScenario(run: SimulationRun | null, scenarios: SimulationScenario[] = []) {
  if (!run) return null;
  const metadata = scenarios.find((item) => item.scenario_id === run.scenario_id);
  const detectors = Object.keys(run.detector_availability ?? {});
  return {
    name: run.scenario?.name ?? metadata?.name ?? run.scenario_id,
    limitation: run.scenario?.limitation ?? metadata?.limitation ?? "No scenario limitation was recorded.",
    detectors: detectors.length ? detectors : metadata?.detector_allowlist?.length ? metadata.detector_allowlist : metadata ? [metadata.detector] : [],
  };
}

export function readable(value: string) {
  return value.toLowerCase().replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

export function detectionLabel(value: string) {
  return value === "NOT_DETECTED" ? "No finding observed" : readable(value);
}

export function durationMs(run: SimulationRun) {
  if (run.duration_ms != null && Number.isFinite(run.duration_ms) && run.duration_ms >= 0) return run.duration_ms;
  if (!run.completed_at) return null;
  const elapsed = Date.parse(run.completed_at) - Date.parse(run.started_at);
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : null;
}

export function formatDuration(value: number | null) {
  if (value == null || !Number.isFinite(value) || value < 0) return "Not recorded";
  return value < 1_000 ? `${Math.round(value)} ms` : `${(value / 1_000).toFixed(2)} s`;
}

export function formatTimestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Timestamp unavailable" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

export function timelineElapsed(timestamp: string, startedAt: string) {
  const elapsed = Date.parse(timestamp) - Date.parse(startedAt);
  return Number.isFinite(elapsed) && elapsed >= 0 ? `+${formatDuration(elapsed)}` : "Timing unavailable";
}

/** A conceptual route, not additional backend stages or wall-clock progress. */
export function topologyRoute(kind: OutcomeKind, scenarioId?: string) {
  const detectionPath = scenarioId === "network-anomaly" ? "M90 90 H450 H630" : "M90 90 H270 H450 H630";
  const detectionNodes = scenarioId === "network-anomaly" ? ["source", "engine", "detector"] : ["source", "gateway", "engine", "detector"];
  if (kind === "running") return { path: detectionPath, endpoint: "detector", nodes: detectionNodes };
  if (kind === "idle") return null;
  if (["failed", "unavailable"].includes(kind)) return { path: detectionPath, endpoint: "detector", nodes: detectionNodes };
  const policyPath = `${detectionPath} V260 H450`;
  const fullNodes = [...detectionNodes, "risk", "enforce"];
  if (kind === "allow") return { path: `${policyPath} H270`, endpoint: "resource", nodes: [...fullNodes, "resource"] };
  return { path: policyPath, endpoint: "enforce", nodes: fullNodes };
}

export function presentationStage(progress: number, kind: OutcomeKind) {
  if (kind === "idle") return "READY";
  if (kind === "running" || progress < 0.2) return "EVENT MOVING TO GATEWAY";
  if (progress < 0.62) return "SENTIVRA ANALYSIS";
  if (progress < 0.86) return "RISK ASSESSMENT";
  if (kind === "block") return "SIMULATED BLOCK";
  if (kind === "allow") return "SIMULATED ALLOW";
  if (kind === "review") return "REVIEW REQUIRED";
  if (kind === "failed") return "SIMULATION FAILED";
  return "ANALYSIS UNAVAILABLE";
}
