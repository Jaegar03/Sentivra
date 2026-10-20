// Types mirroring the SENTIVRA backend's Pydantic schemas
// (backend/app/schemas/detection.py, backend/app/events/schema.py, backend/app/api/*).

export type Severity = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type SourceType = "LIVE" | "SIMULATED" | "DEMO_DATA";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
export type RecommendedAction = "ALLOW" | "MONITOR" | "REVIEW" | "BLOCK";
export type FindingStatus = "suspicious" | "no_finding_observed" | "partial_analysis" | "invalid_input" | "scanner_or_model_unavailable" | "timed_out" | "internal_error";

export const SEVERITIES: Severity[] = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  source: string;
}

export interface Evidence {
  type: string;
  detail: string;
  excerpt?: string | null;
  weight?: number | null;
}

export interface DetectionResult {
  detector: string;
  category: string;
  severity: Severity;
  score: number;
  confidence: number;
  evidence: Evidence[];
  recommended_action: RecommendedAction;
  status?: FindingStatus;
  rule_ids?: string[];
  model_id?: string | null;
  threshold?: number | null;
  model_version?: string | null;
  mitre_attack: MitreMapping[];
  generated_at: string;
}

export interface RiskAssessment {
  assessment_id: string;
  event_id: string;
  risk_score: number;
  severity: Severity;
  classification: string;
  confidence: number;
  analysis_status?: "complete" | "partial_analysis";
  analysis_errors?: string[];
  findings: DetectionResult[];
  generated_at: string;
}

export interface EventSummary {
  source: string | null;
  source_type: SourceType | null;
  event_type: string | null;
}

export interface AlertListItem extends RiskAssessment {
  status: AlertStatus;
  event: EventSummary;
}

export interface SecurityEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  source: string;
  source_type: SourceType;
  user_id?: string | null;
  content?: Record<string, unknown> | null;
  attachments: { filename: string; declared_mime?: string | null; size_bytes?: number | null; sha256?: string | null }[];
  network?: Record<string, unknown> | null;
  process?: Record<string, unknown> | null;
  metadata: Record<string, unknown>;
}

export interface AlertDetail extends RiskAssessment {
  status: AlertStatus;
  event: SecurityEvent | EventSummary;
}

export interface EngineStatus {
  status: "Available" | "Not Configured" | "Degraded" | "Error";
  detail: string;
  engine_version?: string | null;
}

export interface Health {
  status: "ok" | "degraded";
  environment: string;
  database: string;
  engines: Record<string, EngineStatus>;
}

export interface DetectorInfo {
  name: string;
  version: string;
  category: string;
  applicable_event_types: string[];
  availability: EngineStatus;
}

export interface Metrics {
  window_hours: number;
  generated_at: string;
  totals: { events: number; alerts: number };
  window: {
    alerts: number;
    open_alerts: number;
    by_severity: Record<Severity, number>;
    open_by_severity: Record<Severity, number>;
    by_status: Partial<Record<AlertStatus, number>>;
    by_classification: Record<string, number>;
    by_detector: Record<string, number>;
    by_domain: Record<"network" | "files" | "endpoint" | "urls" | "prompts" | "sql", number>;
    by_source_type: Record<string, number>;
    timeline: { bucket: "hour" | "day"; start: string; counts: number[] };
    simulation_alerts_excluded?: number;
  };
  security_score: { value: number; formula: string; penalty: number; note: string };
  note: string;
}

export interface SimulationScenario {
  scenario_id: string;
  name: string;
  category: string;
  description: string;
  detector: string;
  detector_allowlist: string[];
  event_type: string;
  version: string;
  expected_outcome: string;
  limitation: string;
  target_endpoint?: string | null;
  detector_availability: { status: string; detail: string; engine_version?: string | null };
  simulation_warning: string;
}

export interface SimulationRun {
  execution_id: string;
  scenario_id: string;
  scenario_version: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "PARTIALLY_COMPLETED" | "FAILED";
  simulation_marker: string;
  source_type: "SIMULATED";
  detection_state: "DETECTED" | "NOT_DETECTED" | "REVIEW_REQUIRED" | "DETECTOR_UNAVAILABLE" | "ANALYSIS_FAILED";
  enforcement_decision: "SIMULATED_BLOCK" | "SIMULATED_ALLOW" | "SIMULATED_REVIEW" | "SIMULATED_UNAVAILABLE" | "BLOCKED" | "ALLOWED" | "REVIEW_REQUIRED" | "ENFORCEMENT_UNAVAILABLE";
  event_id?: string | null;
  alert_id?: string | null;
  started_at: string;
  completed_at?: string | null;
  duration_ms?: number | null;
  error?: string | null;
  request_key?: string;
  errors?: string[];
  timeline?: { stage: string; timestamp: string }[];
  detector_results?: DetectionResult[];
  detector_availability?: Record<string, EngineStatus>;
  findings?: DetectionResult[];
  risk_assessment?: RiskAssessment | null;
  enforcement?: { decision: string; reason: string; mode: string; real_world_action_taken: boolean };
  scenario?: { id: string; name: string; limitation: string };
  target?: { endpoint: string; status_code: number; response: Record<string, unknown>; protected_operation_executed: boolean; target_execution_state: string; request_id: string };
}

export interface SimulationStats {
  totals: { runs: number; completed: number; partial: number; failed: number; running: number; detected: number; blocks: number };
  by_scenario: { scenario_id: string; runs: number; avg_duration_ms: number; failed: number; detected: number }[];
  timeline: { execution_id: string; scenario_id: string; status: string; detection_state: string; timestamp: string }[];
  timeline_truncated: boolean;
}

export interface ModelMetadata {
  name: string;
  domain: string;
  version: string;
  artifact_filename: string;
  artifact_format: string;
  sha256: string;
  training_dataset: string;
  datasets: { name: string; role: string; license: string; source: string; notes?: string | null }[];
  splits: Record<string, number>;
  split_method?: string | null;
  threshold?: number | null;
  threshold_policy?: string | null;
  calibration?: Record<string, unknown> | null;
  evaluation_metrics: Record<string, number>;
  evaluation_date?: string | null;
  limitations: string[];
  notes?: string | null;
}

export interface ModelEntry {
  domain: string;
  name: string;
  trained: boolean;
  directory: string;
  metadata: ModelMetadata | null;
  reason_untrained: string | null;
}

export interface RulesInventory {
  yara: { files: string[] };
  sigma: {
    loaded: { id: string; title: string; level: string; status: string; path: string; logsource: Record<string, string>; tags: string[] }[];
    unsupported: { path: string; reason: string; title?: string }[];
  };
  custom: { file: string; used_by: string; rules?: string[]; error?: string }[];
  attack_index: { attack_version: string | null; techniques: number };
}

export interface Integration {
  name: string;
  kind: "messaging" | "telemetry" | "engine";
  status: "Connected" | "Available" | "Not configured" | "Not implemented" | "Degraded" | "Error";
  detail: string;
  credentials_configured?: boolean;
  engine_version?: string | null;
}

export interface AuditEntry {
  id: string;
  created_at: string;
  actor: string;
  action: string;
  resource: string;
  detail: Record<string, unknown>;
}

export interface AnalysisResponse {
  event_id: string;
  source_type: SourceType;
  findings: DetectionResult[];
  risk_assessment: RiskAssessment;
  [key: string]: unknown;
}

export interface TextAnalysisResponse extends AnalysisResponse {
  limitations?: string[];
}

export interface FileAnalysisResponse extends AnalysisResponse {
  file_metadata: {
    filename: string;
    sha256: string;
    size_bytes: number;
    entropy: number;
    matched_magic_types: string[];
    extension_mismatch: boolean;
    is_polyglot: boolean;
  };
}

export interface NetworkAnalysisResponse extends AnalysisResponse {
  input_format?: string;
  truncated?: boolean;
  network: {
    flow_count: number;
    fusion_cut: number;
    model_flagged_total: number;
    model_flag_significance: { expected_by_chance: number; p_value: number; significant: boolean; summary: string };
    layer_status: Record<string, string>;
    layer_fire_counts: Record<string, number>;
    behavior_findings: {
      rule: string;
      category: string;
      description: string;
      subject: string;
      details: Record<string, unknown>;
      flow_count: number;
      mitre_attack: MitreMapping[];
    }[];
    flagged_flows_total: number;
    flagged_flows: {
      flow: Record<string, string | number>;
      ground_truth_label: string | null;
      fused_score: number;
      fired_layers: string[];
      explanations: string[];
      behavior_rules: string[];
    }[];
  };
}

export interface BatchAnalysisResponse extends AnalysisResponse {
  event_count: number;
  hosts: string[];
  analysis: {
    sigma?: { rule_id: string; title: string; level: string; matches: number; hosts: string[]; mitre_attack: MitreMapping[] }[];
    auth?: { rule: string; description: string; subject: string; details: Record<string, unknown>; event_count: number; mitre_attack: MitreMapping[] }[];
    behavior?: {
      baseline: string;
      rules_skipped_without_baseline: string[];
      findings: {
        rule: string;
        category: string;
        description: string;
        host: string;
        subject: string;
        details: Record<string, unknown>;
        event_count: number;
        mitre_attack: MitreMapping[];
        ground_truth_labels: string[];
      }[];
    };
  };
}
