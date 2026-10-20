import { AlertTriangle, ChevronRight, SearchCheck, ShieldCheck, ShieldX } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { comparisonSummary, detectionLabel, displayedScenario, formatDuration, hasConfirmedAllow, hasConfirmedBlock, readable, runOutcome } from "@/lib/simulation";
import type { SimulationRun, SimulationScenario } from "@/types/api";
import styles from "./command-center.module.css";

type ComparisonPanelProps = {
  runs: SimulationRun[];
  scenarios: SimulationScenario[];
  selectedExecutionId?: string;
  presentationMode?: boolean;
  onSelectExecution: (run: SimulationRun) => void;
};

const flow = ["REQUEST", "DETECTION", "RISK ASSESSMENT", "ENFORCEMENT POLICY", "PROTECTED OPERATION", "VERIFIED OUTCOME"];

export function ComparisonPanel({ runs, scenarios, selectedExecutionId, presentationMode = false, onSelectExecution }: ComparisonPanelProps) {
  const summary = comparisonSummary(runs);
  const malicious = runs.find((run) => run.scenario_id === "sqli-indicator") ?? (runs[0]?.scenario_id !== "benign-control" ? runs[0] : undefined);
  const benign = runs.find((run) => run.scenario_id === "benign-control") ?? (runs[0]?.scenario_id === "benign-control" ? runs[0] : undefined);

  return <section className={`${styles.comparisonSection} ${presentationMode ? styles.comparisonPresentation : ""}`} aria-label="Malicious versus benign comparison">
    <Card className={styles.comparisonCard}>
      <CardHeader>
        <div className={styles.sectionHeading}><div><p className={styles.eyebrow}><SearchCheck size={14} aria-hidden="true" /> Evidence comparison</p><h2>Malicious vs benign request</h2></div><span className={styles.badge} data-tone={summary.complete ? "cyan" : "amber"}>{summary.executed} SCENARIOS {summary.complete ? "COMPLETE" : "RECORDED"}</span></div>
        <p className={styles.muted}>Same request path. Different detector evidence, policy decision, and verified target outcome.</p>
      </CardHeader>
      <CardContent>
        <div className={styles.decisionFlow} aria-label="Shared security decision flow">{flow.map((step, index) => <span key={step} className={styles.flowStep}><span>{step}</span>{index < flow.length - 1 ? <ChevronRight size={14} aria-hidden="true" /> : null}</span>)}</div>
        <div className={styles.comparisonGrid}>
          {malicious ? <ComparisonCard run={malicious} role="malicious" scenarios={scenarios} selected={selectedExecutionId === malicious.execution_id} onSelect={onSelectExecution} /> : <MissingComparisonCard role="malicious" />}
          {benign ? <ComparisonCard run={benign} role="benign" scenarios={scenarios} selected={selectedExecutionId === benign.execution_id} onSelect={onSelectExecution} /> : <MissingComparisonCard role="benign" />}
          <div className={styles.comparisonSummary} role="status"><div><strong>{summary.complete ? "COMPARISON COMPLETE" : "COMPARISON INCOMPLETE"}</strong><span>{summary.executed} scenarios executed</span></div><span className={styles.summaryDanger}>{summary.blocked} prohibited request{summary.blocked === 1 ? "" : "s"} blocked</span><span className={styles.summarySuccess}>{summary.allowed} benign request{summary.allowed === 1 ? "" : "s"} allowed</span><span>{summary.unverified} unverified outcome{summary.unverified === 1 ? "" : "s"}</span></div>
        </div>
      </CardContent>
    </Card>
  </section>;
}

function MissingComparisonCard({ role }: { role: "malicious" | "benign" }) {
  return <article className={styles.comparisonColumn} data-tone="amber"><div className={styles.comparisonCardHeader}><div><p className={styles.comparisonRole}>{role === "malicious" ? "MALICIOUS REQUEST" : "BENIGN CONTROL"}</p><h3>Execution not recorded</h3></div><AlertTriangle className={styles.comparisonStatusIcon} size={25} aria-hidden="true" /></div><div className={styles.comparisonVerdict}><div><strong>OUTCOME UNVERIFIED</strong><span>The sequence did not produce a record for this scenario.</span></div><span className={styles.badge} data-tone="amber">INCOMPLETE</span></div><p className={styles.comparisonExplanation}>No detector, enforcement, or protected-operation claim is made without an authoritative execution record.</p></article>;
}

function ComparisonCard({ run, role, scenarios, selected, onSelect }: { run: SimulationRun; role: "malicious" | "benign"; scenarios: SimulationScenario[]; selected: boolean; onSelect: (run: SimulationRun) => void }) {
  const scenario = displayedScenario(run, scenarios);
  const outcome = runOutcome(run);
  const blocked = role === "malicious" && hasConfirmedBlock(run);
  const allowed = role === "benign" && hasConfirmedAllow(run);
  const confirmed = blocked || allowed;
  const Icon = blocked ? ShieldX : allowed ? ShieldCheck : AlertTriangle;
  const targetOutcome = run.target ? `${run.target.status_code} · ${readable(run.target.target_execution_state)}` : "Not recorded";
  const protectedOutcome = run.target?.protected_operation_executed === true ? "EXECUTED" : run.target?.protected_operation_executed === false ? "NOT EXECUTED" : "UNVERIFIED";
  const title = role === "malicious" ? "MALICIOUS REQUEST" : "BENIGN CONTROL";
  const evidenceClaim = blocked ? "THREAT INDICATOR DETECTED" : allowed ? "NO SQL INJECTION INDICATOR DETECTED" : "DETECTION OUTCOME UNVERIFIED";
  const headline = blocked ? "REQUEST BLOCKED" : allowed ? "REQUEST ALLOWED BY SIMULATION POLICY" : "OUTCOME UNVERIFIED";
  const supporting = blocked ? "PROTECTED OPERATION NOT EXECUTED" : allowed ? "PROTECTED OPERATION EXECUTED" : "No confirmed block or allow is claimed.";

  function activate() { onSelect(run); }

  return <article className={styles.comparisonColumn} data-tone={blocked ? "red" : allowed ? "green" : "amber"} data-confirmed={confirmed || undefined} data-selected={selected || undefined} tabIndex={0} aria-label={`Inspect ${title.toLowerCase()} execution ${run.execution_id}`} onClick={activate} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); activate(); } }}>
    <div className={styles.comparisonCardHeader}><div><p className={styles.comparisonRole}>{title}</p><h3>{scenario?.name ?? run.scenario_id}</h3></div><Icon className={styles.comparisonStatusIcon} size={25} aria-hidden="true" /></div>
    <div className={styles.comparisonVerdict}><div><strong>{evidenceClaim}</strong><strong>{headline}</strong><span>{supporting}</span></div><span className={styles.badge} data-tone={blocked ? "red" : allowed ? "green" : "amber"}>{confirmed ? "VERIFIED" : readable(outcome.kind)}</span></div>
    <dl className={styles.comparisonList}>
      <div><dt>Execution ID</dt><dd className={styles.comparisonCode}>{run.execution_id}</dd></div>
      <div><dt>Detector</dt><dd>{scenario?.detectors.join(", ") || "Not recorded"}</dd></div>
      <div><dt>Detection</dt><dd>{detectionLabel(run.detection_state)}</dd></div>
      <div><dt>Enforcement</dt><dd>{readable(run.enforcement_decision)}</dd></div>
      <div><dt>Target response</dt><dd>{targetOutcome}</dd></div>
      <div><dt>Protected operation</dt><dd>{protectedOutcome}</dd></div>
      <div><dt>Recorded duration</dt><dd>{formatDuration(run.duration_ms ?? null)}</dd></div>
    </dl>
    <p className={styles.comparisonExplanation}>{run.enforcement?.reason ?? scenario?.limitation ?? "No explanation was recorded."}</p>
    <Button type="button" variant="outline" size="sm" className={styles.evidenceButton} onClick={(event) => { event.stopPropagation(); activate(); }}><SearchCheck /> Inspect execution evidence</Button>
  </article>;
}
