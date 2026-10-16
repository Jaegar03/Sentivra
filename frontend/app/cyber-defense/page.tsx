"use client";

import { useEffect, useRef, useState } from "react";
import { Activity, ArrowLeft, ArrowRight, Crosshair, History, Play, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";

import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { SourceTypeBadge } from "@/components/sentivra/badges";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { createRequestKey, detectionLabel, displayedScenario, formatDuration, formatTimestamp, HISTORY_PAGE_SIZE, readable, runOutcome, SIMULATION_NOTICE } from "@/lib/simulation";
import type { SimulationRun, SimulationScenario, SimulationStats } from "@/types/api";
import { RunDetails } from "./run-details";
import { Topology } from "./topology";
import styles from "./command-center.module.css";

type Attempt = { scenarioId: string; requestKey: string };

export default function CyberDefensePage() {
  const scenarios = useApi<SimulationScenario[]>("/api/simulation/scenarios");
  const stats = useApi<SimulationStats>("/api/simulation/stats");
  const [offset, setOffset] = useState(0);
  // The extra row is a lookahead; pagination does not depend on stale aggregate counts.
  const history = useApi<SimulationRun[]>(`/api/simulation/runs?limit=${HISTORY_PAGE_SIZE + 1}&offset=${offset}`, { keepPreviousData: false });
  const [selectedId, setSelectedId] = useState("");
  const [selectedRun, setSelectedRun] = useState<SimulationRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const inFlight = useRef(false);
  const pendingAttempt = useRef<Attempt | null>(null);
  const detail = useApi<SimulationRun>(selectedRun ? `/api/simulation/runs/${encodeURIComponent(selectedRun.execution_id)}` : null, {
    keepPreviousData: false,
    refreshInterval: (data) => (data ?? selectedRun)?.status === "RUNNING" ? 2_000 : 0,
    shouldRetryOnError: false,
  });
  const run = detail.data?.execution_id === selectedRun?.execution_id ? detail.data ?? null : selectedRun;
  const selected = selectedId || scenarios.data?.[0]?.scenario_id || "";
  const scenario = scenarios.data?.find((item) => item.scenario_id === selected);
  const runScenario = displayedScenario(run, scenarios.data);
  const rows = history.data?.slice(0, HISTORY_PAGE_SIZE) ?? [];
  const counts = stats.data?.totals;
  const pending = Boolean(attempt);
  const previousStatus = useRef<string | null>(null);
  const { mutate: mutateStats } = stats;
  const { mutate: mutateHistory } = history;

  // GET polling may observe a previously uncertain execution finishing; refresh
  // aggregates then, without ever replaying the POST automatically.
  useEffect(() => {
    if (previousStatus.current === "RUNNING" && run && run.status !== "RUNNING") {
      void mutateStats();
      void mutateHistory();
    }
    previousStatus.current = run?.status ?? null;
  }, [run, mutateStats, mutateHistory]);

  async function execute(retry = false) {
    if (inFlight.current) return;
    const request = retry ? pendingAttempt.current : scenario ? { scenarioId: scenario.scenario_id, requestKey: createRequestKey() } : null;
    if (!request || (!retry && pendingAttempt.current)) return;
    // A synchronous guard prevents same-tick double submissions before React renders.
    inFlight.current = true;
    pendingAttempt.current = request;
    setAttempt(request);
    setBusy(true);
    setError(null);
    setSelectedRun(null);
    try {
      const result = await api.runSimulation(request.scenarioId, request.requestKey);
      setSelectedRun(result);
      pendingAttempt.current = null;
      setAttempt(null);
      if (offset !== 0) setOffset(0);
      void mutateHistory();
      void mutateStats();
    } catch (cause) {
      // Keep the original key and scenario. Only the explicit retry button can
      // resubmit, so a lost response cannot silently create a second execution.
      setError(cause);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  function dismissRequest() {
    if (inFlight.current) return;
    pendingAttempt.current = null;
    setAttempt(null);
    setError(null);
    void mutateHistory();
    void mutateStats();
  }

  return (
    <div className={styles.commandCenter}>
      <div className={styles.hero}>
        <p className={styles.eyebrow}><Crosshair size={14} aria-hidden="true" /> Sentivra / defense lab</p>
        <PageHeader title="Cyber Defense Command Center" description="Simulate. Detect. Analyze. Defend. Trace trusted fixtures through your local security pipeline."
          actions={<Button variant="outline" onClick={() => setSelectedRun(null)} disabled={busy || !selectedRun}><RotateCcw /> Reset visualization</Button>} />
      </div>

      <div role="note" className={styles.safetyNotice}><ShieldCheck size={20} aria-hidden="true" /><p>{SIMULATION_NOTICE}</p><span className={styles.marker}>SIMULATED EVENT</span></div>

      <section aria-label="Simulation statistics" className={styles.statistics}>
        <div className={styles.sectionHeading}><h2>Simulation overview</h2><span className={styles.muted}>All stored executions · your account</span></div>
        {stats.error ? <div className={styles.errorWithRetry}><ErrorState error={stats.error} /><Button variant="outline" disabled={stats.isValidating} onClick={() => void stats.mutate()}>Retry statistics</Button></div> : null}
        <div className={styles.statsGrid} aria-busy={stats.isLoading}>
          {[
            { label: "Total executions", value: counts?.runs, tone: "cyan", detail: counts ? `${counts.completed} completed · ${counts.running} running` : "Loading aggregate totals" },
            { label: "Detected indicators", value: counts?.detected, tone: "violet", detail: "Executions with a finding" },
            { label: "Simulated blocks", value: counts?.blocks, tone: "red", detail: "Decision-only enforcement" },
            { label: "Incomplete analyses", value: counts ? counts.partial + counts.failed : undefined, tone: "amber", detail: counts ? `${counts.partial} partial · ${counts.failed} failed` : "Partial and failed executions" },
          ].map((metric) => <Card key={metric.label} size="sm" className={styles.statCard} data-tone={metric.tone}><CardContent><p className={styles.metricLabel}>{metric.label}</p><p className={styles.metricValue}>{metric.value?.toLocaleString() ?? "—"}</p><p className={styles.metricDetail}>{metric.detail}</p></CardContent></Card>)}
        </div>
        {stats.data?.by_scenario.length ? <details className={styles.scenarioStats}><summary>Scenario breakdown <span>{stats.data.by_scenario.length} scenarios</span></summary><div className={styles.tableScroll}><table><caption className="sr-only">Aggregate statistics by scenario</caption><thead><tr><th>Scenario</th><th>Executions</th><th>Detected</th><th>Failed</th><th>Average duration</th></tr></thead><tbody>{stats.data.by_scenario.map((item) => <tr key={item.scenario_id}><th>{scenarios.data?.find((entry) => entry.scenario_id === item.scenario_id)?.name ?? item.scenario_id}</th><td>{item.runs}</td><td>{item.detected}</td><td>{item.failed}</td><td>{formatDuration(item.avg_duration_ms)}</td></tr>)}</tbody></table></div></details> : null}
      </section>

      <div className={styles.workspace}>
        <Card className={styles.topologyCard}>
          <CardHeader><div className={styles.sectionHeading}><h2><Activity size={17} aria-hidden="true" /> Security topology</h2><span className={styles.badge} data-tone="cyan">LOCAL PIPELINE</span></div><p className={styles.muted}>{runScenario ? `Showing: ${runScenario.name}` : "Eight conceptual nodes. Actual results. No external connections."}</p></CardHeader>
          <CardContent><Topology run={run} scenarios={scenarios.data ?? []} busy={busy} scenarioId={selected} /></CardContent>
        </Card>

        <Card className={styles.launcher}>
          <CardHeader><p className={styles.eyebrow}>Scenario launcher</p><h2 className={styles.sectionTitle}>Choose the next simulation</h2><p className={styles.muted}>Fixtures and detector allowlists are owned by the server.</p></CardHeader>
          <CardContent className={styles.launcherBody}>
            {scenarios.error ? <div className={styles.errorWithRetry}><ErrorState error={scenarios.error} /><Button variant="outline" disabled={scenarios.isValidating} onClick={() => void scenarios.mutate()}>Retry scenarios</Button></div> : null}
            {!scenarios.data && !scenarios.error ? <LoadingBlock label="Loading trusted scenarios…" /> : null}
            {scenarios.data?.length === 0 ? <EmptyState title="No scenarios available">The server has no registered simulation fixtures.</EmptyState> : null}
            {scenarios.data?.length ? <>
              <label className={styles.selectLabel} htmlFor="simulation-scenario">Trusted scenario<select id="simulation-scenario" value={selected} disabled={busy || pending} onChange={(event) => setSelectedId(event.target.value)}>{scenarios.data.map((item) => <option key={item.scenario_id} value={item.scenario_id}>{item.name}</option>)}</select></label>
              {scenario ? <div className={styles.scenarioInfo}><span className={styles.category}>{scenario.category}</span><p>{scenario.description}</p><div><span className={styles.fieldLabel}>Scenario detectors</span><ul className={styles.detectorNames}>{(scenario.detector_allowlist?.length ? scenario.detector_allowlist : [scenario.detector]).map((name) => <li key={name}>{name}</li>)}</ul></div><div className={styles.availability}><span className={styles.badge} data-tone={scenario.detector_availability.status === "Available" ? "cyan" : "amber"}>{scenario.detector_availability.status}</span><p>{scenario.detector_availability.detail}</p></div><p className={styles.limitation}>{scenario.limitation}</p></div> : null}
              <Button size="lg" className={styles.launchButton} disabled={busy || pending || !scenario} onClick={() => void execute()}><Play aria-hidden="true" />{busy ? "Analyzing fixture…" : "Run simulation"}</Button>
            </> : null}
             <p className={styles.launchHint} role="status">{busy ? "Waiting for the backend result. The visualization begins only after a response." : run?.status === "RUNNING" ? "This execution is still running. Its status is refreshed with read-only requests." : "Each launch records one execution. Reset clears only the displayed result; it never cancels or deletes a run."}</p>
            {error ? <div className={styles.requestError}><ErrorState error={error} /><p>The result is unconfirmed. Retry reuses the same request key to recover this execution.</p><code>{attempt?.requestKey}</code><Button variant="outline" disabled={busy} onClick={() => void execute(true)}><RefreshCw /> Retry same request</Button><Button variant="ghost" disabled={busy} onClick={dismissRequest}>Dismiss pending request</Button><p>Dismissing only clears local request state; backend work is not cancelled.</p></div> : null}
          </CardContent>
        </Card>
      </div>

      {selectedRun && detail.error ? <div className={styles.errorWithRetry}><ErrorState error={detail.error} /><p className={styles.muted}>Showing the last received snapshot for this execution.</p><Button variant="outline" disabled={detail.isValidating || busy} onClick={() => void detail.mutate()}>Retry execution details</Button></div> : null}
      {run ? <RunDetails run={run} scenarios={scenarios.data ?? []} /> : <EmptyState title={busy ? "Analyzing the selected fixture" : "Ready to trace a simulation"}>{busy ? "No detection or enforcement result is assumed while the request is in flight." : "Run a trusted scenario or open an execution below to inspect evidence, policy, and recorded timing."}</EmptyState>}

      <Card>
        <CardHeader><div className={styles.sectionHeading}><h2><History size={17} aria-hidden="true" /> Execution history</h2><Button variant="ghost" size="sm" disabled={busy || history.isValidating} onClick={() => { void history.mutate(); void stats.mutate(); }}><RefreshCw /> Refresh history</Button></div><p className={styles.muted}>Stored simulation executions. Select a row to inspect its own scenario and evidence.</p></CardHeader>
        <CardContent>
          {history.error ? <div className={styles.errorWithRetry}><ErrorState error={history.error} /><Button variant="outline" disabled={history.isValidating} onClick={() => void history.mutate()}>Retry history</Button></div> : null}
          {history.isLoading ? <LoadingBlock label="Loading execution history…" /> : null}
          {!history.isLoading && !history.error && !rows.length ? <EmptyState title={offset ? "No more executions" : "No simulations yet"}>{offset ? "Return to the previous page or refresh history." : "Your first recorded simulation will appear here."}</EmptyState> : null}
          {rows.length ? <div className={styles.historyList}>{rows.map((item) => {
            const outcome = runOutcome(item);
            return <button type="button" key={item.execution_id} disabled={busy} className={styles.historyRow} aria-pressed={run?.execution_id === item.execution_id} onClick={() => setSelectedRun(item)}>
              <span className={styles.historyIcon} data-tone={outcome.tone}><Activity size={17} aria-hidden="true" /></span>
              <span className={styles.historyIdentity}><strong>{item.scenario?.name ?? scenarios.data?.find((entry) => entry.scenario_id === item.scenario_id)?.name ?? item.scenario_id}</strong><time dateTime={item.started_at} title={item.started_at}>{formatTimestamp(item.started_at)}</time><span className={styles.historyId}>{item.execution_id}</span></span>
               <span className={styles.historyStatus}><span className={styles.badge} data-tone={outcome.tone}>{outcome.label}</span><span>{readable(item.status)} · {detectionLabel(item.detection_state)}</span><SourceTypeBadge sourceType={item.source_type} /><span className={styles.historyMarker}>SIMULATED EVENT</span></span><ArrowRight size={16} aria-hidden="true" />
            </button>;
          })}</div> : null}
          <div className={styles.pagination}><span>{rows.length ? `${offset + 1}–${offset + rows.length}` : "0"} shown · Page {Math.floor(offset / HISTORY_PAGE_SIZE) + 1}</span><div><Button variant="outline" size="sm" disabled={busy || history.isLoading || offset === 0} onClick={() => setOffset(Math.max(0, offset - HISTORY_PAGE_SIZE))}><ArrowLeft /> Previous</Button><Button variant="outline" size="sm" disabled={busy || history.isLoading || Boolean(history.error) || (history.data?.length ?? 0) <= HISTORY_PAGE_SIZE} onClick={() => setOffset(offset + HISTORY_PAGE_SIZE)}>Next <ArrowRight /></Button></div></div>
        </CardContent>
      </Card>
    </div>
  );
}
