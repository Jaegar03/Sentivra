"use client";

import type { ReactNode } from "react";

import { AnalysisError, AnalysisSummary, RunButton, UploadButton, useAnalysis } from "@/components/sentivra/analysis-result";
import { MitreList } from "@/components/sentivra/findings";
import { EmptyState, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { humanize, integer } from "@/lib/format";
import type { BatchAnalysisResponse } from "@/types/api";

function Section({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">{children}</CardContent>
    </Card>
  );
}

function BatchDetails({ result }: { result: BatchAnalysisResponse }) {
  const { sigma = [], auth = [], behavior } = result.analysis;
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Section title="Sigma rules" description={`${sigma.length} rule(s) matched across ${integer(result.event_count)} events`}>
        {sigma.length === 0 ? <p className="text-sm text-muted-foreground">No Sigma rule matched.</p> : null}
        {sigma.map((s) => (
          <div key={s.rule_id} className="space-y-1.5 rounded-lg border p-3 text-sm">
            <p className="font-medium">{s.title}</p>
            <p className="text-xs text-muted-foreground">{humanize(s.level)} · {s.matches} match(es) · {s.hosts.join(", ")}</p>
            <MitreList mappings={s.mitre_attack} />
          </div>
        ))}
      </Section>
      <Section title="Host behavior" description={behavior ? `Fleet baseline: ${behavior.baseline}` : "Not run for this input"}>
        {behavior?.rules_skipped_without_baseline.length ? (
          <p className="text-xs text-muted-foreground">Not evaluated without a baseline: {behavior.rules_skipped_without_baseline.join(", ")}</p>
        ) : null}
        {behavior && behavior.findings.length === 0 ? <p className="text-sm text-muted-foreground">No host rule fired.</p> : null}
        {behavior?.findings.map((f, i) => (
          <div key={`${f.rule}-${i}`} className="space-y-1.5 rounded-lg border p-3 text-sm">
            <p className="font-medium">{humanize(f.rule)}</p>
            <p className="font-mono text-xs break-all text-muted-foreground">{f.host}: {f.subject}</p>
            {f.ground_truth_labels.length ? <p className="text-xs">Simulated scenario: {f.ground_truth_labels.join(", ")}</p> : null}
            <MitreList mappings={f.mitre_attack} />
          </div>
        ))}
      </Section>
      <Section title="Authentication" description="Counts over time: guessing, spraying, success after failures">
        {auth.length === 0 ? <p className="text-sm text-muted-foreground">No authentication rule fired.</p> : null}
        {auth.map((a, i) => (
          <div key={`${a.rule}-${i}`} className="space-y-1.5 rounded-lg border p-3 text-sm">
            <p className="font-medium">{humanize(a.rule)}</p>
            <p className="font-mono text-xs text-muted-foreground">{a.subject}</p>
            <MitreList mappings={a.mitre_attack} />
          </div>
        ))}
      </Section>
    </div>
  );
}

export default function EndpointPage() {
  const { result, error, busy, run } = useAnalysis<BatchAnalysisResponse>();
  return (
    <>
      <PageHeader
        title="Endpoint"
        description="osquery telemetry and system logs, checked by Sigma rules, host behavior rules against a learned fleet baseline, and authentication rules. There is no endpoint ML model in this build."
        actions={
          <>
            <RunButton label="Run simulated fleet" busy={busy} onClick={() => run("Run simulated fleet", api.endpointDemo)} />
            <UploadButton label="Upload osquery results" accept=".log,.json,.ndjson" busy={busy}
              onFile={(f) => run("Upload osquery results", () => api.analyzeOsquery(f))} />
            <UploadButton label="Upload log file" accept=".log,.txt,.json" busy={busy}
              onFile={(f) => run("Upload log file", () => api.analyzeLogs(f))} />
          </>
        }
      />
      <p className="text-xs text-muted-foreground">
        The simulated fleet emits genuine osquery result logs with neutral placeholder command lines; it&apos;s labeled Simulated.
        Deploy endpoint-agent/osquery/sentivra-pack.conf to collect real telemetry. Log uploads accept auth.log, Windows Security
        events as JSON lines, and Wazuh alerts.json.
      </p>
      <AnalysisError error={error} />
      {result ? (
        <AnalysisSummary result={result} extra={<BatchDetails result={result} />} />
      ) : (
        <EmptyState title="No telemetry analyzed yet">Run the simulated fleet, or upload osquery results or a log file.</EmptyState>
      )}
    </>
  );
}
