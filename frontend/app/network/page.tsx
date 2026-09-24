"use client";

import { AnalysisError, AnalysisSummary, RunButton, UploadButton, useAnalysis } from "@/components/sentivra/analysis-result";
import { StatusPill } from "@/components/sentivra/badges";
import { MitreList } from "@/components/sentivra/findings";
import { EmptyState, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { humanize, integer } from "@/lib/format";
import type { NetworkAnalysisResponse } from "@/types/api";

function NetworkDetails({ result }: { result: NetworkAnalysisResponse }) {
  const n = result.network;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Layers</CardTitle>
            <CardDescription>
              {integer(n.flow_count)} flows{result.input_format ? ` from ${result.input_format}` : ""}
              {result.truncated ? " (truncated at the upload limit)" : ""}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow><TableHead>Layer</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Flows flagged</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(n.layer_status).map(([layer, status]) => (
                  <TableRow key={layer}>
                    <TableCell>{humanize(layer)}</TableCell>
                    <TableCell><StatusPill status={status.startsWith("Available") ? "Available" : status} /></TableCell>
                    <TableCell className="text-right tabular">
                      {layer === "behavior_rules" ? `${n.behavior_findings.length} findings` : integer(n.layer_fire_counts[layer] ?? 0)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <p className="mt-3 text-xs text-muted-foreground">
              A flow counts as model-flagged when at least two layers agree (fusion cut {n.fusion_cut.toFixed(3)}, chosen on
              calibration data). {n.model_flag_significance.summary}.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Behavior rules</CardTitle>
            <CardDescription>Patterns across many flows (thresholds in detection-rules/custom/network_rules.yaml)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {n.behavior_findings.length === 0 ? <p className="text-sm text-muted-foreground">No behavior rule fired.</p> : null}
            {n.behavior_findings.map((f, i) => (
              <div key={`${f.rule}-${i}`} className="space-y-1.5 rounded-lg border p-3 text-sm">
                <p className="font-medium">{humanize(f.rule)} <span className="font-mono text-xs text-muted-foreground">{f.subject}</span></p>
                <p className="text-muted-foreground">{f.description}</p>
                <p className="font-mono text-xs text-muted-foreground">
                  {Object.entries(f.details).map(([k, v]) => `${k}=${String(v)}`).join("  ")}
                </p>
                <MitreList mappings={f.mitre_attack} />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      {n.flagged_flows.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Flagged flows</CardTitle>
            <CardDescription>
              Highest-scoring {integer(Math.min(20, n.flagged_flows.length))} of {integer(n.flagged_flows_total)}. Ground-truth labels only exist
              for demo data and labeled CSVs; no layer uses them.
            </CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Flow</TableHead><TableHead className="text-right">Fused</TableHead><TableHead>Layers / rules</TableHead>
                  <TableHead>Why</TableHead><TableHead>Ground truth</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {n.flagged_flows.slice(0, 20).map((v, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs whitespace-nowrap">
                      {String(v.flow.src_ip)}:{String(v.flow.src_port)} → {String(v.flow.dst_ip)}:{String(v.flow.dst_port)}/{String(v.flow.protocol)}
                    </TableCell>
                    <TableCell className="text-right tabular">{v.fused_score.toFixed(2)}</TableCell>
                    <TableCell className="text-xs">{[...v.fired_layers, ...v.behavior_rules.map((r) => `rule:${r}`)].join(", ")}</TableCell>
                    <TableCell className="max-w-md text-xs text-muted-foreground">{v.explanations[0] ?? "Covered by a behavior rule"}</TableCell>
                    <TableCell className="text-xs">{v.ground_truth_label ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export default function NetworkPage() {
  const { result, error, busy, run } = useAnalysis<NetworkAnalysisResponse>();
  return (
    <>
      <PageHeader
        title="Network"
        description="Signature-style behavior rules plus four per-flow layers (statistical, Isolation Forest, autoencoder, classifier). The models were trained on synthetic flows; see Models for what that means."
        actions={
          <>
            <RunButton label="Run demo sample" busy={busy} onClick={() => run("Run demo sample", api.networkDemo)} />
            <UploadButton label="Upload PCAP or flow CSV" accept=".pcap,.pcapng,.cap,.csv" busy={busy}
              onFile={(f) => run("Upload PCAP or flow CSV", () => api.analyzeNetwork(f))} />
          </>
        }
      />
      <p className="text-xs text-muted-foreground">
        Suricata and Zeek aren&apos;t integrated in this build (nothing reads their logs yet), so results come from Sentivra&apos;s own rules and models only.
        Uploaded traffic is parsed in memory and discarded after the request.
      </p>
      <AnalysisError error={error} />
      {result ? (
        <AnalysisSummary result={result} extra={<NetworkDetails result={result} />} />
      ) : (
        <EmptyState title="No analysis yet">
          Run the bundled demo sample (synthetic flows, labeled Demo data) or upload a PCAP/PCAPNG, a Sentivra flow CSV, or a
          CICFlowMeter CSV.
        </EmptyState>
      )}
    </>
  );
}
