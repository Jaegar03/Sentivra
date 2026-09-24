"use client";

import { StatusPill } from "@/components/sentivra/badges";
import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { humanize, metricLabel, significant } from "@/lib/format";
import type { ModelEntry } from "@/types/api";

function Metrics({ metrics }: { metrics: Record<string, number> }) {
  const entries = Object.entries(metrics);
  if (!entries.length) return <p className="text-sm text-muted-foreground">No headline metrics recorded.</p>;
  return (
    <Table>
      <TableHeader><TableRow><TableHead>Metric (test split)</TableHead><TableHead className="text-right">Value</TableHead></TableRow></TableHeader>
      <TableBody>
        {entries.map(([k, v]) => (
          <TableRow key={k}>
            <TableCell>{metricLabel(k)}</TableCell>
            <TableCell className="text-right tabular">{Number.isInteger(v) ? v : v.toFixed(3)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function ModelsPage() {
  const { data, error } = useApi<ModelEntry[]>("/api/v1/models");
  return (
    <>
      <PageHeader
        title="Models"
        description="Every model directory in the registry, read live from its metadata.json. A metric is shown only with its dataset, split and evaluation date, and untrained models say so."
      />
      {error ? <ErrorState error={error} /> : null}
      {!data && !error ? <LoadingBlock /> : null}
      <div className="grid gap-4 lg:grid-cols-2">
        {data?.map((entry) => {
          const m = entry.metadata;
          return (
            <Card key={`${entry.domain}/${entry.name}`}>
              <CardHeader>
                <CardTitle className="flex flex-wrap items-center gap-2">
                  {humanize(entry.domain)} / {humanize(entry.name)}
                  <StatusPill status={entry.trained ? "Available" : "Not trained"} />
                </CardTitle>
                <CardDescription className="font-mono text-xs">{entry.directory}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                {!m ? (
                  <p className="text-muted-foreground">{entry.reason_untrained}</p>
                ) : (
                  <>
                    <dl className="grid grid-cols-[9rem_1fr] gap-y-1">
                      <dt className="text-muted-foreground">Version</dt><dd>{m.version}</dd>
                      <dt className="text-muted-foreground">Format</dt><dd>{m.artifact_format}</dd>
                      <dt className="text-muted-foreground">Trained on</dt><dd>{m.training_dataset}</dd>
                      <dt className="text-muted-foreground">Split</dt><dd>{m.split_method ?? "—"}</dd>
                      <dt className="text-muted-foreground">Evaluated</dt><dd>{m.evaluation_date ?? "—"}</dd>
                      <dt className="text-muted-foreground">Threshold</dt>
                      <dd>{m.threshold != null ? significant(m.threshold) : "—"}{m.threshold_policy ? <span className="block text-xs text-muted-foreground">{m.threshold_policy}</span> : null}</dd>
                      <dt className="text-muted-foreground">SHA-256</dt><dd className="font-mono text-xs break-all">{m.sha256}</dd>
                    </dl>
                    <Metrics metrics={m.evaluation_metrics} />
                    {m.limitations.length ? (
                      <div>
                        <p className="mb-1 font-medium">Limitations</p>
                        <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                          {m.limitations.map((l) => <li key={l}>{l}</li>)}
                        </ul>
                      </div>
                    ) : null}
                  </>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </>
  );
}
