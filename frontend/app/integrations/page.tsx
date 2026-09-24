"use client";

import { StatusPill } from "@/components/sentivra/badges";
import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import type { Integration } from "@/types/api";

const GROUPS: { kind: Integration["kind"]; title: string }[] = [
  { kind: "messaging", title: "Messaging connectors" },
  { kind: "telemetry", title: "Telemetry sources" },
  { kind: "engine", title: "Detection engines" },
];

export default function IntegrationsPage() {
  const { data, error } = useApi<Integration[]>("/api/v1/integrations");
  return (
    <>
      <PageHeader
        title="Integrations"
        description="What is connected versus what is planned. Nothing here shows as available unless it actually works in this build."
      />
      {error ? <ErrorState error={error} /> : null}
      {!data && !error ? <LoadingBlock /> : null}
      <div className="grid gap-4 lg:grid-cols-3">
        {data
          ? GROUPS.map((g) => (
              <Card key={g.kind}>
                <CardHeader><CardTitle>{g.title}</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {data.filter((i) => i.kind === g.kind).map((i) => (
                    <div key={i.name} className="space-y-1 rounded-lg border p-3 text-sm">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{i.name}</span>
                        <StatusPill status={i.status} />
                      </div>
                      <p className="text-muted-foreground">{i.detail}</p>
                      {i.engine_version ? <p className="font-mono text-xs text-muted-foreground">version {i.engine_version}</p> : null}
                    </div>
                  ))}
                </CardContent>
              </Card>
            ))
          : null}
      </div>
    </>
  );
}
