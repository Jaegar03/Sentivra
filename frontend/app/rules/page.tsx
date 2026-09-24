"use client";

import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { humanize } from "@/lib/format";
import type { RulesInventory } from "@/types/api";

export default function RulesPage() {
  const { data, error } = useApi<RulesInventory>("/api/v1/rules");
  return (
    <>
      <PageHeader
        title="Rules"
        description="Detection rules live in detection-rules/, outside application code. This is what's loaded right now, including any Sigma rule the engine can't support, with the reason."
      />
      {error ? <ErrorState error={error} /> : null}
      {!data && !error ? <LoadingBlock /> : null}
      {data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Sigma</CardTitle>
              <CardDescription>
                {data.sigma.loaded.length} loaded · {data.sigma.unsupported.length} unsupported · ATT&CK tags resolved against
                ATT&CK v{data.attack_index.attack_version} ({data.attack_index.techniques} techniques)
              </CardDescription>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Rule</TableHead><TableHead>Level</TableHead><TableHead>Status</TableHead><TableHead>Log source</TableHead><TableHead>Tags</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {data.sigma.loaded.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell><span className="font-medium">{r.title}</span><span className="block font-mono text-xs text-muted-foreground">{r.path}</span></TableCell>
                      <TableCell>{humanize(r.level)}</TableCell>
                      <TableCell>{humanize(r.status)}</TableCell>
                      <TableCell className="text-xs">{Object.entries(r.logsource).map(([k, v]) => `${k}: ${v}`).join(", ")}</TableCell>
                      <TableCell className="font-mono text-xs">{r.tags.join(" ")}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {data.sigma.unsupported.length ? (
                <div className="mt-4 space-y-1 text-sm">
                  <p className="font-medium">Not loaded</p>
                  {data.sigma.unsupported.map((u) => <p key={u.path} className="text-muted-foreground"><span className="font-mono">{u.path}</span>: {u.reason}</p>)}
                </div>
              ) : null}
            </CardContent>
          </Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader><CardTitle>Custom rule packs</CardTitle><CardDescription>Thresholds and patterns read by Sentivra&apos;s own detectors</CardDescription></CardHeader>
              <CardContent className="space-y-3 text-sm">
                {data.custom.map((c) => (
                  <div key={c.file} className="rounded-lg border p-3">
                    <p className="font-mono text-xs">{c.file}</p>
                    <p className="text-muted-foreground">Used by {c.used_by}</p>
                    {c.error ? <p className="text-destructive">{c.error}</p> : <p className="mt-1 text-xs text-muted-foreground">{c.rules?.length ?? 0} rules</p>}
                  </div>
                ))}
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>YARA</CardTitle><CardDescription>Rule files compiled by YaraDetector</CardDescription></CardHeader>
              <CardContent className="space-y-1 text-sm">
                {data.yara.files.map((f) => <p key={f} className="font-mono text-xs">detection-rules/yara/{f}</p>)}
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </>
  );
}
