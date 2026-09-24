"use client";

import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { dateTime, humanize } from "@/lib/format";
import type { AuditEntry } from "@/types/api";

export default function AuditPage() {
  const { data, error } = useApi<{ total: number; entries: AuditEntry[] }>("/api/v1/audit?limit=200");
  return (
    <>
      <PageHeader
        title="Audit Log"
        description="Append-only record of every analysis and every alert status change. The API exposes no way to edit or delete entries."
      />
      <Card>
        <CardContent className="overflow-x-auto">
          {error ? <ErrorState error={error} /> : null}
          {!data && !error ? <LoadingBlock /> : null}
          {data && data.entries.length === 0 ? <EmptyState title="Nothing recorded yet" /> : null}
          {data && data.entries.length > 0 ? (
            <>
              <p className="mb-2 text-sm text-muted-foreground">Latest {data.entries.length} of {data.total}</p>
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Time</TableHead><TableHead>Actor</TableHead><TableHead>Action</TableHead><TableHead>Resource</TableHead><TableHead>Detail</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {data.entries.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell className="whitespace-nowrap tabular">{dateTime(e.created_at)}</TableCell>
                      <TableCell>{e.actor}</TableCell>
                      <TableCell>{humanize(e.action)}</TableCell>
                      <TableCell className="font-mono text-xs">{e.resource}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {Object.entries(e.detail).filter(([, v]) => v !== null).map(([k, v]) => `${k}=${String(v)}`).join("  ")}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          ) : null}
        </CardContent>
      </Card>
    </>
  );
}
