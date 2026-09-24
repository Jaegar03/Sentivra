import Link from "next/link";

import { SeverityBadge, SourceTypeBadge } from "@/components/sentivra/badges";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { classificationLabel, detectorLabel, humanize, relative, shortId } from "@/lib/format";
import type { AlertListItem } from "@/types/api";

export function AlertsTable({ alerts }: { alerts: AlertListItem[] }) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>Classification</TableHead>
            <TableHead>Detectors</TableHead>
            <TableHead>Source</TableHead>
            <TableHead className="text-right">Risk</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Raised</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {alerts.map((a) => (
            <TableRow key={a.assessment_id}>
              <TableCell><SeverityBadge severity={a.severity} /></TableCell>
              <TableCell>
                <Link href={`/threats/${a.assessment_id}`} className="font-medium underline-offset-4 hover:underline">
                  {classificationLabel(a.classification)}
                </Link>
                <span className="ml-2 font-mono text-xs text-muted-foreground">{shortId(a.assessment_id)}</span>
              </TableCell>
              <TableCell className="max-w-[16rem] truncate text-muted-foreground" title={a.findings.map((f) => f.detector).join(", ")}>
                {a.findings.map((f) => detectorLabel(f.detector)).join(", ")}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <SourceTypeBadge sourceType={a.event.source_type} />
                  <span className="text-xs text-muted-foreground">{a.event.source}</span>
                </div>
              </TableCell>
              <TableCell className="text-right tabular">{a.risk_score}</TableCell>
              <TableCell className="text-muted-foreground">{humanize(a.status)}</TableCell>
              <TableCell className="whitespace-nowrap text-muted-foreground">{relative(a.generated_at)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
