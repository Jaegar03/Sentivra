"use client";

import { useState } from "react";

import { AlertsTable } from "@/components/sentivra/alerts-table";
import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { humanize } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { AlertListItem, AlertStatus, Severity } from "@/types/api";

const SEVERITY_FILTERS: (Severity | "ALL")[] = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const STATUS_FILTERS: (AlertStatus | "ALL")[] = ["ALL", "OPEN", "ACKNOWLEDGED", "RESOLVED"];

function FilterGroup<T extends string>({ label, options, value, onChange, format }: {
  label: string;
  options: T[];
  value: T;
  onChange: (v: T) => void;
  format: (v: T) => string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={label}>
      <span className="mr-1 text-sm text-muted-foreground">{label}</span>
      {options.map((o) => (
        <button key={o} type="button" onClick={() => onChange(o)} aria-pressed={value === o}
          className={cn("rounded-md border px-2.5 py-1 text-sm",
            value === o ? "border-foreground/30 bg-muted font-medium" : "text-muted-foreground hover:bg-muted")}>
          {format(o)}
        </button>
      ))}
    </div>
  );
}

export default function ThreatsPage() {
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [status, setStatus] = useState<AlertStatus | "ALL">("ALL");
  const params = new URLSearchParams({ limit: "200" });
  if (severity !== "ALL") params.set("min_severity", severity);
  if (status !== "ALL") params.set("status", status);
  const { data, error, isValidating } = useApi<AlertListItem[]>(`/api/v1/alerts?${params}`);

  return (
    <>
      <PageHeader
        title="Threats"
        description="Every alert the risk engine raised. Open one to see why it fired, the evidence, and what to do."
      />
      <div className="flex flex-wrap gap-x-6 gap-y-2">
        <FilterGroup label="Minimum severity" options={SEVERITY_FILTERS} value={severity} onChange={setSeverity}
          format={(v) => (v === "ALL" ? "Any" : humanize(v))} />
        <FilterGroup label="Status" options={STATUS_FILTERS} value={status} onChange={setStatus}
          format={(v) => (v === "ALL" ? "Any" : humanize(v))} />
      </div>
      <Card>
        <CardContent className={cn("transition-opacity", isValidating && data && "opacity-70")}>
          {error ? <ErrorState error={error} /> : null}
          {!data && !error ? <LoadingBlock /> : null}
          {data && data.length === 0 ? <EmptyState title="No alerts match these filters" /> : null}
          {data && data.length > 0 ? <AlertsTable alerts={data} /> : null}
        </CardContent>
      </Card>
    </>
  );
}
