"use client";

import Link from "next/link";
import { useState } from "react";

import { ChartCard } from "@/components/charts/chart-card";
import { CategoryBars, SeverityBars, TimelineColumns } from "@/components/charts/charts";
import { AlertsTable } from "@/components/sentivra/alerts-table";
import { SourceTypeBadge } from "@/components/sentivra/badges";
import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { classificationLabel, detectorLabel, humanize, integer } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SEVERITIES, type AlertListItem, type Health, type Metrics, type SourceType } from "@/types/api";

const WINDOWS = [
  { hours: 24, label: "Last 24 hours" },
  { hours: 24 * 7, label: "Last 7 days" },
  { hours: 24 * 30, label: "Last 30 days" },
];

function bucketLabel(start: string, index: number, bucket: "hour" | "day") {
  const d = new Date(start);
  if (bucket === "hour") {
    d.setUTCHours(d.getUTCHours() + index + 1);
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  d.setUTCDate(d.getUTCDate() + index + 1);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function StatTile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card size="sm">
      <CardContent className="space-y-1">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-2xl font-semibold">{value}</p>
        {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

// Domains with detectors count alerts any of their detectors contributed to.
// Domains whose detector hasn't been built say so instead of showing a zero
// that would read as "nothing found".
const DOMAINS: { label: string; domain: "network" | "files" | "endpoint" | null; href: string }[] = [
  { label: "Network anomalies", domain: "network", href: "/network" },
  { label: "Malicious files", domain: "files", href: "/files" },
  { label: "Suspicious URLs", domain: null, href: "/messages" },
  { label: "Prompt attacks", domain: null, href: "/prompt-security" },
  { label: "Endpoint anomalies", domain: "endpoint", href: "/endpoint" },
];

export default function OverviewPage() {
  const [windowHours, setWindowHours] = useState(24);
  const metrics = useApi<Metrics>(`/api/v1/metrics?window_hours=${windowHours}`);
  const alerts = useApi<AlertListItem[]>("/api/v1/alerts?limit=8");
  const health = useApi<Health>("/api/v1/health");

  const m = metrics.data;
  const engines = health.data ? Object.values(health.data.engines) : [];
  const available = engines.filter((e) => e.status === "Available").length;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Detections across every Sentivra layer. Counts are what the platform has seen; model accuracy lives on the Models page, tied to its evaluation data."
      />

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Time window">
        {WINDOWS.map((w) => (
          <button
            key={w.hours}
            type="button"
            onClick={() => setWindowHours(w.hours)}
            aria-pressed={windowHours === w.hours}
            className={cn(
              "rounded-md border px-3 py-1 text-sm",
              windowHours === w.hours ? "border-foreground/30 bg-muted font-medium" : "text-muted-foreground hover:bg-muted",
            )}
          >
            {w.label}
          </button>
        ))}
      </div>

      {metrics.error ? <ErrorState error={metrics.error} /> : null}
      {!m && !metrics.error ? <LoadingBlock /> : null}

      {m ? (
        <div className={cn("space-y-6 transition-opacity", metrics.isValidating && "opacity-70")}>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,2fr)]">
            <Card>
              <CardHeader>
                <CardTitle>Security score</CardTitle>
                <CardDescription>From open alerts in the window</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="text-6xl font-semibold tracking-tight">{m.security_score.value}</p>
                <p className="text-xs text-muted-foreground">{m.security_score.formula}.</p>
                <p className="text-xs text-muted-foreground">{m.security_score.note}</p>
              </CardContent>
            </Card>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-2">
              <StatTile label="Open alerts" value={integer(m.window.open_alerts)} hint={`${integer(m.window.alerts)} raised in window`} />
              <StatTile label="Open high or critical" value={integer(m.window.open_by_severity.HIGH + m.window.open_by_severity.CRITICAL)} />
              <StatTile label="Events analyzed" value={integer(m.totals.events)} hint="all time" />
              <StatTile label="Engines available" value={health.data ? `${available}/${engines.length}` : "…"} hint="see Integrations" />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            <span>Alerts by input:</span>
            {(["LIVE", "SIMULATED", "DEMO_DATA"] as SourceType[]).map((t) => (
              <span key={t} className="flex items-center gap-1.5">
                <SourceTypeBadge sourceType={t} /> <span className="tabular text-foreground">{integer(m.window.by_source_type[t] ?? 0)}</span>
              </span>
            ))}
          </div>

          {m.window.alerts === 0 ? (
            <EmptyState title="No alerts in this window">
              Run the scenarios in <Link href="/demo" className="underline underline-offset-4">Demo mode</Link> to see the
              pipeline end to end. Demo results are labeled as demo or simulated data everywhere they appear.
            </EmptyState>
          ) : (
            <>
              <div className="grid gap-4 lg:grid-cols-2">
                <ChartCard
                  title="Threat timeline"
                  description={`Alerts per ${m.window.timeline.bucket}`}
                  rows={m.window.timeline.counts.map((value, i) => ({ label: bucketLabel(m.window.timeline.start, i, m.window.timeline.bucket), value }))}
                  valueLabel="Alerts"
                >
                  <TimelineColumns
                    data={m.window.timeline.counts.map((value, i) => ({ label: bucketLabel(m.window.timeline.start, i, m.window.timeline.bucket), value }))}
                  />
                </ChartCard>
                <ChartCard
                  title="Severity distribution"
                  description="Alerts raised in the window"
                  rows={[...SEVERITIES].filter((s) => s !== "SAFE").reverse().map((s) => ({ label: humanize(s), value: m.window.by_severity[s] }))}
                  valueLabel="Alerts"
                >
                  <SeverityBars counts={m.window.by_severity} />
                </ChartCard>
              </div>
              <div className="grid gap-4 lg:grid-cols-2">
                <ChartCard
                  title="Detection sources"
                  description="Alerts each detector contributed a finding to"
                  rows={Object.entries(m.window.by_detector).map(([label, value]) => ({ label: detectorLabel(label), value }))}
                  valueLabel="Alerts"
                >
                  <CategoryBars data={Object.entries(m.window.by_detector).map(([label, value]) => ({ label: detectorLabel(label), value }))} />
                </ChartCard>
                <ChartCard
                  title="Top threat categories"
                  description="Each alert's classification (its strongest finding's category)"
                  rows={Object.entries(m.window.by_classification).map(([label, value]) => ({ label: classificationLabel(label), value }))}
                  valueLabel="Alerts"
                >
                  <CategoryBars data={Object.entries(m.window.by_classification).map(([label, value]) => ({ label: classificationLabel(label), value }))} labelWidth={210} />
                </ChartCard>
              </div>
            </>
          )}

          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            {DOMAINS.map((d) => (
              <Link key={d.label} href={d.href} className="block">
                <Card size="sm" className="h-full hover:ring-foreground/25">
                  <CardContent className="space-y-1">
                    <p className="text-sm text-muted-foreground">{d.label}</p>
                    {d.domain ? (
                      <p className="text-2xl font-semibold">{integer(m.window.by_domain[d.domain] ?? 0)}</p>
                    ) : (
                      <p className="text-sm font-medium">Detector not built yet</p>
                    )}
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Recent threats</CardTitle>
          <CardDescription>
            Latest alerts. <Link href="/threats" className="underline underline-offset-4">All threats</Link>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {alerts.error ? <ErrorState error={alerts.error} /> : null}
          {alerts.data && alerts.data.length === 0 ? <EmptyState title="No alerts yet" /> : null}
          {alerts.data && alerts.data.length > 0 ? <AlertsTable alerts={alerts.data} /> : null}
        </CardContent>
      </Card>
    </>
  );
}
