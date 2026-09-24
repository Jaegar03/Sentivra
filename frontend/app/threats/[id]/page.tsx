"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { ChevronRight } from "lucide-react";

import { SourceTypeBadge } from "@/components/sentivra/badges";
import { AlertExplanation, FindingCard } from "@/components/sentivra/findings";
import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { classificationLabel, dateTime, humanize } from "@/lib/format";
import type { AlertDetail, AlertStatus, SecurityEvent } from "@/types/api";

function isFullEvent(e: AlertDetail["event"]): e is SecurityEvent {
  return "event_id" in e;
}

export default function ThreatDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, error, mutate } = useApi<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(id)}`);
  const [pending, setPending] = useState<AlertStatus | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  async function setStatus(status: AlertStatus) {
    setPending(status);
    setActionError(null);
    try {
      await api.setAlertStatus(id, status);
      await mutate();
    } catch (e) {
      setActionError(e);
    } finally {
      setPending(null);
    }
  }

  if (error) return <ErrorState error={error} />;
  if (!data) return <LoadingBlock />;
  const event = data.event;

  return (
    <>
      <nav className="flex items-center gap-1 text-sm text-muted-foreground" aria-label="Breadcrumb">
        <Link href="/threats" className="hover:text-foreground">Threats</Link>
        <ChevronRight className="size-3.5" aria-hidden />
        <span className="font-mono">{id.slice(0, 8)}</span>
      </nav>
      <PageHeader
        title={classificationLabel(data.classification)}
        description={<>Raised {dateTime(data.generated_at)} · status <span className="font-medium text-foreground">{humanize(data.status)}</span></>}
        actions={
          <>
            {(["ACKNOWLEDGED", "RESOLVED", "OPEN"] as AlertStatus[]).filter((s) => s !== data.status).map((s) => (
              <Button key={s} variant={s === "RESOLVED" ? "default" : "outline"} disabled={pending !== null} onClick={() => setStatus(s)}>
                {pending === s ? "Saving…" : s === "OPEN" ? "Reopen" : humanize(s === "ACKNOWLEDGED" ? "Acknowledge" : "Resolve")}
              </Button>
            ))}
          </>
        }
      />
      {actionError ? <ErrorState error={actionError} /> : null}

      <AlertExplanation assessment={data} />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>Each detector&apos;s own verdict and evidence. The risk engine combines them; none decides alone.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {data.findings.map((f, i) => <FindingCard key={`${f.detector}-${i}`} finding={f} />)}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Event</CardTitle>
            <CardDescription>What the detectors analyzed</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {isFullEvent(event) ? (
              <>
                <dl className="grid grid-cols-[7rem_1fr] gap-y-1.5">
                  <dt className="text-muted-foreground">Input</dt><dd><SourceTypeBadge sourceType={event.source_type} /></dd>
                  <dt className="text-muted-foreground">Source</dt><dd>{event.source}</dd>
                  <dt className="text-muted-foreground">Type</dt><dd>{humanize(event.event_type)}</dd>
                  <dt className="text-muted-foreground">Time</dt><dd>{dateTime(event.timestamp)}</dd>
                  <dt className="text-muted-foreground">Event ID</dt><dd className="font-mono text-xs break-all">{event.event_id}</dd>
                </dl>
                {event.attachments.length ? (
                  <div>
                    <p className="mb-1 text-muted-foreground">Files (hash and metadata only; the file itself isn&apos;t kept)</p>
                    <ul className="space-y-1">
                      {event.attachments.map((a) => (
                        <li key={a.sha256 ?? a.filename} className="rounded-md border p-2">
                          <p className="font-medium break-all">{a.filename}</p>
                          <p className="font-mono text-xs break-all text-muted-foreground">sha256 {a.sha256}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <details>
                  <summary className="cursor-pointer text-muted-foreground">Event metadata</summary>
                  <pre className="mt-2 max-h-80 overflow-auto rounded-md bg-muted p-2 text-xs">
                    {JSON.stringify({ ...event.metadata, file_metadata: undefined }, null, 2)}
                  </pre>
                </details>
              </>
            ) : (
              <p className="text-muted-foreground">The event record for this alert isn&apos;t available.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
