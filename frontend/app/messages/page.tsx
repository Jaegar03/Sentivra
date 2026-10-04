"use client";

import { SourceTypeBadge, StatusPill } from "@/components/sentivra/badges";
import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { dateTime, relative } from "@/lib/format";
import type { Integration, SecurityEvent } from "@/types/api";

const MESSAGE_TYPES = new Set(["gmail_message", "telegram_message", "whatsapp_message"]);

type MessageEvent = Omit<SecurityEvent, "content"> & {
  content: {
    sender?: string | null;
    subject?: string | null;
    body?: string | null;
    recipients?: string[];
    urls?: string[];
  } | null;
};

const SOURCE_LABEL: Record<string, string> = {
  gmail: "Gmail",
  telegram: "Telegram",
  whatsapp: "WhatsApp",
};

function MessageCard({ event }: { event: MessageEvent }) {
  const content = event.content;
  const sha = typeof event.metadata.content_sha256 === "string" ? event.metadata.content_sha256 : null;
  const urls = content?.urls ?? [];
  return (
    <div className="space-y-2 rounded-lg border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{SOURCE_LABEL[event.source] ?? event.source}</span>
        <SourceTypeBadge sourceType={event.source_type} />
        <span className="ml-auto text-xs text-muted-foreground" title={dateTime(event.timestamp)}>
          {relative(event.timestamp)}
        </span>
      </div>
      <div className="space-y-1">
        {content?.subject ? <p className="font-medium">{content.subject}</p> : null}
        <p className="break-words text-muted-foreground">{content?.sender ?? "(no sender recorded)"}</p>
        {content?.recipients?.length ? (
          <p className="break-words text-xs text-muted-foreground">to {content.recipients.join(", ")}</p>
        ) : null}
      </div>
      {urls.length ? (
        <div className="space-y-0.5">
          <p className="text-xs font-medium text-muted-foreground">URLs found (shown as text, not links)</p>
          {urls.map((url) => (
            <p key={url} className="break-all font-mono text-xs">{url}</p>
          ))}
        </div>
      ) : null}
      {event.attachments.length ? (
        <p className="text-xs text-muted-foreground">
          Attachments: {event.attachments.map((a) => `${a.filename} (${a.declared_mime ?? "unknown type"})`).join(", ")}
          {" — "}metadata only, bytes never fetched
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        {content && content.body === null && sha
          ? <>Body not retained: analyzed in memory, stored as SHA-256 {sha.slice(0, 16)}…</>
          : "Body not retained."}
      </p>
    </div>
  );
}

export default function MessagesPage() {
  const integrations = useApi<Integration[]>("/api/v1/integrations");
  const events = useApi<SecurityEvent[]>("/api/v1/events?limit=200");

  const messaging = integrations.data?.filter((i) => i.kind === "messaging") ?? [];
  const messages = (events.data ?? []).filter((e) => MESSAGE_TYPES.has(e.event_type)) as MessageEvent[];

  return (
    <>
      <PageHeader
        title="Messages"
        description="Email and messaging security: what the Gmail, Telegram and WhatsApp webhooks delivered, and what was done with it."
      />
      <Card>
        <CardHeader><CardTitle>Connector status</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {integrations.error ? <ErrorState error={integrations.error} /> : null}
          {!integrations.data && !integrations.error ? <LoadingBlock /> : null}
          {messaging.map((i) => (
            <div key={i.name} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border p-3 text-sm">
              <div className="min-w-0">
                <p className="font-medium">{i.name}</p>
                <p className="text-muted-foreground">{i.detail}</p>
              </div>
              <StatusPill status={i.status} />
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Delivered messages</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {events.error ? <ErrorState error={events.error} /> : null}
          {!events.data && !events.error ? <LoadingBlock /> : null}
          {events.data && messages.length === 0 ? (
            <EmptyState title="No messages have arrived yet">
              A connector has to be configured first — the status above names the variable that&apos;s missing. Setup
              steps for Telegram, WhatsApp and Gmail are in <code>docs/api.md</code> (§ Webhooks). Message bodies are
              never stored: you&apos;ll see the sender, subject, URLs and a hash here.
            </EmptyState>
          ) : null}
          {messages.map((m) => (
            <MessageCard key={m.event_id} event={m} />
          ))}
          <p className="text-xs text-muted-foreground">
            No detector in this build analyzes message content yet (phishing, URL and prompt injection are Phase 4),
            so an arriving message is stored and labeled, not judged. This page never reports a message as clean.
          </p>
        </CardContent>
      </Card>
    </>
  );
}
