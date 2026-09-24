"use client";

import Link from "next/link";

import { StatusPill } from "@/components/sentivra/badges";
import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import type { Integration } from "@/types/api";

export default function MessagesPage() {
  const { data, error } = useApi<Integration[]>("/api/v1/integrations");
  const messaging = data?.filter((i) => i.kind === "messaging") ?? [];
  return (
    <>
      <PageHeader
        title="Messages"
        description="Email and messaging security: phishing, malicious links and attachments, prompt injection hidden in messages."
      />
      <EmptyState title="Message analysis isn't available in this build">
        The Gmail, Telegram and WhatsApp Business connectors and the message-content detectors (phishing, URL, prompt
        injection) haven&apos;t been built yet, so there are no messages to show. Attachment scanning already works on the{" "}
        <Link href="/files" className="underline underline-offset-4">Files</Link> page.
      </EmptyState>
      <Card>
        <CardHeader><CardTitle>Connector status</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {error ? <ErrorState error={error} /> : null}
          {!data && !error ? <LoadingBlock /> : null}
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
    </>
  );
}
