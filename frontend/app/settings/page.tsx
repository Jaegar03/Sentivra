"use client";

import { SessionDetails } from "@/components/sentivra/auth-gate";
import { StatusPill } from "@/components/sentivra/badges";
import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { API_BASE } from "@/lib/api";
import type { DetectorInfo, Health } from "@/types/api";

export default function SettingsPage() {
  const health = useApi<Health>("/api/v1/health");
  const detectors = useApi<DetectorInfo[]>("/api/v1/detectors");
  return (
    <>
      <PageHeader
        title="Settings"
        description="Connection and environment. Backend settings come from environment variables (see .env.example) and aren't editable here."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Connection</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            <dl className="grid grid-cols-[9rem_1fr] gap-y-1.5">
              <dt className="text-muted-foreground">API base URL</dt><dd className="font-mono text-xs break-all">{API_BASE}</dd>
              <dt className="text-muted-foreground">Environment</dt><dd>{health.data?.environment ?? "…"}</dd>
              <dt className="text-muted-foreground">Database</dt><dd>{health.data ? <StatusPill status={health.data.database === "ok" ? "Available" : "Error"} /> : "…"}</dd>
              <SessionDetails />
            </dl>
            {health.error ? <ErrorState error={health.error} /> : null}
            <p className="text-xs text-muted-foreground">
              Set NEXT_PUBLIC_API_BASE_URL in frontend/.env.local to point the dashboard at another backend, and add this
              dashboard&apos;s origin to SENTIVRA_CORS_ORIGINS on the backend.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>This build</CardTitle>
            <CardDescription>Scope of the demonstration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1.5 text-sm text-muted-foreground">
            <p>Runs locally: FastAPI + SQLite and this Next.js app. No Docker, Redis or message queue.</p>
            <p>Detects and explains only. There is no automation or remediation.</p>
            <p>
              Every API call needs an OAuth2 access token. The token lives only in this tab and is dropped when it
              expires or the tab closes.
            </p>
<p>
              Webhook connectors (Gmail, Telegram, WhatsApp) are built: each is authenticated by the provider itself,
              never by your access token. They need a public HTTPS URL to be reached, so keep the backend bound to
              localhost until you deliberately expose it.
            </p>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader><CardTitle>Detectors</CardTitle><CardDescription>Live availability reported by each detector</CardDescription></CardHeader>
        <CardContent className="space-y-2">
          {!detectors.data && !detectors.error ? <LoadingBlock /> : null}
          {detectors.error ? <ErrorState error={detectors.error} /> : null}
          {detectors.data?.map((d) => (
            <div key={d.name} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border p-3 text-sm">
              <div className="min-w-0">
                <p className="font-medium">{d.name} <span className="text-xs text-muted-foreground">v{d.version}</span></p>
                <p className="break-words text-muted-foreground">{d.availability.detail}</p>
              </div>
              <StatusPill status={d.availability.status} />
            </div>
          ))}
        </CardContent>
      </Card>
    </>
  );
}
