import type { ReactNode } from "react";
import { CircleDashed, ServerCrash } from "lucide-react";

import { ApiError } from "@/lib/api";

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0 space-y-1">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed px-6 py-10 text-center">
      <CircleDashed className="size-6 text-muted-foreground" aria-hidden />
      <p className="text-sm font-medium">{title}</p>
      {children ? <div className="max-w-md text-sm text-muted-foreground">{children}</div> : null}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof ApiError || error instanceof Error ? error.message : "Something went wrong.";
  const status = error instanceof ApiError ? error.status : undefined;
  return (
    <div role="alert" className="flex items-start gap-3 rounded-xl border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm">
      <ServerCrash className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden />
      <div className="min-w-0">
        <p className="font-medium">{status === 501 ? "Not implemented yet" : "Request failed"}</p>
        <p className="break-words text-muted-foreground">{message}</p>
      </div>
    </div>
  );
}

/** Initial load only. Refetches keep the previous render (see useApi). */
export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center rounded-xl border px-6 py-10 text-sm text-muted-foreground" aria-busy>
      {label}
    </div>
  );
}
