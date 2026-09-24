"use client";

import { useEffect, useState } from "react";

import { EmptyState, ErrorState, PageHeader } from "@/components/sentivra/states";
import { ApiError, api } from "@/lib/api";

export default function PromptSecurityPage() {
  // Ask the real endpoint rather than hard-coding a "coming soon": when the
  // detector lands, this page reports the change without an edit.
  const [probe, setProbe] = useState<{ status: number; message: string } | null>(null);
  useEffect(() => {
    let cancelled = false;
    api.probe("/api/v1/analyze/prompt").then(
      () => !cancelled && setProbe({ status: 200, message: "The prompt endpoint answered." }),
      (e) => !cancelled && setProbe({ status: e instanceof ApiError ? e.status : 0, message: e instanceof Error ? e.message : "" }),
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <PageHeader
        title="Prompt Security"
        description="Prompt-injection, jailbreak and system-prompt-extraction detection for text headed to an LLM."
      />
      <EmptyState title="The prompt-injection detector isn't available in this build">
        Its building blocks exist in the backend (Unicode confusable and hidden-text decoding, a pickle-free text classifier
        format, verified MITRE ATLAS mappings), but the detector isn&apos;t wired up, so nothing here can be analyzed yet.
      </EmptyState>
      {probe && probe.status !== 200 ? <ErrorState error={new ApiError(probe.status, probe.message)} /> : null}
    </>
  );
}
