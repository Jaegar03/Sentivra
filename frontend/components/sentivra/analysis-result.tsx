"use client";

import Link from "next/link";
import { useRef, useState, type ReactNode } from "react";
import { Play, Upload } from "lucide-react";

import { SeverityBadge, SourceTypeBadge } from "@/components/sentivra/badges";
import { AlertExplanation, FindingCard } from "@/components/sentivra/findings";
import { ErrorState } from "@/components/sentivra/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { AnalysisResponse } from "@/types/api";

/** Run a demo scenario or upload a file, and keep the last result on screen. */
export function useAnalysis<T extends AnalysisResponse>() {
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function run(label: string, fn: () => Promise<T>) {
    setBusy(label);
    setError(null);
    try {
      setResult(await fn());
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  }
  return { result, error, busy, run };
}

export function RunButton({ label, busy, onClick }: { label: string; busy: string | null; onClick: () => void }) {
  return (
    <Button onClick={onClick} disabled={busy !== null}>
      <Play data-icon="inline-start" />
      {busy === label ? "Running…" : label}
    </Button>
  );
}

export function UploadButton({ label, accept, busy, onFile }: {
  label: string;
  accept?: string;
  busy: string | null;
  onFile: (file: File) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      <input
        ref={input}
        type="file"
        accept={accept}
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />
      <Button variant="outline" disabled={busy !== null} onClick={() => input.current?.click()}>
        <Upload data-icon="inline-start" />
        {busy === label ? "Analyzing…" : label}
      </Button>
    </>
  );
}

export function AnalysisSummary({ result, extra }: { result: AnalysisResponse; extra?: ReactNode }) {
  const assessment = result.risk_assessment;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-xl border bg-card px-4 py-3">
        <span className="text-sm text-muted-foreground">Verdict</span>
        <SeverityBadge severity={assessment.severity} />
        <span className="text-sm tabular">Risk {assessment.risk_score} / 100</span>
        <SourceTypeBadge sourceType={result.source_type} />
        {assessment.severity !== "SAFE" ? (
          <Link href={`/threats/${assessment.assessment_id}`} className="ml-auto text-sm underline underline-offset-4">
            Open alert
          </Link>
        ) : (
          <span className="ml-auto text-sm text-muted-foreground">No alert raised</span>
        )}
      </div>
      {extra}
      {assessment.severity !== "SAFE" ? <AlertExplanation assessment={assessment} /> : null}
      {result.findings.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>Per-detector verdicts and evidence</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {result.findings.map((f, i) => <FindingCard key={`${f.detector}-${i}`} finding={f} />)}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export function AnalysisError({ error }: { error: unknown }) {
  return error ? <ErrorState error={error} /> : null;
}
