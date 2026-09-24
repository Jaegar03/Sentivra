"use client";

import Link from "next/link";
import { useState } from "react";
import { Play } from "lucide-react";

import { SeverityBadge, SourceTypeBadge, StatusPill } from "@/components/sentivra/badges";
import { ErrorState, PageHeader } from "@/components/sentivra/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { AnalysisResponse } from "@/types/api";

// Standard harmless antivirus test string (not malware).
const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const SCENARIOS: { key: string; title: string; what: string; run: () => Promise<AnalysisResponse>; page: string }[] = [
  {
    key: "file",
    title: "File threat: EICAR test file",
    what: "YARA recognizes the standard EICAR test string. ClamAV joins in if it's installed.",
    run: () => api.analyzeFile(new Blob([EICAR], { type: "text/plain" }), "eicar-test.txt"),
    page: "/files",
  },
  {
    key: "network",
    title: "Network anomaly: synthetic traffic sample",
    what: "Two hours of synthetic flows with scan, brute-force, flood, bulk outbound, DNS tunneling and beaconing episodes (demo data).",
    run: api.networkDemo,
    page: "/network",
  },
  {
    key: "endpoint",
    title: "Endpoint: simulated fleet",
    what: "osquery-format telemetry from ten simulated hosts, with nine behavioral scenarios (simulated).",
    run: api.endpointDemo,
    page: "/endpoint",
  },
];

const UNAVAILABLE = ["Prompt injection", "SQL injection", "Phishing URL"];

export default function DemoPage() {
  const [results, setResults] = useState<Record<string, AnalysisResponse | Error>>({});
  const [running, setRunning] = useState<string | null>(null);

  async function runOne(s: (typeof SCENARIOS)[number]) {
    setRunning(s.key);
    try {
      const r = await s.run();
      setResults((prev) => ({ ...prev, [s.key]: r }));
    } catch (e) {
      setResults((prev) => ({ ...prev, [s.key]: e instanceof Error ? e : new Error(String(e)) }));
    } finally {
      setRunning(null);
    }
  }

  async function runAll() {
    for (const s of SCENARIOS) await runOne(s);
  }

  return (
    <>
      <PageHeader
        title="Demo mode"
        description="Controlled scenarios that exercise the real detection pipeline. Nothing here is real malware or real traffic, and every result is labeled Demo data or Simulated wherever it appears."
        actions={<Button onClick={runAll} disabled={running !== null}><Play data-icon="inline-start" />Run all scenarios</Button>}
      />
      <div className="grid gap-4 lg:grid-cols-3">
        {SCENARIOS.map((s) => {
          const r = results[s.key];
          return (
            <Card key={s.key}>
              <CardHeader>
                <CardTitle>{s.title}</CardTitle>
                <CardDescription>{s.what}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button variant="outline" onClick={() => runOne(s)} disabled={running !== null}>
                  {running === s.key ? "Running…" : "Run"}
                </Button>
                {r instanceof Error ? <ErrorState error={r} /> : null}
                {r && !(r instanceof Error) ? (
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <SeverityBadge severity={r.risk_assessment.severity} />
                    <span className="tabular">Risk {r.risk_assessment.risk_score}</span>
                    <SourceTypeBadge sourceType={r.source_type} />
                    <span className="text-muted-foreground">{r.findings.length} detector finding(s)</span>
                    <Link href={r.risk_assessment.severity === "SAFE" ? s.page : `/threats/${r.risk_assessment.assessment_id}`}
                      className="underline underline-offset-4">
                      {r.risk_assessment.severity === "SAFE" ? "Details" : "Open alert"}
                    </Link>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          );
        })}
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Not available in this build</CardTitle>
          <CardDescription>These demonstrations need detectors that haven&apos;t been wired up yet.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-4">
          {UNAVAILABLE.map((name) => (
            <span key={name} className="flex items-center gap-2 text-sm">{name} <StatusPill status="Not implemented" /></span>
          ))}
        </CardContent>
      </Card>
    </>
  );
}
