import type { ReactNode } from "react";
import { ShieldAlert } from "lucide-react";

import { SeverityBadge } from "@/components/sentivra/badges";
import { classificationLabel, percent } from "@/lib/format";
import type { DetectionResult, MitreMapping, RiskAssessment } from "@/types/api";

export function MitreList({ mappings }: { mappings: MitreMapping[] }) {
  if (!mappings.length) {
    return <p className="text-xs text-muted-foreground">No ATT&CK / ATLAS mapping. The evidence doesn&apos;t identify a technique.</p>;
  }
  return (
    <ul className="flex flex-wrap gap-1.5">
      {mappings.map((m) => (
        <li key={m.technique_id} title={`${m.tactic} · ${m.source}`}
          className="rounded-md border px-2 py-0.5 text-xs">
          <span className="font-mono font-medium">{m.technique_id}</span>{" "}
          <span className="text-muted-foreground">{m.technique_name}</span>
        </li>
      ))}
    </ul>
  );
}

export function FindingCard({ finding }: { finding: DetectionResult }) {
  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-medium">{finding.detector}</span>
          <SeverityBadge severity={finding.severity} />
        </div>
        <span className="text-xs text-muted-foreground tabular">
          score {finding.score.toFixed(2)} · confidence {percent(finding.confidence)} · action {finding.recommended_action}
        </span>
      </div>
      <ul className="space-y-2.5 text-sm">
        {finding.evidence.map((e, i) => (
          <li key={i} className="min-w-0 space-y-0.5">
            <span className="block font-mono text-[11px] break-all text-muted-foreground">{e.type}</span>
            <span className="block break-words">{e.detail}</span>
            {e.excerpt ? <span className="block text-xs break-words text-muted-foreground">{e.excerpt}</span> : null}
          </li>
        ))}
      </ul>
      <MitreList mappings={finding.mitre_attack} />
      {finding.model_version ? <p className="text-xs text-muted-foreground">Detector version: {finding.model_version}</p> : null}
    </div>
  );
}

/** Brief §22: every alert answers what, why, which evidence, how confident, what to do. */
export function AlertExplanation({ assessment }: { assessment: RiskAssessment }) {
  const top = [...assessment.findings].sort((a, b) => b.score * b.confidence - a.score * a.confidence)[0];
  const action = top?.recommended_action ?? "ALLOW";
  const detectors = assessment.findings.map((f) => f.detector);
  const rows: { label: string; value: ReactNode }[] = [
    {
      label: "What happened",
      value: <>{classificationLabel(assessment.classification)} on event <span className="font-mono">{assessment.event_id.slice(0, 8)}</span></>,
    },
    {
      label: "Why",
      value: detectors.length
        ? `${detectors.length} independent detector${detectors.length > 1 ? "s" : ""} raised findings: ${detectors.join(", ")}`
        : "No detector raised a finding",
    },
    { label: "Evidence", value: top ? top.evidence.slice(0, 3).map((e) => e.detail).join(" · ") : "—" },
    {
      label: "Confidence",
      value: (
        <>
          {percent(assessment.confidence)}{" "}
          <span className="text-muted-foreground">
            (mean detector confidence; risk {assessment.risk_score}/100 is a weighted heuristic, not a probability)
          </span>
        </>
      ),
    },
    { label: "Recommended action", value: <span className="font-medium">{action}</span> },
  ];
  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="mb-3 flex items-center gap-2">
        <ShieldAlert className="size-4" aria-hidden />
        <span className="text-sm font-semibold">Explanation</span>
        <SeverityBadge severity={assessment.severity} />
        <span className="text-sm text-muted-foreground tabular">Risk {assessment.risk_score} / 100</span>
      </div>
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[10rem_1fr]">
        {rows.map(({ label, value }) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="min-w-0 break-words">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
