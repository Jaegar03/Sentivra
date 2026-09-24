"use client";

import { AnalysisError, AnalysisSummary, RunButton, UploadButton, useAnalysis } from "@/components/sentivra/analysis-result";
import { EmptyState, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { integer } from "@/lib/format";
import type { FileAnalysisResponse } from "@/types/api";

// The EICAR test string: the industry-standard, harmless file every antivirus
// engine recognizes as a test. It isn't malware and can't run.
const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

function FileFacts({ result }: { result: FileAnalysisResponse }) {
  const f = result.file_metadata;
  const rows: { label: string; value: string }[] = [
    { label: "File name", value: f.filename },
    { label: "SHA-256", value: f.sha256 },
    { label: "Size", value: `${integer(f.size_bytes)} bytes` },
    { label: "Entropy", value: `${f.entropy.toFixed(2)} / 8 bits per byte` },
    { label: "Detected type (magic bytes)", value: f.matched_magic_types.join(", ") || "unknown" },
    { label: "Extension matches content", value: f.extension_mismatch ? "No: the extension disagrees with the bytes" : "Yes" },
    { label: "Polyglot structure", value: f.is_polyglot ? "Yes: valid as more than one format" : "No" },
  ];
  return (
    <Card>
      <CardHeader><CardTitle>File facts</CardTitle></CardHeader>
      <CardContent>
        <dl className="grid gap-y-1.5 text-sm sm:grid-cols-[14rem_1fr]">
          {rows.map((r) => (
            <div key={r.label} className="contents">
              <dt className="text-muted-foreground">{r.label}</dt>
              <dd className="min-w-0 font-mono text-xs break-all sm:font-sans sm:text-sm">{r.value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

export default function FilesPage() {
  const { result, error, busy, run } = useAnalysis<FileAnalysisResponse>();
  return (
    <>
      <PageHeader
        title="Files"
        description="Magic bytes, hash and entropy first, then YARA, ClamAV (when installed) and structural heuristics. Files are parsed, never executed, and only the hash, metadata and verdict are kept."
        actions={
          <>
            <RunButton label="Scan EICAR test file" busy={busy}
              onClick={() => run("Scan EICAR test file", () => api.analyzeFile(new Blob([EICAR], { type: "text/plain" }), "eicar-test.txt"))} />
            <UploadButton label="Upload a file" busy={busy} onFile={(f) => run("Upload a file", () => api.analyzeFile(f))} />
          </>
        }
      />
      <p className="text-xs text-muted-foreground">
        The EICAR string is the standard harmless antivirus test file, not malware. The static ML tier for executables isn&apos;t
        trained in this build, so no ML score appears here.
      </p>
      <AnalysisError error={error} />
      {result ? (
        <AnalysisSummary result={result} extra={<FileFacts result={result} />} />
      ) : (
        <EmptyState title="No file analyzed yet">Scan the EICAR test file or upload your own (limit 50 MB).</EmptyState>
      )}
    </>
  );
}
