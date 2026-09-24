// Thin, typed client for the SENTIVRA FastAPI backend.
// The browser talks to the backend directly; its CORS allowlist admits the
// dashboard's origin (SENTIVRA_CORS_ORIGINS in the backend .env).

import type {
  AlertStatus,
  BatchAnalysisResponse,
  FileAnalysisResponse,
  NetworkAnalysisResponse,
} from "@/types/api";

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch {
    // fetch() rejects the same way for "server down" and "blocked by CORS",
    // so name both causes and how to fix each.
    const origin = typeof window === "undefined" ? "this dashboard" : window.location.origin;
    throw new ApiError(
      0,
      `Can't reach the SENTIVRA backend at ${API_BASE}. Check that it's running, and that ${origin} is listed in ` +
        "SENTIVRA_CORS_ORIGINS on the backend.",
    );
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      // non-JSON error body: keep the status text
    }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

/** SWR fetcher: the key is the API path. */
export const fetcher = <T,>(path: string) => request<T>(path);

function upload<T>(path: string, file: File | Blob, filename?: string): Promise<T> {
  const form = new FormData();
  form.append("file", file, filename ?? (file instanceof File ? file.name : "upload"));
  return request<T>(path, { method: "POST", body: form });
}

export const api = {
  setAlertStatus: (alertId: string, status: AlertStatus, note?: string) =>
    request<{ alert_id: string; status: AlertStatus; previous_status: AlertStatus }>(
      `/api/v1/alerts/${encodeURIComponent(alertId)}`,
      { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, note }) },
    ),
  analyzeFile: (file: File | Blob, filename?: string) =>
    upload<FileAnalysisResponse>("/api/v1/analyze/file", file, filename),
  analyzeNetwork: (file: File) => upload<NetworkAnalysisResponse>("/api/v1/network/analyze", file),
  networkDemo: () => request<NetworkAnalysisResponse>("/api/v1/network/demo", { method: "POST" }),
  analyzeOsquery: (file: File) => upload<BatchAnalysisResponse>("/api/v1/endpoint/osquery", file),
  endpointDemo: () => request<BatchAnalysisResponse>("/api/v1/endpoint/demo", { method: "POST" }),
  analyzeLogs: (file: File) => upload<BatchAnalysisResponse>("/api/v1/logs/analyze", file),
  /** Endpoints the API contract defines but whose detectors haven't landed; they answer 501. */
  probe: (path: string) => request<unknown>(path, { method: "POST" }),
};
