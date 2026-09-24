export function compact(n: number): string {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function integer(n: number): string {
  return new Intl.NumberFormat("en").format(n);
}

export function percent(fraction: number, digits = 0): string {
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function dateTime(iso: string): string {
  const d = new Date(iso.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : `${iso}Z`);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function relative(iso: string): string {
  const d = new Date(iso.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : `${iso}Z`);
  const seconds = Math.round((Date.now() - d.getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (Math.abs(seconds) < 60) return rtf.format(-seconds, "second");
  if (Math.abs(seconds) < 3600) return rtf.format(-Math.round(seconds / 60), "minute");
  if (Math.abs(seconds) < 86400) return rtf.format(-Math.round(seconds / 3600), "hour");
  return rtf.format(-Math.round(seconds / 86400), "day");
}

/** "network_anomaly" / "NETWORK_ANOMALY" -> "Network anomaly" */
export function humanize(value: string): string {
  const text = value.replace(/[_-]+/g, " ").toLowerCase().trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

// Alert classification = the category of the alert's strongest finding.
// Phrase each as what an analyst would call it.
const CLASSIFICATIONS: Record<string, string> = {
  MALWARE: "Malware indicator",
  NETWORK_ANOMALY: "Network anomaly",
  SIGMA_RULE: "Sigma rule match",
  LOG_ANOMALY: "Suspicious authentication activity",
  BEHAVIORAL_ANOMALY: "Endpoint behavior anomaly",
  PHISHING: "Phishing",
  MALICIOUS_URL: "Malicious URL",
  PROMPT_INJECTION: "Prompt injection",
  SQL_INJECTION: "SQL injection",
  NO_FINDINGS: "No findings",
};

export function classificationLabel(value: string): string {
  return CLASSIFICATIONS[value.toUpperCase()] ?? humanize(value);
}

/** "BehavioralAnomalyDetector" -> "Behavioral anomaly", "YaraDetector" -> "YARA". */
export function detectorLabel(name: string): string {
  const base = name.replace(/Detector$/, "");
  if (base === "Yara") return "YARA";
  if (base === "ClamAV") return "ClamAV";
  return humanize(base.replace(/([a-z])([A-Z])/g, "$1 $2"));
}

const METRIC_LABELS: Record<string, string> = {
  pr_auc: "PR-AUC",
  roc_auc: "ROC-AUC",
  f1: "F1",
  false_positive_rate: "False-positive rate",
  false_negative_rate: "False-negative rate",
};

export function metricLabel(key: string): string {
  return METRIC_LABELS[key] ?? humanize(key);
}

/** Up to 4 significant digits, without float noise like 0.00022627515762594597. */
export function significant(n: number): string {
  return Number.isInteger(n) ? String(n) : Number(n.toPrecision(4)).toString();
}
