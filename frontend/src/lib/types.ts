export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type FindingStatus =
  | "open"
  | "confirmed"
  | "in_progress"
  | "fixed"
  | "false_positive"
  | "accepted_risk";

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  confirmed: "Confirmed",
  in_progress: "In Progress",
  fixed: "Fixed",
  false_positive: "False Positive",
  accepted_risk: "Accepted Risk",
};

export interface User {
  id: string;
  email: string;
  name: string;
  role: "admin" | "member";
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  owner_id: string;
  role: "owner" | "editor" | "viewer";
  created_at: string;
  open_findings: Record<Severity, number>;
  repository_count: number;
  last_scan_at: string | null;
}

export interface Repository {
  id: string;
  project_id: string;
  provider: string;
  name: string;
  url: string;
  default_branch: string;
  created_at: string;
  latest_snapshot_id: string | null;
}

export interface ScannerInfo {
  name: string;
  display_name: string;
  version: string;
  description: string;
  supported_inputs: string[];
  available: boolean;
  status_note: string;
}

export interface ScannerProgress {
  state: "pending" | "running" | "completed" | "failed" | "skipped" | "unavailable";
  percent: number;
  message?: string;
  findings?: number;
}

export interface Scan {
  id: string;
  project_id: string;
  repository_id: string | null;
  snapshot_id: string | null;
  kind: string;
  scanners: string[];
  status: "queued" | "running" | "completed" | "partial" | "failed" | "cancelled";
  progress: Record<string, ScannerProgress>;
  summary: { severity?: Record<Severity, number>; scanners?: Record<string, unknown> };
  trigger: string;
  ref: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: string;
  project_id: string;
  repository_id: string | null;
  asset_id: string | null;
  asset: string | null;
  scanner: string;
  detection_source: string;
  rule_id: string;
  title: string;
  category: string;
  cwe: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  exploitability: string;
  exposure: string;
  risk_score: number;
  file_path: string;
  line: number;
  language: string;
  status: FindingStatus;
  verification: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
}

export interface FindingEvent {
  id: string;
  kind: string;
  message: string;
  data: Record<string, unknown>;
  actor_id: string | null;
  created_at: string;
}

export interface FindingDetail extends Finding {
  description: string;
  impact: string;
  remediation: string;
  references: string[];
  end_line: number;
  code_context: string;
  extra: Record<string, unknown>;
  events: FindingEvent[];
}

export interface FindingPage {
  items: Finding[];
  total: number;
}

export interface Explanation {
  finding_id: string;
  audience: string;
  detected: { label: string; value: string }[];
  source: "rule" | "ai";
  model: string | null;
  provider?: string | null;
  notice: string | null;
  what_happened: string;
  why_it_matters: string;
  inferred: string[];
  recommended: string[];
  cached?: boolean;
}

export interface VerificationResult {
  state?: "verified_fixed" | "still_detected" | "unable_to_verify";
  summary?: string;
  checks?: { name: string; passed: boolean }[];
  introduced?: { rule_id: string; title: string; severity: string; line: number }[];
  preflight?: { performed: boolean; rule_still_triggers?: boolean; note: string };
}

export interface Patch {
  id: string;
  finding_id: string;
  status: "proposed" | "applied" | "rejected";
  generator: "rule" | "ai";
  explanation: string;
  diff: string;
  file_path: string;
  caveats: string[];
  verification: VerificationResult;
  applied_snapshot_id: string | null;
  created_at: string;
  applied_at: string | null;
}

export interface Policy {
  max_critical: number | null;
  max_high: number | null;
  max_new_high: number | null;
  max_new_medium: number | null;
  fail_on_secrets: boolean;
  fail_on_severity: Severity | null;
  min_confidence: "low" | "medium" | "high";
  ignore_statuses: string[];
  ignore_scanners: string[];
}

export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  last_used: string | null;
  expires_at: string | null;
  revoked: boolean;
}

export interface ModuleStatus {
  scanner: string;
  name: string;
  status: "ok" | "attention" | "not_scanned" | "unavailable";
  open_findings: number;
  last_scan_at: string | null;
  available: boolean;
}

export interface Dashboard {
  severity: Record<Severity, number>;
  totals: {
    active: number;
    fixed: number;
    triaged: number;
    total: number;
    remediation_progress: number | null;
  };
  modules: ModuleStatus[];
  trend: { date: string; opened: number; resolved: number; active: number }[];
  recently_fixed: {
    id: string;
    title: string;
    severity: Severity;
    file_path: string;
    resolved_at: string;
  }[];
  recent_scans: {
    id: string;
    project_id: string;
    status: string;
    scanners: string[];
    created_at: string;
    finished_at: string | null;
    severity: Record<Severity, number> | null;
  }[];
  affected_repositories: { id: string; name: string; counts: Record<Severity, number> }[];
  affected_hosts: { id: string; name: string; ip: string; counts: Record<Severity, number> }[];
}
