// Mirrors the backend API contract (see CLAUDE.md / backend schemas).
// Keep these in sync with backend/app/models/schemas.py.

export type Verdict = "safe" | "suspicious" | "dangerous";
export type Severity = "low" | "medium" | "high";

export interface Finding {
  source: string;
  severity: Severity;
  title: string;
  detail: string;
  tip: string;
}

export interface CheckResponse {
  input_url: string;
  final_url: string;
  verdict: Verdict;
  score: number;
  summary: string;
  findings: Finding[];
  sources_checked: string[];
  sources_unavailable: string[];
}

export interface CheckRequest {
  url: string;
  message?: string;
}
