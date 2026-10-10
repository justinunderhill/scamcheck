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
  // Both null for a message-only check (no link was given).
  input_url: string | null;
  final_url: string | null;
  verdict: Verdict;
  score: number;
  summary: string;
  findings: Finding[];
  sources_checked: string[];
  sources_unavailable: string[];
}

// At least one of url / message is required.
export interface CheckRequest {
  url?: string;
  message?: string;
}

// POST /api/extract: a screenshot to read. Never stored or logged.
export interface ScreenshotRequest {
  image: string; // base64, no data: prefix
  media_type: string;
}

export interface ScreenshotResponse {
  url: string | null;
  message: string | null;
}
