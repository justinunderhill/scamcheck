import type { CheckRequest, CheckResponse, ScreenshotRequest, ScreenshotResponse } from "./types";

// Empty base => same-origin (uses the Vite dev proxy). In prod, set
// VITE_API_BASE_URL to the deployed backend. The frontend NEVER calls
// Google / VirusTotal directly — only our own backend.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export class ApiError extends Error {}

export function checkUrl(payload: CheckRequest): Promise<CheckResponse> {
  return post<CheckResponse>("/api/check", payload, "Something went wrong checking that. Please try again.");
}

export function readScreenshot(payload: ScreenshotRequest): Promise<ScreenshotResponse> {
  return post<ScreenshotResponse>(
    "/api/extract",
    payload,
    "Something went wrong reading that screenshot. Please try again, or paste the text instead.",
  );
}

async function post<T>(path: string, payload: unknown, fallback: string): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new ApiError(
      "We couldn't reach ScamCheck. Please check your connection and try again.",
    );
  }

  if (!resp.ok) {
    // The backend sends a clear, friendly `detail` for rate limits (429), bad
    // input (400/422) and unavailability (503). Prefer it; else a generic message.
    const detail = await readDetail(resp);
    throw new ApiError(detail ?? fallback);
  }

  return (await resp.json()) as T;
}

async function readDetail(resp: Response): Promise<string | null> {
  try {
    const body = await resp.json();
    return typeof body?.detail === "string" ? body.detail : null;
  } catch {
    return null;
  }
}
