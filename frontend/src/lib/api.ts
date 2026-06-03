import type { CheckRequest, CheckResponse } from "./types";

// Empty base => same-origin (uses the Vite dev proxy). In prod, set
// VITE_API_BASE_URL to the deployed backend. The frontend NEVER calls
// Google / VirusTotal directly — only our own backend.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export class ApiError extends Error {}

export async function checkUrl(payload: CheckRequest): Promise<CheckResponse> {
  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}/api/check`, {
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
    // The backend sends a clear, friendly `detail` for rate limits (429) and
    // bad input (400). Prefer it; fall back to a generic message.
    const detail = await readDetail(resp);
    if (detail) throw new ApiError(detail);
    throw new ApiError("Something went wrong checking that link. Please try again.");
  }

  return (await resp.json()) as CheckResponse;
}

async function readDetail(resp: Response): Promise<string | null> {
  try {
    const body = await resp.json();
    return typeof body?.detail === "string" ? body.detail : null;
  } catch {
    return null;
  }
}
