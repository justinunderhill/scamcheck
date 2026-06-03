import type { Verdict } from "./types";

// Honest, plain-language verdict labels. Note: "safe" never claims certainty.
export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: "No known threats found",
  suspicious: "Be careful with this link",
  dangerous: "This link looks dangerous",
};

// Friendly names for the source identifiers in sources_checked / _unavailable.
const SOURCE_NAMES: Record<string, string> = {
  google_safe_browsing: "Google Safe Browsing",
  web_risk: "Google Web Risk",
  virustotal: "VirusTotal",
  heuristics: "our own checks",
  ai_message_analysis: "message analysis",
  ai: "the plain-language explainer",
};

export function sourceName(id: string): string {
  return SOURCE_NAMES[id] ?? id;
}
