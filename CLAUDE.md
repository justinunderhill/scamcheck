# CLAUDE.md

This file gives Claude Code the context it needs to work on this project. Read it fully before making changes.

## Project: ScamCheck

A web app that lets anyone paste a suspicious URL and get back a clear risk verdict (Safe / Suspicious / Dangerous) with plain-language reasons. The mission is consumer protection: help non-technical people avoid phishing and scam links, and teach them what to look for.

## What we're building (v1 scope)

- A single-page web app with one prominent input: "Paste a link to check."
- A backend API that receives the URL, runs it through multiple detection sources, aggregates the results into one verdict, and returns structured findings.
- Each result includes a verdict, a confidence/score, and a list of human-readable reasons ("This domain was registered 4 days ago," "Listed in PhishTank," etc.).
- An educational tip attached to each finding so users learn to spot scams themselves.

Out of scope for v1: mobile apps, browser extensions, the v2 AI features. Keep the codebase ready to grow into these but don't build them yet. **In scope for v1:** a thin free tier (account-free, rate-limited), the paid-tier feature gating, and abuse protection — see "Tiers & abuse protection" below and `docs/PRICING.md`.

## Detection sources (all three for v1)

1. **Google Safe Browsing API** — check the URL against Google's phishing/malware lists.
2. **VirusTotal API** — submit the URL and read the aggregated engine verdicts.
3. **Own heuristics** — implemented in-house, no external call:
   - Domain age via WHOIS (newly registered = higher risk)
   - Typosquatting / lookalike detection against a list of commonly impersonated brands
   - Raw IP address used instead of a domain
   - Excessive subdomains
   - Known URL-shortener domains (expand before checking)
   - Suspicious / frequently-abused TLDs
   - Missing or invalid HTTPS certificate
   - Punycode / homograph characters in the domain

## Architecture decision (FINALIZED)

Backend is **Python 3.11+ with FastAPI**. Rationale recorded in `docs/DECISIONS.md`: best-in-class async (so the detection sources run concurrently), first-class libraries for every task here (`httpx`, `python-whois`, `cryptography` for cert checks, `tldextract`, `idna`/`confusable_homoglyphs` for punycode), Pydantic for the response contract, and the official `anthropic` SDK for the AI layer. One language across all detection + AI services keeps the module-per-source pattern clean.

Hard requirements:
- **API keys live only on the backend**, loaded from environment variables. Never ship keys to the frontend or commit them. Use `.env` (gitignored) and keep `.env.example` current.
- The frontend talks only to our own backend, never directly to Google/VirusTotal.
- Calls to the two external APIs should run concurrently, not one after another, so the user waits as little as possible.
- Fail gracefully: if one source is down or rate-limited, return the results from the others and note which source was unavailable rather than erroring the whole request.

## Stack

- Frontend: React + Vite (TypeScript)
- Backend: **Python 3.11+ / FastAPI**, served with `uvicorn`. Dependency management with a `pyproject.toml`.
- AI: Anthropic API via the official `anthropic` Python SDK. Model choice documented in `docs/DECISIONS.md` (use a fast, cheap model for the explanation layer; reserve a stronger model for page/message analysis).
- No database in v1 (stateless). Design the "report a scam" feature's data shape but stub its storage.

## AI layer

AI sits **on top of** the deterministic sources — it never replaces them. See `backend/app/services/AI_SPEC.md` for the full spec. The single most important rule:

> **AI can only escalate risk, never downgrade it.** If the blocklists or heuristics return `dangerous`, no AI output may soften that verdict. The LLM never produces a standalone "safe" judgment. Absence of a flag is not a clear signal — the deterministic sources own the verdict; AI explains it and fills the "nothing flagged it yet but it looks wrong" gap.

v1 AI features:
1. **Explanation layer** — turn raw findings into a calm, plain-language summary tailored to the verdict and audience. Replaces hardcoded tip strings.
2. **Message analysis** — user can paste the whole message (not just the URL); the LLM flags social-engineering patterns (fake urgency, authority impersonation, payment pressure, known scam scripts). This can *add* findings and *raise* the score.

v2 AI features (stub the interfaces now):
3. **Page content/visual analysis** — safely capture destination page text/screenshot and detect brand impersonation and pressure tactics on sites too new for any blocklist.
4. **Conversational follow-up** — let the user ask "what do I do now?" / "is it bad that I already clicked?" grounded in the verdict.

## API contract (keep this stable)

`POST /api/check`
Request: `{ "url": "https://example.com/login", "message": "optional full message the link arrived in" }`
Response:
```json
{
  "input_url": "https://example.com/login",
  "final_url": "https://example.com/login",
  "verdict": "suspicious",
  "score": 62,
  "summary": "AI-written plain-language overview of why this got its verdict.",
  "findings": [
    {
      "source": "heuristics",
      "severity": "medium",
      "title": "Recently registered domain",
      "detail": "This domain was registered 4 days ago. Scam sites are often brand new.",
      "tip": "Legitimate companies usually own their domains for years. Be cautious with very new sites."
    }
  ],
  "sources_checked": ["google_safe_browsing", "virustotal", "heuristics", "ai_message_analysis"],
  "sources_unavailable": []
}
```
`verdict` is one of `safe` | `suspicious` | `dangerous`. `score` is 0–100 (higher = riskier). `summary` is AI-generated; if the AI layer is unavailable, fall back to a deterministic template summary and note `ai` in `sources_unavailable`.

## Scoring guidance

Aggregate the sources into one score. A hit on Google Safe Browsing or VirusTotal (multiple engines flagging) should push hard toward `dangerous`. Heuristics are weaker signals individually but compound. Document the exact weighting you choose in `docs/DECISIONS.md` so it can be tuned later.

## Conventions

- Keep services isolated: one module per detection source under the backend's services folder, each exposing a single `check(url)` that returns a normalized list of findings. This makes adding a fourth source (e.g. PhishTank, URLScan.io) trivial.
- Validate and normalize the input URL before doing anything (scheme, expand shorteners). Reject obviously malformed input with a clear message.
- Write tests for the heuristics module — it's pure logic and the easiest to get wrong. Mock the external APIs in tests; never hit them in CI.
- Plain-language everything the user sees. The audience is non-technical. No jargon in `title`, `detail`, or `tip`.

## Tiers & abuse protection

Full reasoning in `docs/PRICING.md`. The model is mission-first: a thin free tier reaches the vulnerable; paid + business tiers subsidize it.

Build requirements for v1:
- **Free tier:** a few checks per day (start at 5/day, make it a config constant), **no account required**, frictionless. Returns the full verdict + findings + AI explanation.
- **Per-IP rate limiting** on `POST /api/check`. Return a clear, friendly message when exceeded (not a raw 429).
- **Hard daily cap on total AI calls.** Once exceeded, fall back to deterministic-only: still return a verdict and findings, set a template `summary`, add `ai` to `sources_unavailable`. The AI bill must never be exposed to scripted abuse.
- **Paid-tier features (gate them now, even if the account system is a stub):** unlimited checks, message analysis, conversational follow-up, check history. Structure the code so flipping a user's tier unlocks these — don't hardcode them on.
- The message-analysis feature (`message` field on the request) is a paid feature; on the free tier, ignore the field or prompt to upgrade. Keep the API contract stable either way.

Make all limits config constants in one place so they're trivially tunable with real-world data.

## Ethics / safety guardrails

- This tool **analyzes** links; it must never **fetch and render** scam pages in a way that could harm the user or proxy malicious content to them. When expanding shorteners or checking certs, follow redirects safely (HEAD requests, don't execute page content).
- Never log full URLs with their query strings to persistent storage — they may contain tokens or personal data. Log domains only if you must.
- Make verdicts honest about uncertainty. A "safe" result should say "no known threats found," not "this link is safe," since absence of evidence isn't a guarantee.

## Getting started (fill in once stack is chosen)

See `docs/SETUP.md` for environment setup and how to obtain the two API keys.
