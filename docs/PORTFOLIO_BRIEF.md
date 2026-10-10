# ScamCheck — Portfolio Brief

A self-contained reference for writing a portfolio piece about this project. Everything below reflects what's actually in the codebase as of June 2026, not aspirational scope.

---

## One-liner

A web app where anyone can paste a suspicious link (or the whole message it arrived in) and get back a plain-language risk verdict — **Safe / Suspicious / Dangerous** — with specific reasons and a learning tip for each. Built for non-technical people to avoid phishing and scam links.

## The problem it solves

Non-technical people get caught by phishing links every day and have no fast, trustworthy way to sanity-check a URL before clicking or entering details. ScamCheck aggregates multiple professional threat-intelligence sources behind a single, calm, jargon-free interface — and teaches users what makes a link suspicious so they get better at spotting scams themselves.

## Live deployment

- Deployed on **Vercel** at `scamcheck-three.vercel.app` (single project serving both the static frontend and the Python API).
- Frontend builds to static assets; the API runs as a Python serverless function. `vercel.json` rewrites `/api/*` to the function and serves the built SPA for everything else.

---

## Tech stack

**Backend**
- **Python 3.11+ / FastAPI**, served with `uvicorn`.
- Async throughout — the external detection sources run **concurrently** (`asyncio.gather`), so the user waits for the slowest source, not the sum of all of them.
- **Pydantic v2** models define and validate the API response contract; **pydantic-settings** centralizes config.
- HTTP via **httpx** (async). Threat intel and heuristics each use purpose-built libraries:
  - `python-whois` — domain-age lookups
  - `tldextract` — registered-domain / subdomain parsing
  - `confusable_homoglyphs` + `idna` — punycode / homograph (lookalike-character) detection
  - `cryptography` — TLS certificate inspection
- **Anthropic SDK** for the AI layer (`AsyncAnthropic`).
- Dependency management via `pyproject.toml`. No database in v1 (stateless by design).

**Frontend**
- **React 18 + Vite + TypeScript**, single-page app.
- No UI framework — hand-written components and CSS for a deliberately calm, trustworthy aesthetic (risk gauge, verdict card, findings list, message box). Custom SVG icons.
- Talks only to the project's own backend — never directly to any third-party API.

**Infrastructure / ops**
- **Vercel** for hosting (static + serverless Python).
- **Upstash Redis** (over its REST API) as a durable, serverless-friendly store for abuse counters and the AI-spend interlock.
- Secrets live only in backend environment variables; `.env` is gitignored and `.env.example` is kept current.

**Testing**
- **pytest** + `pytest-asyncio`, with **respx** to mock external HTTP. ~150 test functions; external APIs are always mocked, never hit in CI. The pure-logic heuristics module is the most heavily tested (~44 tests).

---

## Detection sources (three, aggregated into one verdict)

Each source is an isolated module exposing a single `check(url)` that returns a normalized list of findings — so adding a fourth source (PhishTank, URLScan.io, etc.) is trivial.

1. **Google Web Risk** — Google's current phishing/malware blocklist API. (Notable detail: this replaced the legacy Safe Browsing v4 source mid-build when that API became unavailable; the old module is kept for reference. The migration is recorded in the decisions log.)
2. **VirusTotal** — aggregated verdicts from 70+ security engines.
3. **In-house heuristics** — no external call, pure logic. Detects: embedded credentials in the URL (`@` trick), raw-IP hosts, excessive subdomains, known URL shorteners (expanded first), suspicious/abused TLDs, abuse-heavy free host registries (e.g. `*.biz.ua`), punycode and homograph characters, lookalike/typosquatted brand names (leetspeak-aware, edit-distance matched against a brand seed list combined with phishing keywords), newly registered domains (WHOIS), and missing/invalid HTTPS certificates.

A fourth source activates when the user supplies the message text: **AI message analysis** (see below).

---

## AI layer — the most interesting design constraint

AI sits **on top of** the deterministic sources; it never replaces them. The governing rule, enforced *mechanically* rather than by trust:

> **AI can only escalate risk, never downgrade it.**

How it's enforced: the risk score is the capped sum of per-finding weights. AI findings carry non-negative weights like any other source, so adding AI findings can only *raise* the score — there is no code path by which AI lowers a score or softens a verdict. The LLM never emits a standalone "safe" judgment.

Two AI features in v1:
1. **Explanation layer** — turns raw findings into a calm, plain-language summary tailored to the verdict. Uses a fast, cheap model (Claude Haiku 4.5). Outputs are cached on a hash of (verdict, findings) so identical results don't re-bill.
2. **Message analysis** — the user can paste the whole message, and a stronger model (Claude Sonnet 4.6) flags social-engineering patterns (fake urgency, authority impersonation, payment pressure, known scam scripts). This can *add* findings and *raise* the score.

A notable product decision (in the git history and docs): message analysis was **originally a paid feature, then made free**, because gating it produced a falsely reassuring "safe" on inputs with a clean URL but a scammy message — defeating the whole mission. Cost is bounded by caps and the budget interlock instead of by a paywall.

If the AI layer is unavailable (no key, timeout, rate limit, or daily budget exhausted), the pipeline falls back to a deterministic template summary and notes `ai` in `sources_unavailable`. The summary is honest about uncertainty — a clean result says "no known threats found," never "this link is safe."

v2 AI features (interfaces stubbed, not built): destination-page content/visual analysis, and conversational follow-up ("is it bad that I already clicked?").

---

## Abuse protection & cost control (a real focus of the build)

Because the app is account-free and calls paid APIs, protecting the AI bill from scripted abuse was a first-class concern. Implemented in one tunable config module:

- **Free tier:** 5 checks/IP/day, no account, frictionless. Returns the *full* verdict + findings + AI explanation + message analysis.
- **Per-IP rate limiting** (10 req / 60s fixed window) on `POST /api/check`, with a friendly message on exceed — never a raw 429.
- **Hard global daily ceiling on AI calls** (2000/day across all users). Once hit, the app falls back to deterministic-only; verdicts and findings are unaffected, only the AI summary changes.
- **Durable store with a deliberate failure policy:** counters live in Upstash Redis (fixed-window `INCR`+`EXPIRE NX`, one pipelined round trip). Rate/daily limits **fail open** (don't punish real users during an outage); the AI budget **fails closed** (protect the bill). There's a pluggable `AbuseStore` interface with a Redis implementation for production and an in-memory one for local dev/tests.
- **AI safety interlock:** the AI layer only activates when a durable budget store is actually configured, so the spend cap can never be silently bypassed on serverless.
- **Tier gating** for paid features (unlimited checks, conversational follow-up, history) is structured so flipping a user's tier unlocks them — even though the account system is currently a stub.

---

## Architecture & engineering highlights worth calling out

- **Concurrent detection pipeline** with graceful degradation: each source runs in parallel; any source that's down, rate-limited, or unconfigured is recorded in `sources_unavailable` and never fails the whole request. The pure-logic heuristics run in a thread so they don't block the event loop.
- **Stable, documented API contract** (`POST /api/check`) returning a structured verdict, 0–100 score, AI summary, and a list of findings (source, severity, title, plain-language detail, learning tip).
- **All tunable knobs in one config file** — scoring weights, verdict thresholds, rate limits, daily caps, heuristic thresholds, model choices — so behavior can be tuned with real-world data without hunting through the codebase.
- **Privacy-conscious by design:** never logs full URLs with query strings (they may carry tokens/PII); aggregate analytics count *categories* of findings only, never URLs or message text.
- **Safe by construction:** the tool *analyzes* links, it never fetches and renders scam pages. Shortener expansion follows redirects via HEAD requests only and never executes page content.
- **Internal analytics**: aggregate-only counters (links checked, scams flagged, which heuristics fired by name) sharing the Redis store under a separate namespace, behind a token-guarded admin route and an off-by-default public stats route.
- **Decision log discipline**: `docs/DECISIONS.md` records the FastAPI choice, scoring weights, the Web Risk migration, and model selection; `docs/PRICING.md` records the tier/cost reasoning.

---

## Endpoints

- `POST /api/check` — the core endpoint: `{ url, message? }` → verdict + score + summary + findings + which sources ran.
- `POST /api/report` — "report a scam" (data shape designed, storage stubbed for v1).
- `GET /api/health` — health check.
- `GET /api/admin/analytics` — token-guarded aggregate stats (404s when no token configured).
- `GET /api/stats/public` — public counters, off by default.

---

## Suggested framing for the portfolio piece

- **Theme:** consumer-protection product with real threat-intelligence integration — not a toy. Mission-first ("help the vulnerable") with the monetization model explicitly subordinated to that mission.
- **Strongest talking points:** the escalate-only AI invariant enforced through the scoring math; concurrent multi-source aggregation with per-source graceful degradation; serverless-friendly abuse/cost controls with an intentional fail-open vs. fail-closed split; and the product judgment call to un-gate message analysis when gating it undermined the mission.
- **What it demonstrates:** async Python/FastAPI, third-party API integration, applied LLM engineering with hard safety guardrails and cost ceilings, pragmatic serverless deployment, and a tested, modular, extensible codebase.

---

## Open notes / honesty for the writeup

- No database in v1 — stateless by design; the report endpoint's storage is stubbed.
- The account/tier system is a stub: gating logic exists, but there's no real auth/billing yet.
- v2 features (page analysis, conversational follow-up) are interface stubs only.
- Single-developer project, built with Claude Code.
