# Architecture Decisions

A running log of significant choices. Claude Code: append a dated entry whenever you make a structural decision. Start by recording the backend stack choice.

## Decisions made

### 2026-06-03 — Backend stack: Python 3.11+ / FastAPI
**Decision:** FastAPI on Python, served by uvicorn, deps in pyproject.toml.
**Why:** Native async lets the detection sources run concurrently (the main latency win). Mature libraries for every task: httpx (async HTTP), python-whois (domain age), cryptography (cert checks), tldextract (domain parsing), confusable_homoglyphs/idna (punycode), Pydantic (the response contract), and the official anthropic SDK for the AI layer. One language across detection + AI keeps the module-per-source pattern uniform. Alternative considered: Node/Express — fine, but Python's security/parsing ecosystem and the cleaner AI SDK story won.
**Consequences:** Frontend (TS) and backend (Python) are different languages — acceptable, the API contract is the boundary. Need a Python toolchain in CI.

### 2026-06-03 — AI is an escalate-only reasoning layer
**Decision:** AI explains findings and analyzes pasted messages; it sits on top of deterministic detection and can only raise risk, never lower it. App stays fully functional with AI disabled.
**Why:** An LLM false-"safe" on a real scam is the worst failure mode for this tool. Blocklists/heuristics are trustworthy and own the verdict; AI's job is human-friendly translation and catching social-engineering in message text that URL-checks can't see.
**Consequences:** Verdict logic never depends on the AI being up. Slightly more orchestration (AI runs after deterministic sources). Strong prompt-injection discipline required since URLs/messages are untrusted.

### 2026-06-03 — Dev toolchain & config home
**Decision:** Backend deps + scripts in `backend/pyproject.toml` (optional `[dev]` extra for pytest/respx); `uv` supported for managing Python and the venv. All tunable knobs (tier limits, rate limits, AI daily cap, score thresholds, AI model names) live in one place: `backend/app/config.py`. Frontend is Vite + React + TS with a dev proxy from `/api` to `localhost:8000`, so the browser only ever talks to our backend.
**Why:** CLAUDE.md requires limits to be trivially tunable from one place and keys to stay backend-only. A single `config.py` and a same-origin proxy satisfy both. `uv` works without a system Python install.
**Consequences:** Tuning is a one-file edit. Tests run offline (external APIs mocked). The contract (`app/models/schemas.py`) is the frozen boundary between the two languages.

### 2026-06-03 — URL normalization + safe shortener expansion
**Decision:** Input is normalized in `app/core/urls.py` (not a detection source): trim, reject empty/whitespace, default missing scheme to `https`, allow only `http`/`https` (reject `javascript:`/`file:`/`ftp:`), lowercase host, parse eTLD+1 with tldextract using the **bundled** public-suffix snapshot (no network), and flag raw-IP hosts. Shortener seed list lives in `backend/app/seedlists.py` (inlined as a frozenset — bundles reliably into serverless functions). Expansion follows redirects with **HEAD only** (falls back to a non-body-reading streamed GET if HEAD is refused), capped at `SHORTENER_MAX_REDIRECTS` with a timeout; on any failure it degrades to the original URL and never raises.
**Why:** CLAUDE.md requires validating/normalizing before anything else, expanding shorteners, and never fetching/rendering scam pages. HEAD-follow reads only the redirect chain's final URL — no page content reaches us or the user. Offline suffix list keeps CI hermetic.
**Consequences:** Adding/removing a shortener is a one-line edit in `seedlists.py`. The public-suffix snapshot is refreshed by bumping the tldextract dependency. Initial seed list: bit.ly, bitly.com, buff.ly, cutt.ly, goo.gl, is.gd, lnkd.in, ow.ly, rb.gy, rebrand.ly, shorturl.at, t.co, t.ly, tiny.cc, tinyurl.com, trib.al, v.gd.

### 2026-06-03 — Heuristics: lists, thresholds, and false-positive discipline
**Decision:** Seed lists inlined in `app/seedlists.py` (`BRANDS`, `SUSPICIOUS_TLDS`) — Python frozensets rather than loose data files, so they bundle reliably into serverless functions. Thresholds in `config.py`: domain age < 7 days = high / < 30 = medium; > 3 non-`www` subdomain labels = excessive; lookalike edit-distance ≤ 1. Lookalike detection is deliberately conservative — it fires on (1) a brand in a subdomain whose registered domain is unrelated, (2) leet/number substitution that normalizes exactly to a brand (paypa1→paypal), (3) edit-distance-1 typo-squats for brands ≥ 5 chars, or (4) a brand bundled with a phishing keyword via hyphens (paypal-secure). A bare brand word with no other signal is NOT flagged, to avoid hitting legitimate domains. Punycode (`xn--`) and confusable/mixed-script hosts are flagged high. WHOIS age and TLS cert are the only network checks; their data is injected so all checks are unit-tested offline.
**Why:** HEURISTICS_SPEC.md warns explicitly against false positives on legit domains containing a brand word. Requiring a second signal (keyword, near-miss, or wrong registered domain) keeps precision high. Network data injection keeps CI hermetic.
**Consequences:** Lists extend with one-line edits. Some impersonations using only a bare brand word slip through (accepted trade-off for precision) — the external sources and AI layer can still catch those. Initial brand seed: amazon, apple, paypal, microsoft, google, netflix, the major banks/card networks, couriers (usps/fedex/ups/dhl/royalmail), tax authorities (irs/hmrc), and crypto (coinbase/binance/metamask), among others.

### 2026-06-03 — Scoring weights, thresholds, and aggregation
**Decision:** Score = capped sum of per-finding weights, keyed by `(source, severity)` in `config.SCORE_WEIGHTS`. Verdict thresholds: `score >= 70` → dangerous, `>= 30` → suspicious, else safe. Weights: Google Safe Browsing high 90 / medium 60; VirusTotal high (≥2 engines) 80 / medium 45; AI message analysis high 50 / medium 30 / low 15; heuristics high 35 / medium 20 / low 8. Score is capped at 100. Summary is a deterministic honest template when AI is unavailable.
**Why:** CLAUDE.md says a blocklist hit should push hard toward dangerous, while heuristics are weaker but compound. A single GSB or VirusTotal hit reaches dangerous alone (90/80 ≥ 70); a single heuristic high is suspicious (35); ~2–3 heuristics compound into dangerous. Because all weights are non-negative and AI findings are scored like any other source, **adding AI findings can only raise the score** — the escalate-only rule is enforced by construction, not by trusting the model. The summary never says "this is safe", only "no known threats found".
**Consequences:** All numbers live in `config.py` for tuning with real data. The pipeline (`services/pipeline.py`) runs heuristics in a thread and the two HTTP sources concurrently, then aggregates. A test-isolation fix was required so Settings ignore the repo `.env` during tests (keys would otherwise leak and cause real network calls).

### 2026-06-03 — Tiers & abuse protection (in-memory, header-stubbed accounts)
**Decision:** Three layers in `services/limits.py` (process-wide `AbuseGuard`): per-IP sliding-window rate limit (10/60s), per-IP daily free-tier cap (5/day), and a global daily AI-call budget (2000). Tiers in `core/tiers.py`: `resolve_tier` reads the `X-ScamCheck-Tier` header (stub for real auth; unknown → FREE, fail-safe) and `Features` gates `unlimited_checks` / `message_analysis` / `followup` / `history`. The route enforces rate → daily → AI-budget, then calls the pipeline with `allow_message_analysis` (paid only) and `allow_ai_summary` (false once the AI budget is spent). Limits exceeded return HTTP 429 with a friendly `detail` message, never a bare 429.
**Why:** CLAUDE.md/PRICING.md require a frictionless account-free free tier that can't expose the AI bill to scripted abuse. Gating reads from `Features` everywhere, so flipping a tier unlocks paid features with no call-site changes. In-memory is sufficient for v1's single-instance stateless deploy.
**Consequences:** Counters reset on restart and don't share across workers — a shared store (Redis) is the scaling upgrade, behind the same `AbuseGuard` interface. Real accounts replace `resolve_tier` only. All thresholds live in `config.py`.

## Template

### [DATE] — Title
**Decision:** what was chosen.
**Why:** reasoning and alternatives considered.
**Consequences:** what this makes easier/harder.

---

## Pending decisions (resolve these first)

- [x] **Backend stack** — RESOLVED: Python/FastAPI (see above).
- [x] **Scoring weights** — RESOLVED: `config.SCORE_WEIGHTS` + thresholds 30/70 (see above).
- [x] **Shortener expansion list** — RESOLVED: seed list in `app/seedlists.py`, HEAD-follow expansion (see above).
- [x] **Impersonated-brand list** — RESOLVED: seed list in `app/seedlists.py` + conservative lookalike rules (see above).
