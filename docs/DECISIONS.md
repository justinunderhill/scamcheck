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

### 2026-06-04 — Userinfo (`@`) handling and email-address input
**Decision:** Two paired rules, both centred in `core/urls.normalize_url`:

1. **`@`-in-URL (userinfo) is stripped from the URL the rest of the app sees.**
   A URL's real host is whatever follows the last `@`; anything before it is
   userinfo and is spoofable (`https://instagram.com@evil.com` goes to evil.com).
   `normalize_url` parses with the stdlib, records the userinfo separately on
   `NormalizedURL.userinfo`, and rebuilds the normalized `url` from the true host
   only. Every heuristic and both blocklists already read `host` /
   `registered_domain` / `url`, so they all now run against the true destination.
   A new heuristic, `check_embedded_credentials`, flags any userinfo (medium) and
   escalates to **high** when it imitates a domain or brand (a dot or a brand
   token) — the deliberate-deception pattern — naming the true host in the detail.

2. **A bare email address is checked as its sender domain, never rewritten.**
   `looks_like_email` classifies `localpart@domain` (no scheme, no path, dotted
   domain) *before* normalisation. For an email we check the **domain** through
   the normal pipeline and set `is_email` / `email_address`. The response echoes
   the email as `input_url` and the checked domain as `final_url`, and the summary
   (AI and template) is labelled: *"You pasted an email address, so we checked the
   domain it comes from (…). A clean sender domain doesn't mean the email is
   safe…"*. The email caveat is summary-only — it adds **no** risk points, so a
   clean sender domain still scores 0 / safe.

**Why:** The whole app exists to stop a false "safe". Reading a brand name out of
userinfo, or silently coercing `name@domain` into `https://name@domain` (userinfo
again), are two ways to do exactly that. Classifying email up front and stripping
userinfo close both holes while keeping the public contract stable.
**Consequences:** `NormalizedURL` gained `userinfo`, `is_email`, `email_address`
(defaulted, so construction is unchanged). `template_summary` and `ai.explain`
take an optional `email_domain` (the latter folds it into the cache key);
the pipeline only passes it for email input. Email is honestly scoped as one
weak signal, not a verdict on the message itself.

## Template

### [DATE] — Title
**Decision:** what was chosen.
**Why:** reasoning and alternatives considered.
**Consequences:** what this makes easier/harder.

---

## Pending decisions (resolve these first)

- [x] **Backend stack** — RESOLVED: Python/FastAPI (see above).
- [ ] **Scoring weights** — how each source and heuristic contributes to the 0–100 score and the safe/suspicious/dangerous thresholds. Record the chosen numbers so they can be tuned.
- [ ] **Shortener expansion list** — which shortener domains to expand, and the safe method for following redirects.
- [ ] **Impersonated-brand list** — the seed list of brands used for lookalike/typosquatting detection.
- [x] **Email-input handling** — RESOLVED: detect `localpart@domain` before normalising, check the sender domain, label it as an email-domain check and warn a clean domain ≠ safe email (see 2026-06-04 entry above).
