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

### 2026-06-04 — Internal analytics: aggregate counters in the same KV store
**Decision:** Track product usage with **aggregate integer counters only** — no
event log, no per-request rows, never a URL or message. Counters live in the
same Upstash Redis (Vercel KV-compatible) store already used for abuse
protection, under a dedicated `stats:` prefix so the two never collide. A
`MemoryAnalyticsStore` backs local dev and tests; `RedisAnalyticsStore` (one
pipelined REST round trip per write) backs production. Writes are best-effort
(errors swallowed) and happen only after a check has already succeeded, so they
never block, fail, or skew on invalid input. Numbers are exposed only on a
token-gated `GET /api/admin/analytics` (404 when no token is set). A public
"links checked / scams flagged" pair (`GET /api/stats/public`) is derived from
the same counters but sits behind the `public_stats_enabled` flag, **off by
default**. Full spec: `docs/ANALYTICS.md`.

**Why:** We want to know what's working (volume, verdict mix, which heuristics
earn their keep, source uptime, AI-vs-template rate, how often the caps bite)
without ever building a data-retention liability. URLs and pasted messages can
carry tokens and personal data (CLAUDE.md ethics rule), so the only safe design
is "count, don't log": increment a category counter and keep nothing else.
Reusing the existing KV store avoids new infra; a separate prefix keeps the
abuse and stats namespaces independent. Best-effort writes honour the rule that
analytics must never degrade the user's result.

**Counter keys** (all under the `stats:` prefix; all aggregate integers):

| Key | Meaning | Expiry |
|---|---|---|
| `stats:checks:total` | All-time successful checks | never |
| `stats:checks:day:<YYYY-MM-DD>` | Successful checks on a given UTC day | ~120d |
| `stats:verdict:<safe\|suspicious\|dangerous>` | Verdict breakdown | never |
| `stats:heuristic:<code>` | Times a named heuristic fired (`raw_ip`, `domain_age`, …) | never |
| `stats:source:<name>:<available\|unavailable>` | External source uptime (`web_risk`, `virustotal`, `google_safe_browsing`) | never |
| `stats:ai:ran` / `stats:ai:template` | AI summary produced vs template fallback | never |
| `stats:message:ran` / `:unavailable` / `:found` | Message-analysis layer: ran / supplied-but-couldn't-run / ran-and-flagged (added 2026-06-06) | never |
| `stats:cap:free_tier` | Requests rejected by the per-IP daily free cap | never |
| `stats:cap:ai_hardcap` | Requests where the global daily AI budget was exhausted | never |

**Consequences:** `Finding` gained an internal `code` (excluded from the API
response, so the public contract is unchanged) carrying each heuristic's stable
name; `HEURISTIC_CODES` is that name list. The check route records once per
successful check and once per free-cap rejection. Only day-bucketed keys carry a
TTL; all-time totals never expire. Heuristic counter names are now a stable
internal contract — rewording a finding's user-facing text is safe, but renaming
a `code` resets that counter. Turning on the public counter is a one-flag change.

### 2026-06-05 — Detect free, abuse-heavy third-level registries (`*.biz.ua` etc.)
**Decision:** Add a heuristic, `check_abused_host_registry`, that flags hosts on
free third-level domain spaces known to be abuse magnets — seeded with the free
`.ua` registries `biz.ua`, `pp.ua`, `co.ua`, `in.ua` (`seedlists.ABUSED_HOST_SUFFIXES`).
It is **medium** severity (heuristics-medium = 20 pts). Matching is on the host
**ending** (`host == s or host.endswith("." + s)`), deliberately *not* the parsed
TLD suffix: the Public Suffix List doesn't treat these free spaces as suffixes, so
tldextract parses `x.biz.ua` as suffix `ua` / registered domain `biz.ua`, and the
existing final-label-only `check_suspicious_tld` can never see them. The list is
kept tight to clearly-free spaces; regulated/paid second levels (`com.ua`,
`org.ua`, `net.ua`, `gov.ua`, `edu.ua`) are excluded to protect legitimate sites.
**Why:** A real scam link — `kama.one.ass0028.happydayshub.biz.ua`, URL only, no
message — was returning **safe** (score 20). Brand-new free hosts are invisible to
blocklists, WHOIS is blind on these registries (no domain-age signal), and only
`excessive_subdomains` (20) fired — below the 30 'suspicious' line. Recognising the
free-host pattern adds a second medium so the **stacked-subdomains + free-host**
combination reaches 40 → **suspicious**, while a bare free host alone (20) stays
'safe' to limit false positives. Chose the targeted, high-confidence option over
re-weighting thresholds or a high-entropy-label heuristic (deferred) precisely to
avoid flagging legitimate complex URLs.
**Consequences:** New stable heuristic code `abused_host_registry` (analytics
counter follows automatically). Verdict for the morning case moves safe→suspicious;
verified end-to-end. The seed list is the tuning knob — extend it as new free-abuse
registries show up in real data; weighting stays the documented combination rule.
Still does **not** make URL-only detection reliable on a clean custom domain — the
strongest lever remains pasting the message (proven to escalate to dangerous).
**Update 2026-06-06:** `eu.org` joined `ABUSED_HOST_SUFFIXES` after a second
real report (`strw-v1-cl1.gogomailbali.it.eu.org`). It's a free subdomain
service under the real `.org` TLD, so tldextract parses it as registered domain
`eu.org` / suffix `org` — the same host-ending match (not suffix) catches it.

### 2026-06-06 — An unscanned pasted message must never read as "safe"
**Decision:** When the user supplied a `message` (so they expressly wanted it
scanned) but the message-analysis layer could not run, the result no longer
falls back to a quiet "safe". Two coupled changes: (1) `ai.analyze_message` now
lets `AIUnavailable` **propagate** instead of swallowing it and returning `[]`,
so the pipeline can tell "ran, found nothing" from "couldn't run"; (2) when the
layer is unavailable *and a message was supplied*, the pipeline adds a synthetic
medium finding, **"We couldn't check the message you pasted."** Its weight
(ai_message_analysis-medium = 30) lifts an otherwise-clean link out of the
`safe` band into `suspicious` through the normal escalate-only scoring — no
special-case verdict override.
**Why:** This is the falsely-reassuring failure the free message analysis exists
to prevent. The single most important signal for brand-new scam URLs is the
message; if we silently skip it and still show a green all-clear, we actively
mislead the worried user who pasted it. Surfacing the gap (and erring toward
caution) is the honest behaviour. Synthetic-finding-via-scoring keeps the
escalate-only invariant mechanical rather than a special case.
**Consequences:** A check with a message is at-least-`suspicious` whenever the
AI layer is down — deliberately preferring false-suspicious over false-safe.
The frontend already surfaces `ai_message_analysis` in `sources_unavailable`
("Couldn't reach message analysis"); the finding now also drives the verdict.
The `found` analytics counter is gated on the layer having actually run, so the
synthetic finding is never miscounted as a real social-engineering hit.

### 2026-06-06 — Bound WHOIS; run message analysis concurrently
**Decision:** Hard-cap the WHOIS domain-age lookup with a new
`HEURISTIC_WHOIS_TIMEOUT_SECONDS` (4s), enforced **twice**: a pinned default
socket timeout inside `lookup_registration_date` (so the worker thread can't
hang) and an `asyncio.wait_for` in the pipeline (a ceiling on request latency
regardless of the thread). Separately, move AI **message analysis into the same
`asyncio.gather`** as the heuristic lookups and blocklist calls instead of
running it after them; WHOIS and the cert check are pulled out as bounded async
tasks whose results are injected into a now-pure `heuristics.check`.
**Why:** Live testing traced the real "scam came back safe" miss to **latency,
not detection logic.** `python-whois` enforces no timeout and blocks on the
socket; on the dead/new domains scammers use it hangs for tens of seconds. With
message analysis running *after* the deterministic gather, that hang serialized
in front of it and squeezed the Sonnet call (12s timeout) until it failed —
so message analysis dropped out precisely on real scam links (reproduced:
`eu.org` URL + full message took 15–41s and intermittently 500'd or lost the
message layer, while either input alone was fine). Bounding WHOIS and
parallelizing the AI call removes the squeeze; the user waits for the slowest
source, not the sum (the CLAUDE.md concurrency rule).
**Consequences:** `heuristics.check` no longer does its own network I/O in the
hot path — the pipeline gathers WHOIS/cert with timeouts and injects them.
A stalled whois server degrades to "unknown domain age" instead of stalling or
500'ing the request. Both timeouts are config constants for tuning. Remaining
latency on cold starts is now dominated by serverless init + model latency, not
the WHOIS hang.

### 2026-06-06 — Message-analysis health counters
**Decision:** Add three aggregate counters for the message-analysis layer,
tracked separately from the `ai` summary counters: `stats:message:ran`,
`stats:message:unavailable`, `stats:message:found` (ran AND flagged ≥1 pattern).
They move **only when a message was actually submitted**, so they measure the
detector's health, not how often users paste a message.
**Why:** When a "it said safe on a scam message" report came in, the snapshot
could show the *summary* layer's health but had no signal for the *message*
layer — so we couldn't tell whether the message was scanned at all, scanned and
found nothing, or never ran. That blind spot turned a one-lookup diagnosis into
inference. These counters make the next such report answerable directly.
**Consequences:** `record_check` takes a `message_findings` count; `found` is
gated on `ran` so the synthetic "couldn't check" finding (added on the
unavailable path) is never counted as a real hit. Snapshot gains a
`message_analysis` section. Full key table in `docs/ANALYTICS.md`.

### 2026-06-06 — Keep Sonnet for message analysis, but slim its output
**Decision:** After measuring, the message-analysis latency (~13s, the dominant
cost of a check with a message) is **output volume**, not the model spinning up.
Rather than switch models, keep `claude-sonnet-4-6` and make it emit far less:
the prompt now asks for at most the **4 strongest** findings, terse one-clause
`detail`/`tip` (≤18 words), and `AI_ANALYSIS_MAX_TOKENS` drops 700 → 400.
Measured effect: scam cases fall from ~10–20s to ~7–8s while still producing a
dangerous-grade finding set; legitimate messages were already fast and stay
clean.
**Why we didn't switch to Haiku.** A head-to-head (Sonnet 4.6 vs Haiku 4.5, real
prompt, 7 scams + 4 legitimate messages) showed Haiku is ~3× faster and **caught
every scam** — but it **false-positives on legitimate urgent messages**: it
flagged a genuine bank one-time-passcode as *dangerous* (3 findings, 2 high) and
a real "sale ends midnight" promo, where Sonnet correctly stayed silent. For a
consumer-protection tool, crying wolf on a real 2FA code is its own harm (it
teaches vulnerable users to distrust legitimate security messages). The quality
we'd lose with Haiku isn't scam recall — it's false-positive discrimination —
so we kept Sonnet and attacked the *real* cost (verbosity) instead. The prompt
also gained an explicit "a real passcode / delivery update / ordinary marketing
deadline is NOT a scam; return []" guard to keep that discrimination crisp.
**Consequences:** ~2× faster message analysis with no model change, no contract
change (still `title`/`detail`/`tip`), and the documented "stronger model for
message analysis" choice intact. Findings are now capped at 4 (was 5) — a real
scam trips the same few patterns, so the cap costs nothing the verdict needs.
If ~7s is still too slow later, the remaining lever is Haiku **with**
prompt-hardening + a re-run of this comparison to confirm the false positives
are gone — not a blind switch. Streaming the verdict first (perceived latency)
stays available as a non-model option.

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
