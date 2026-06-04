# Analytics

How ScamCheck measures its own usage — and the hard line it never crosses.

## The one absolute rule: count, don't log

We store **aggregate integer counters and nothing else.** We never persist a
URL, a domain, a query string, a pasted message, an IP, or anything that could
identify a user or their input. Every counter answers a *category* question
("how many checks came back dangerous?"), never a *which* question ("which URL?").

This is a deliberate design constraint, not an implementation detail: URLs and
messages routinely contain session tokens, password-reset links, and personal
data (see the ethics rules in `CLAUDE.md`). The only way to make a usage metric
safe is to throw the input away and keep a tally. If a counter ever needed the
URL to compute, that's a bug — redesign the counter.

## Where the numbers live

Counters are stored in the same Upstash Redis (Vercel KV-compatible) instance
used for abuse protection, under a dedicated `stats:` prefix so the two
namespaces never collide. Two store implementations sit behind the
`AnalyticsStore` protocol (`backend/app/services/analytics.py`):

- **`MemoryAnalyticsStore`** — a per-process dict. Used for local dev, tests,
  and direct inspection. Counters reset when the process restarts.
- **`RedisAnalyticsStore`** — Upstash Redis over its REST API. One pipelined
  round trip per write (`INCRBY` per key, plus `EXPIRE … NX` for day-bucketed
  keys). Used in production / on Vercel.

The process picks the Redis store automatically when `UPSTASH_REDIS_REST_URL` /
`KV_REST_API_URL` (+ token) are configured, otherwise the memory store. This is
the same selection logic as the abuse `guard`.

See `docs/DECISIONS.md` (2026-06-04 entry) for the KV decision and the full key
table.

## When counters move

Counters are incremented **only after a check has already succeeded** — a valid
URL that ran through the pipeline and produced a verdict. Consequences:

- Malformed input (400) and rate/cap rejections never touch the volume counters.
  (The cap *rejection* counters are the deliberate exception — see below.)
- Writes are **best-effort**: every store call is wrapped so a KV outage is
  swallowed. Analytics can never block, delay meaningfully, or fail a user's
  result. We would rather under-count than degrade the product.

Recording happens in `POST /api/check` (`backend/app/routes/check.py`), once per
successful check (`record_check`) and once per free-tier cap rejection
(`record_free_cap_hit`).

## What we track

| Dimension | Keys |
|---|---|
| **Total checks** | `stats:checks:total` (all-time) and `stats:checks:day:<YYYY-MM-DD>` (per UTC day) |
| **Verdict breakdown** | `stats:verdict:safe`, `stats:verdict:suspicious`, `stats:verdict:dangerous` |
| **Which heuristics fired** | `stats:heuristic:<code>` — one per heuristic, by stable name |
| **External source availability** | `stats:source:<name>:available` and `…:unavailable` for `web_risk`, `virustotal`, `google_safe_browsing` |
| **AI ran vs template fallback** | `stats:ai:ran`, `stats:ai:template` |
| **Free-tier cap hits** | `stats:cap:free_tier` |
| **AI hard-cap hits** | `stats:cap:ai_hardcap` |

### Heuristic names (`stats:heuristic:<code>`)

Each heuristic finding carries a stable internal `code` (excluded from the API
response). The full set lives in `HEURISTIC_CODES`
(`backend/app/services/heuristics.py`):

`embedded_credentials`, `raw_ip`, `excessive_subdomains`, `shortener`,
`suspicious_tld`, `punycode`, `homograph`, `lookalike`, `domain_age`,
`no_https`, `cert_problem`.

These names are an internal contract for the counters. The user-facing wording
of a finding (`title` / `detail` / `tip`) can change freely; renaming a `code`,
by contrast, starts a fresh counter, so don't.

### AI ran vs template fallback

Derived from whether the `ai` summary source landed in `sources_unavailable`: if
it did, the request used the deterministic template summary
(`stats:ai:template`); otherwise the AI explanation ran (`stats:ai:ran`). This
covers every fallback reason (no key, interlock off, budget exhausted).

### The two cap counters

- `stats:cap:free_tier` — a request was rejected because the caller hit the
  per-IP daily free-tier cap (`FREE_TIER_CHECKS_PER_DAY`). Recorded at the 429.
- `stats:cap:ai_hardcap` — a successful check that *lost its AI summary* because
  the global daily AI budget (`AI_DAILY_CALL_CAP`) was exhausted (or its store
  was unavailable, which fails closed). The verdict and findings are unaffected.

## Retention

Only day-bucketed keys (`stats:checks:day:*`) carry a TTL
(`ANALYTICS_DAILY_TTL_SECONDS`, ~120 days) so they don't accumulate forever.
All-time totals never expire. Nothing here is user data, so retention is purely
about bounding key count.

## Reading the numbers

### Admin (private) — `GET /api/admin/analytics`

Returns the full snapshot (totals, today, verdict mix, every heuristic, source
uptime, AI ratio, cap hits). **Admin-only:**

- Requires the secret `ADMIN_API_TOKEN`, sent as `X-Admin-Token: <token>` or
  `Authorization: Bearer <token>`. Compared in constant time.
- When `ADMIN_API_TOKEN` is unset the route is **disabled and returns 404** — we
  don't even advertise that an admin surface exists. A wrong/missing token on an
  enabled deployment returns 401.

Example response:

```json
{
  "checks": { "total": 12840, "today": 317 },
  "verdicts": { "safe": 9001, "suspicious": 2600, "dangerous": 1239 },
  "heuristics": { "raw_ip": 142, "domain_age": 1880, "lookalike": 540, "...": 0 },
  "sources": {
    "web_risk": { "available": 12700, "unavailable": 140 },
    "virustotal": { "available": 12010, "unavailable": 830 },
    "google_safe_browsing": { "available": 0, "unavailable": 0 }
  },
  "ai": { "ran": 8200, "template_fallback": 4640 },
  "caps": { "free_tier_hit": 410, "ai_hardcap_hit": 35 }
}
```

### Public — `GET /api/stats/public` (feature-flagged, OFF)

A trust-building "links checked / scams flagged" pair, derived from the same
counters:

- `links_checked` = `stats:checks:total`
- `scams_flagged` = `stats:verdict:suspicious` + `stats:verdict:dangerous`

This route sits behind the `PUBLIC_STATS_ENABLED` flag, which is **off by
default**: until it's turned on the route returns 404. No new data is collected
to power it — flipping the flag only exposes a read of existing counters.

```json
{ "links_checked": 12840, "scams_flagged": 3839 }
```

## Testing

The store is mocked everywhere (`backend/tests/test_analytics.py`):

- `MemoryAnalyticsStore` for inspecting exactly which counters moved.
- A tiny broken store to prove recording is best-effort (never raises).
- `respx` for the Upstash REST transport of `RedisAnalyticsStore`.
- Route tests cover admin token gating (404 disabled / 401 wrong / 200 right)
  and the public flag (404 off / 200 on).

`conftest.py` points the global `analytics` singleton at a fresh in-memory store
for every test, so the suite never reaches a real KV.
