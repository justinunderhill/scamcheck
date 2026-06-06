# Heuristics service — spec

This is the in-house detection module (no external API). Implement it in the chosen backend language under `backend/app/services/`. Expose one function:

```
check(normalized_url) -> list of findings
```

Each finding is a dict/object:
```
{
  source: "heuristics",
  severity: "low" | "medium" | "high",
  title: <short plain-language label>,
  detail: <one sentence explaining what was found>,
  tip: <one sentence teaching the user the general lesson>
}
```

## Checks to implement (each is independent and testable)

| Check | Signal | Severity |
|---|---|---|
| Domain age (WHOIS) | Registered very recently (< 30 days) | medium–high by recency |
| Lookalike / typosquatting | Domain resembles a known brand but isn't it (e.g. paypa1, amaz0n-support) | high |
| Raw IP as host | URL uses an IP address instead of a domain | high |
| Excessive subdomains | Many dot-separated labels hiding the real domain | medium |
| URL shortener | Host is a known shortener — expand and re-check the destination | low (info) |
| Suspicious TLD | TLD frequently abused in scams | low–medium |
| Abused free-host registry | Host sits on a free, abuse-heavy shared space (`*.biz.ua`, `*.eu.org`, …) — matched on the host *ending*, since the PSL doesn't treat these as suffixes (see `docs/DECISIONS.md`, 2026-06-05/06) | medium |
| No/invalid HTTPS | Missing cert or invalid/expired | medium |
| Punycode / homograph | Non-ASCII lookalike characters in the domain | high |
| Embedded credentials / `@` in URL | URL contains userinfo before an `@`, so the real host is what follows the `@` (e.g. `instagram.com@evil.com` goes to evil.com) | high |

## Notes
- Pure logic — fully unit-testable. Write tests covering each check with safe and unsafe examples.
- Seed lists (brands, shorteners, suspicious TLDs, abused host suffixes) live in `app/seedlists.py` so they're easy to extend. Document them in `docs/DECISIONS.md`.
- Be careful with lookalike detection: avoid false positives on legitimate domains that simply contain a brand word.
- **The two network-backed checks (WHOIS domain age, TLS cert) take their gathered data as arguments** so the checks stay pure/offline-testable; the pipeline fetches them as bounded async tasks. WHOIS in particular **must** be hard-bounded (`HEURISTIC_WHOIS_TIMEOUT_SECONDS`): `python-whois` has no timeout and blocks on the socket, and the dead/new domains scams use make it hang — which previously starved the concurrent AI message-analysis call (see `docs/DECISIONS.md`, 2026-06-06).

## Detailed: Embedded credentials / `@` in URL (high priority)

**Why this matters.** In a URL, anything between `://` and an `@` is the *userinfo* (a username/password), and the real host is whatever comes *after* the `@`. Browsers honour this. So `https://instagram.com@evil-site.com` does NOT go to Instagram — it goes to `evil-site.com`. This is a classic, widely-used phishing trick: put a trusted brand name before the `@` so a glancing human reads "instagram.com" while the browser silently navigates somewhere else. A naive checker that reads the brand name as the domain can return a false "safe" — exactly the failure mode this whole app is built to avoid.

**Detection logic:**
1. Parse the URL properly (use the stdlib URL parser, not a hand-rolled regex). After parsing, the host is the authority *after* any `@`. Run all other heuristics and the blocklist checks against that true host, never against the userinfo portion.
2. If userinfo is present at all (there is an `@` in the authority), raise a finding. The presence of credentials embedded in a link sent to a consumer is itself unusual and worth flagging.
3. Escalate to **high** severity when the userinfo *looks like a domain or a known brand* (contains a dot, or matches the impersonated-brand seed list) — i.e. `instagram.com@…`, `paypal.com@…`. This is the deliberate deception pattern.
4. The finding's `detail` should name the **true** destination host plainly, so the user sees where the link really goes. Example detail: "This link looks like it goes to instagram.com, but it actually goes to evil-site.com." `tip`: "The real destination of a link is the part right before the first single slash — anything before an '@' sign can be faked."

**Test cases to include:**
- `https://instagram.com@evil-site.com` → high finding, true host evil-site.com
- `https://paypal.com@192.0.2.10/login` → high finding (also trips raw-IP check on the true host)
- `https://user@github.com` → finding present but lower severity (userinfo isn't a brand/domain lookalike) — tune to avoid over-flagging legitimate-but-rare cases
- `https://instagram.com/login` → no `@` finding

## Decision: how to handle pasted email addresses

**Resolved 2026-06-04** (see `docs/DECISIONS.md`): emails are detected by shape
before normalisation and checked as their sender domain — never rewritten into a
`https://…@…` URL — and the result is labelled as an email-domain check. The
behaviour below is implemented in `core/urls.py` (`looks_like_email`,
`normalize_url`) and surfaced by the summary.


Users will paste **email addresses**, not just URLs — they get suspicious *emails* and want to check the sender. Right now an input like `security@mail.instagram.com` is being silently coerced into `https://security@mail.instagram.com`, which then parses as userinfo `security` + host `mail.instagram.com`. That's misleading on two fronts: it's not what the user meant, and it hides the `@` logic above.

Required behaviour (record the chosen approach in `docs/DECISIONS.md`):
1. **Detect input type before normalising.** If the input matches an email address shape (`localpart@domain` with no scheme and no path), treat it as an email, not a URL.
2. For an email, check the **domain part** (e.g. `mail.instagram.com`) through the normal pipeline, and label the result clearly as "We checked the domain this email comes from" — don't present it as if a URL was checked.
3. Be honest about scope: domain reputation is only one signal for email. A clean sender domain does NOT mean the email is safe (display-name spoofing, lookalike domains, and compromised accounts all exist). The summary must say so.
4. Never silently rewrite an email into a `https://…@…` URL. That conflates the two cases and can produce a misleading "safe."

This pairs with the `@`-in-URL heuristic: one keeps genuine URLs honest, the other stops email input from masquerading as a safe URL.
