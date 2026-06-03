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
| No/invalid HTTPS | Missing cert or invalid/expired | medium |
| Punycode / homograph | Non-ASCII lookalike characters in the domain | high |

## Notes
- Pure logic — fully unit-testable. Write tests covering each check with safe and unsafe examples.
- Seed lists (brands, shorteners, suspicious TLDs) live in small data files so they're easy to extend. Document them in `docs/DECISIONS.md`.
- Be careful with lookalike detection: avoid false positives on legitimate domains that simply contain a brand word.
