# Roadmap

## v1 (current)
- Single URL check endpoint
- Three sources: Google Safe Browsing, VirusTotal, built-in heuristics
- AI explanation layer + message analysis (escalate-only)
- Plain-language verdict + reasons + tips
- React web UI with one input
- Thin free tier (account-free, rate-limited) + paid feature gating + abuse protection

## Monetization (evolves alongside features — see docs/PRICING.md)
- v1: free tier (account-free, capped) + paid tier (small fee, account-based) + business/org tier
- Later: optional "sponsor a senior" / donation path so businesses and individuals can fund free access for vulnerable users
- Keep the paid price genuinely small — accessibility over margin

## v2 — community + reach
- "Report a scam" submissions (data shape stubbed in v1) with moderation
- Build an internal blocklist from confirmed reports
- Add PhishTank and URLScan.io as sources
- Shareable result links so people can warn friends

## v3 — meet users where scams arrive
- Browser extension (right-click a link → check)
- Mobile apps (the React UI can inform a React Native port)
- A check-by-paste bot for WhatsApp/Telegram, since that's where many scam links spread

## v4 — scale + sustainability
- Caching layer for repeat lookups (respect privacy: hash domains, short TTL)
- Optional accounts for history and reporting reputation
- Localization — scams are global; the educational tips especially should translate

## Always
- Keep verdicts honest about uncertainty
- Keep the language non-technical
- Privacy first: minimize what's logged or stored
