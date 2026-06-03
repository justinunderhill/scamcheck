# Pricing & Tiers

This document captures the pricing model and the reasoning behind it. The model is mission-first: the free tier exists to reach the people most targeted by scams (often elderly, less tech-savvy, or in financial distress — the least able to pay in the panicked moment a scam arrives). Paid and business tiers subsidize that free access.

## Principles

1. **The vulnerable must not be priced out.** A pure paywall would structurally exclude actual scam victims. The free tier is the mission.
2. **The free tier is also the funnel.** A free check is shareable — someone flags a scam and forwards the tool to their family group chat. That word-of-mouth is the growth engine, especially among the worried-relative demographic.
3. **Free must be cheap to serve and abuse-resistant.** Thin limits + caching + a cheap model + rate limiting keep free-tier cost negligible and prevent automated abuse from running up the AI bill.
4. **Paid + business carry the economics.** Power users, worried relatives who check constantly, and small businesses/community orgs fund the free access.

## Tiers (v1 target)

### Free — "Check a link"
- A few checks per day (exact number tunable; start low, e.g. 5/day).
- **No account required.** Frictionless — this is non-negotiable for reaching vulnerable users in the moment.
- Core verdict + findings + AI plain-language explanation.
- Rate-limited per IP; hard daily cap on AI calls (see abuse protection below).

### Paid — small monthly fee
- Unlimited checks.
- Message analysis (paste the whole message, not just the URL).
- Conversational follow-up ("what do I do now?").
- Check history.
- Requires a lightweight account.

### Business / Organization
- For small businesses, schools, community orgs, support groups for the elderly, etc.
- Higher volume, optional API access, team/seat management.
- This tier (and optionally a "sponsor a senior" / donation option) is what subsidizes free individual use, fulfilling the "greater community" mission.

## Cost structure (for reference, not commitments)

- **Fixed:** modest server hosting for FastAPI + static frontend. Google Safe Browsing free; VirusTotal free tier until volume grows.
- **Variable (scales with use):** the AI layer. The explanation call uses a fast, cheap model and is cached on a hash of (verdict, findings), so identical results don't re-bill — cost per check is a small fraction of a cent. Message analysis costs somewhat more (longer input). The v2 page/vision analysis is the expensive feature and is intentionally gated to paid tiers.

## Abuse protection (required in v1 — protects the free tier)

- Per-IP rate limiting on `/api/check`.
- A global/hard daily cap on total AI calls, with deterministic-only fallback once exceeded (the app still returns a verdict, just without the AI summary).
- These let the free tier stay account-free without exposing the AI bill to scripted abuse.

## Open questions to revisit
- Exact free-tier daily limit (start conservative, tune with real data).
- Price point for the paid tier (keep it genuinely small — the goal is broad accessibility, not margin maximization).
- Whether to add an explicit donation / sponsorship path in v1 or v2.
