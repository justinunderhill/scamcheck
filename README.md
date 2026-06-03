# ScamCheck

Paste a suspicious link, get a clear verdict. ScamCheck helps non-technical people avoid phishing and scam URLs by checking a link against multiple security sources and explaining the result in plain language.

## Why

Innocent people get caught by scam links every day. ScamCheck gives them a fast, free way to verify a URL before they click or enter any details — and teaches them what makes a link suspicious.

## How it works

A pasted URL is checked against three sources and combined into one verdict:

1. **Google Safe Browsing** — Google's phishing/malware blocklist
2. **VirusTotal** — 70+ security engines at once
3. **Built-in heuristics** — domain age, lookalike domains, suspicious patterns, certificate checks, and more

The result is `Safe`, `Suspicious`, or `Dangerous`, with a list of reasons and a learning tip for each.

## Project layout

```
scamcheck/
├── CLAUDE.md            # Read this first — full context for Claude Code
├── README.md
├── backend/             # API: receives URL, runs detection, returns verdict
│   └── app/
│       ├── routes/      # HTTP endpoints
│       ├── services/    # One module per detection source
│       └── models/      # Request/response shapes
├── frontend/            # React + Vite single-page app
│   └── src/
│       ├── components/
│       └── lib/         # API client
└── docs/
    ├── SETUP.md         # Environment + API keys
    ├── DECISIONS.md     # Architecture decisions log
    └── ROADMAP.md       # What's next after v1
```

## Status

v1 implemented. Python/FastAPI backend with the three detection sources (Google
Safe Browsing, VirusTotal, in-house heuristics), concurrent source execution,
aggregated scoring, an escalate-only AI explanation + message-analysis layer,
per-IP rate limiting, daily free-tier cap, a global AI-call budget, stub tier
gating, and a stubbed "report a scam" endpoint. React + Vite frontend.

- API: `POST /api/check`, `POST /api/report`, `GET /api/health`
- Decisions log: `docs/DECISIONS.md` · Setup: `docs/SETUP.md`

## Getting started

See [docs/SETUP.md](docs/SETUP.md).
