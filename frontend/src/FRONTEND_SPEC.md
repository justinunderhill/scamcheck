# Frontend — spec

React + Vite single-page app. One job in v1: take a URL and show the verdict clearly.

## Components to build
- `UrlInput` — large paste field + "Check link" button. Disable while loading.
- `VerdictCard` — big colored verdict (green/amber/red) with the score and a one-line summary. Be honest: "No known threats found" rather than "This is safe."
- `FindingsList` — each finding as a row: title, detail, and an expandable tip.
- `SourcesNote` — small print listing which sources were checked and any that were unavailable.

## lib/
- `api.js` — single `checkUrl(url)` that POSTs to `${VITE_API_BASE_URL}/api/check` and returns the parsed response. Handle network/timeout errors with a friendly message.

## UX principles
- Non-technical audience. No jargon on screen.
- Make the verdict readable at a glance; details are secondary.
- Never auto-open or preview the submitted link.
