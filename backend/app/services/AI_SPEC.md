# AI service — spec

The AI layer adds human-friendly reasoning on top of the deterministic detection. It lives in `backend/app/services/` alongside the other sources and follows the same shape, but it is **special**: it never owns the verdict.

## The one rule that overrides everything

**AI can only escalate risk, never downgrade it.**

- The verdict and base score come from blocklists + heuristics. AI runs after them.
- AI may *add* findings and *raise* the score (e.g. it spots a scam script in the pasted message).
- AI may **never** lower the score, remove a finding, or turn a `dangerous`/`suspicious` verdict into `safe`.
- The LLM must never emit a standalone "this is safe" claim. The most it can say about a clean link is "nothing was flagged, but stay cautious."
- If the AI service errors, times out, or rate-limits: continue without it. Return the deterministic result, set a template `summary`, and add `ai` to `sources_unavailable`. The app must be fully functional with AI off.

## v1 functions

### 1. `explain(verdict, score, findings) -> summary_string`
Takes the finished deterministic result and writes a calm, plain-language paragraph for a non-technical, possibly worried user. No jargon. Honest about uncertainty. Tailor tone to severity (reassuring-but-cautious for clean, firm-and-clear for dangerous). Use a **fast, cheap model** — this runs on every request.

### 2. `analyze_message(message_text, url) -> list[finding]`
Only runs if the user pasted a message. Detects social-engineering patterns:
- Fake urgency / deadlines ("account closes in 24h")
- Authority impersonation (bank, tax office, police, boss, CEO)
- Payment / gift-card / crypto pressure
- Known scripts: grandparent ("Hi mum, lost my phone"), romance, job-offer, parcel-delivery, refund scams
- Mismatch between who the message claims to be and the actual link domain

Returns normalized findings (`source: "ai_message_analysis"`) that feed into scoring like any other source. Can raise severity to `high`.

## v2 functions (define interfaces now, stub bodies)

### 3. `analyze_page(safe_capture) -> list[finding]`
Vision/text analysis of a **safely captured** destination (screenshot + extracted text — never live-rendered to the user). Detects brand-impersonation login pages and pressure tactics on sites too new for blocklists.

### 4. `followup(question, prior_result) -> answer_string`
Grounded Q&A after a verdict ("what do I do now?", "I already clicked — what now?"). Must stay within the established verdict and give practical safety steps.

## Implementation notes
- Use the official `anthropic` Python SDK. Key from env (`ANTHROPIC_API_KEY`), backend only.
- Keep prompts in a dedicated `prompts/` area or constants module so they're reviewable and testable — don't bury them inline.
- **Cost control:** cache `explain` outputs keyed by a hash of (verdict, sorted findings) so identical results don't re-bill. Set sensible `max_tokens`. Pick the cheapest model that gives good explanations; only `analyze_page` warrants a stronger model.
- **Privacy:** the pasted message may contain personal data. Do not persist it. Strip it from logs. Send only what's needed to the model.
- **Prompt-injection safety:** the URL, page content, and pasted message are UNTRUSTED input. Never let them alter the system instructions or the escalate-only rule. Treat them strictly as data to analyze, never as commands.
- Mock the AI calls in tests — CI never hits the real API.
