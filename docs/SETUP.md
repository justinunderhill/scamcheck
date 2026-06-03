# Setup

## Prerequisites

- Node.js 18+ (for the frontend, and the backend if you choose Node)
- Python 3.11+ (only if you choose a Python backend)
- Git

## 1. Get your API keys

Both are free to start.

### Google Safe Browsing
1. Go to the Google Cloud Console and create a project.
2. Enable the **Safe Browsing API**.
3. Create an API key under Credentials.
4. Copy it into your `.env` as `GOOGLE_SAFE_BROWSING_KEY`.

### VirusTotal
1. Create a free account at virustotal.com.
2. Open your profile → **API Key**.
3. Copy it into your `.env` as `VIRUSTOTAL_KEY`.
4. Note: the free tier is rate-limited (a few requests/minute). The backend should handle 429 responses gracefully.

### Anthropic (AI layer)
1. Create an account at console.anthropic.com.
2. Generate an API key under API Keys.
3. Copy it into your `.env` as `ANTHROPIC_API_KEY`.

## 2. Environment file

Copy the example and fill in your keys:

```bash
cp .env.example .env
```

Never commit `.env`. It's already gitignored.

## 3. Backend (Python / FastAPI)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

Or with [uv](https://docs.astral.sh/uv/) (no system Python needed — it manages
the interpreter for you):

```bash
cd backend
uv python install 3.12
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run uvicorn app.main:app --reload --port 8000
```

Check it's up: `GET http://localhost:8000/api/health`.

## 4. Frontend

```bash
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` calls to the backend. Configure the backend URL in `frontend/.env` if needed.

## Running tests

Heuristics have unit tests. External APIs are mocked in tests — CI never makes real network calls (tests also ignore the repo `.env`, so real keys never leak in).

```bash
cd backend
uv run pytest          # or: pytest, inside an activated venv
```

Frontend type-check + build:

```bash
cd frontend
npm run build
```
