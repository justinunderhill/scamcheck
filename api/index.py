"""Vercel serverless entrypoint.

Vercel's Python runtime serves the ASGI `app` exposed here. We add the backend
package to the path and re-export the existing FastAPI app unchanged, so the
same code runs locally (uvicorn) and on Vercel. All requests under /api/* are
routed here by vercel.json; FastAPI's own /api-prefixed routes handle them.
"""
import os
import sys

_BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from app.main import app  # noqa: E402  (re-exported for Vercel)

__all__ = ["app"]
