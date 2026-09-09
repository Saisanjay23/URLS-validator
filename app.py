"""
FastAPI application — Stateless URL validation microservice.
Java sends URLs → Python returns results → done. No database, no state.

Enterprise v5.0: Added /api/metrics, enhanced /api/health, pass-through
for confidence/signals/metadata fields.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.logger import get_logger
from backend import config
from api.routes import router as api_router

logger = get_logger()

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Social URL Status Checker",
    description="Enterprise-grade bulk URL validation engine. Check whether social media URLs are active or taken down.",
    version="5.0.0",
)

# Frontend is served same-origin (no CORS needed); Java calls server-to-server
# (CORS not applicable). Extra browser origins come from URLCHECK_ALLOWED_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── API routes ────────────────────────────────────────────────────────────────

app.include_router(api_router)


@app.on_event("shutdown")
async def shutdown_event():
    """Ensure the global Playwright browser closes cleanly on app shutdown."""
    try:
        from backend.fast_checker import close_global_playwright
        await close_global_playwright()
        logger.info("[PLAYWRIGHT] Global browser closed cleanly on shutdown.")
    except Exception as e:
        logger.warning(f"[PLAYWRIGHT] Error closing global browser on shutdown: {e}")


# Serve screenshot evidence (hover previews in the UI). Mounted BEFORE the "/"
# catch-all so it isn't shadowed. NOTE: this directory is served without auth —
# it inherits whatever access control fronts the app, so put the API behind auth
# before exposing this publicly.
os.makedirs(config.SCREENSHOT_DIR, exist_ok=True)
app.mount("/evidence", StaticFiles(directory=config.SCREENSHOT_DIR), name="evidence")

# Mount frontend static files at root
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

