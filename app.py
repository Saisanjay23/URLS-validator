"""
FastAPI application — Stateless URL validation microservice.
Java sends URLs → Python returns results → done. No database, no state.

Enterprise v5.0: Added /api/metrics, enhanced /api/health, pass-through
for confidence/signals/metadata fields.
"""

import json
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.fast_checker import create_export_zip, process_urls_stream
from backend.logger import get_logger
from backend import config
from backend.metrics import metrics_collector
from backend.networking import circuit_breaker

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


# ── Request / Response models ─────────────────────────────────────────────────

MAX_URLS_PER_REQUEST = 500

class URLCheckRequest(BaseModel):
    urls: list[str]

class ExportResultItem(BaseModel):
    url: str = ""
    platform: str = "generic"
    status: str = ""
    reason: str = ""
    http_code: Optional[int] = None

class ExportRequest(BaseModel):
    results: list[ExportResultItem]

class CookiesSaveRequest(BaseModel):
    cookies: dict[str, list[dict]]


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/cookies")
async def get_cookies():
    """Get all saved cookies for platform checks (LinkedIn, FB, IG, X)."""
    from backend.cookies import load_all_cookies
    return load_all_cookies()


@app.post("/api/cookies")
async def post_cookies(request: CookiesSaveRequest):
    """Save cookies to disk for platform checkers."""
    from backend.cookies import save_all_cookies
    save_all_cookies(request.cookies)
    return {"status": "ok"}


@app.get("/api/health")
async def health():
    """
    Enhanced health check endpoint.
    
    Returns service status, version, feature flags, and circuit breaker state.
    """
    response = {
        "status": "ok",
        "service": "social-url-status-checker",
        "version": "5.0.0",
    }

    # Include feature flags status
    response["feature_flags"] = config.get_all_flags()

    # Include circuit breaker status if enabled
    if config.ENABLE_CIRCUIT_BREAKER:
        cb_status = circuit_breaker.get_status()
        if cb_status:
            response["circuit_breaker"] = cb_status

    return response


@app.post("/api/check/json")
async def check_urls_json(request: URLCheckRequest):
    """
    Primary endpoint — Check URLs and return results as JSON.
    Used by Java integration.
    
    Response includes the original fields (url, platform, status, reason, http_code)
    plus optional enterprise fields (confidence, signals, metadata) when enabled.
    """
    if len(request.urls) > MAX_URLS_PER_REQUEST:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_URLS_PER_REQUEST} URLs per request.")

    results = []
    async for event in process_urls_stream(request.urls):
        if event.get("type") == "result":
            # Build result with original fields (backward compatible)
            result_item = {
                "url": event.get("url"),
                "platform": event.get("platform"),
                "status": event.get("status"),
                "reason": event.get("reason"),
                "http_code": event.get("http_code"),
            }

            # Append enterprise fields if present (additive only)
            if "confidence" in event:
                result_item["confidence"] = event["confidence"]
            if "signals" in event:
                result_item["signals"] = event["signals"]
            if "metadata" in event:
                result_item["metadata"] = event["metadata"]

            results.append(result_item)

    return {"results": results}


@app.post("/api/check")
async def check_urls_stream(request: URLCheckRequest):
    """Stream URL check results as Server-Sent Events (for frontend use)."""
    if len(request.urls) > MAX_URLS_PER_REQUEST:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_URLS_PER_REQUEST} URLs per request.")

    async def _generate():
        async for event in process_urls_stream(request.urls):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.get("/api/metrics")
async def get_metrics():
    """
    Performance metrics endpoint (enterprise enhancement).
    
    Returns aggregated performance data including:
      - Total checks, uptime, throughput
      - Status and platform breakdowns
      - Timing averages and percentiles (p50, p95, p99)
      - Error type breakdown
    """
    if not config.ENABLE_METRICS:
        return {"message": "Metrics collection is disabled. Set URLCHECK_ENABLE_METRICS=true to enable."}

    return metrics_collector.get_summary()


@app.post("/api/export")
async def export_results(request: ExportRequest):
    """Build a ZIP containing report.csv and return it as a download."""
    results_dicts = [r.model_dump() for r in request.results]
    zip_bytes = create_export_zip(results_dicts)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="url-report-{ts}.zip"'},
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Ensure the global Playwright browser closes cleanly on app shutdown."""
    try:
        from backend.fast_checker import close_global_playwright
        await close_global_playwright()
        logger.info("[PLAYWRIGHT] Global browser closed cleanly on shutdown.")
    except Exception as e:
        logger.warning(f"[PLAYWRIGHT] Error closing global browser on shutdown: {e}")


# Mount frontend static files at root
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

