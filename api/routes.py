import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from backend.fast_checker import create_export_excel, create_export_zip, process_urls_stream
from backend import config
from backend.metrics import metrics_collector
from backend.networking import circuit_breaker

router = APIRouter(prefix="/api")

# ── Request / Response models ─────────────────────────────────────────────────

MAX_URLS_PER_REQUEST = 500

class URLCheckRequest(BaseModel):
    urls: list[str]
    # Screenshot capture mode for this run: "off" | "all" | "active" |
    # "uncertain" | "taken_down". None falls back to the server default.
    screenshot_mode: Optional[str] = None

class ExportResultItem(BaseModel):
    url: str = ""
    platform: str = "generic"
    status: str = ""
    reason: str = ""
    http_code: Optional[int] = None
    # Evidence strength behind the verdict (0-100). Exported so a reviewer can
    # see which rows were proven and which were only plausible.
    confidence: Optional[int] = None

class ExportRequest(BaseModel):
    results: list[ExportResultItem]

class CookiesSaveRequest(BaseModel):
    cookies: dict[str, list[dict]]

# ── API routes ────────────────────────────────────────────────────────────────

@router.get("/cookies")
async def get_cookies():
    """Get all saved cookies for platform checks (LinkedIn, FB, IG, X)."""
    from backend.cookies import load_all_cookies
    return load_all_cookies()

@router.post("/cookies")
async def post_cookies(request: CookiesSaveRequest):
    """Save cookies to disk for platform checkers."""
    from backend.cookies import save_all_cookies
    save_all_cookies(request.cookies)
    return {"status": "ok"}

@router.get("/health")
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

@router.post("/check/json")
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
    async for event in process_urls_stream(request.urls, screenshot_mode=request.screenshot_mode):
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
            if "screenshot_url" in event:
                result_item["screenshot_url"] = event["screenshot_url"]

            results.append(result_item)

    return {"results": results}

@router.post("/check")
async def check_urls_stream(request: URLCheckRequest):
    """Stream URL check results as Server-Sent Events (for frontend use)."""
    if len(request.urls) > MAX_URLS_PER_REQUEST:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_URLS_PER_REQUEST} URLs per request.")

    async def _generate():
        async for event in process_urls_stream(request.urls, screenshot_mode=request.screenshot_mode):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )

@router.get("/metrics")
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

@router.post("/export")
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


@router.post("/export/excel")
async def export_excel_results(request: ExportRequest):
    """Build an Excel file with Summary Pivot table and Detailed Results."""
    results_dicts = [r.model_dump() for r in request.results]
    excel_bytes = create_export_excel(results_dicts)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    return Response(
        content=excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="url-summary-report-{ts}.xlsx"'},
    )

