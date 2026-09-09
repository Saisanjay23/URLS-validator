"""
Configuration & Feature Flags — Enterprise URL Validation Engine.

Every enhancement is independently togglable via feature flags.
All flags can be overridden via environment variables:
    export URLCHECK_ENABLE_CONFIDENCE=false

Defaults: All features ON.
"""

import os
from typing import Any


def _env_bool(key: str, default: bool = True) -> bool:
    """Read a boolean from environment, defaulting to `default`."""
    val = os.environ.get(f"URLCHECK_{key}", "").strip().lower()
    if val in ("0", "false", "no", "off"):
        return False
    if val in ("1", "true", "yes", "on"):
        return True
    return default


# ── Feature Flags ─────────────────────────────────────────────────────────────
# Each flag controls an independent enhancement layer.
# Disabling a flag causes the engine to fall back to existing behavior.

ENABLE_CONFIDENCE          = _env_bool("ENABLE_CONFIDENCE")
ENABLE_EVIDENCE            = _env_bool("ENABLE_EVIDENCE")
ENABLE_METRICS             = _env_bool("ENABLE_METRICS")
ENABLE_HEAD_OPTIMIZATION   = _env_bool("ENABLE_HEAD_OPTIMIZATION", default=False)
ENABLE_CIRCUIT_BREAKER     = _env_bool("ENABLE_CIRCUIT_BREAKER")
# Enforces HOST_CONCURRENCY. Now on by default: without it all CONCURRENT_LIMIT
# slots hit a single platform at once, and Facebook/Scribd verdicts flipped
# between runs under that load (stable when checked individually). Accuracy
# under batch load depends on this.
ENABLE_ADAPTIVE_RATE_LIMIT = _env_bool("ENABLE_ADAPTIVE_RATE_LIMIT", default=True)
ENABLE_STRUCTURED_LOGGING  = _env_bool("ENABLE_STRUCTURED_LOGGING")
ENABLE_PARKING_EXPANSION   = _env_bool("ENABLE_PARKING_EXPANSION")
ENABLE_ERROR_CLASSIFICATION = _env_bool("ENABLE_ERROR_CLASSIFICATION")
ENABLE_PLAYWRIGHT_FALLBACK  = _env_bool("ENABLE_PLAYWRIGHT_FALLBACK", default=True)
ENABLE_TEMPORAL_CONFIRMATION = _env_bool("ENABLE_TEMPORAL_CONFIRMATION", default=True)
ENABLE_PROXY_ROTATION       = _env_bool("ENABLE_PROXY_ROTATION", default=False)
ENABLE_SCREENSHOT_CAPTURE   = _env_bool("ENABLE_SCREENSHOT_CAPTURE", default=False)
ENABLE_SCREENSHOT_OCR       = _env_bool("ENABLE_SCREENSHOT_OCR", default=False)
ENABLE_STEALTH_HEADERS      = _env_bool("ENABLE_STEALTH_HEADERS", default=True)
ENABLE_REFERER_SPOOFING     = _env_bool("ENABLE_REFERER_SPOOFING", default=True)
ENABLE_GOOGLE_CACHE_VERIFY  = _env_bool("ENABLE_GOOGLE_CACHE_VERIFY", default=True)
ENABLE_WAYBACK_VERIFY       = _env_bool("ENABLE_WAYBACK_VERIFY", default=True)

# ── Verdict Verification Gate ─────────────────────────────────────────────────
# Audits every `active` verdict against the page content actually fetched, so a
# checker can never report `active` merely because it failed to find a removal
# notice. Soft-404s (HTTP 200 + "content unavailable" in the body), redirect
# drift onto a homepage, empty SPA shells, and WAF/login walls are demoted to
# `uncertain` — or promoted to `taken_down` when a removal notice is proven.
# This is what makes the active/taken_down buckets safe to trust unreviewed;
# turning it off restores the old "active by default" behaviour.
ENABLE_VERDICT_AUDIT        = _env_bool("ENABLE_VERDICT_AUDIT", default=True)
# When the audit finds an `active` unproven, re-check it in a real browser
# before settling on `uncertain`. Catches JS-rendered 404s and passes most WAFs.
ENABLE_AUDIT_ESCALATION     = _env_bool("ENABLE_AUDIT_ESCALATION", default=True)


# ── Temporal Confirmation ─────────────────────────────────────────────────────
# Industry practice: never trust a single observation for a "taken_down" verdict.
# A dead-looking or uncertain result is re-observed over a short jittered window;
# only a quorum of "down" observations confirms takedown. A single credible
# "active" observation always wins (active signals are high-confidence).
#   CONFIRM_ATTEMPTS — max observations for a dead/uncertain candidate
#   CONFIRM_QUORUM   — "down" votes required to confirm takedown (early-exits)
CONFIRM_ATTEMPTS           = max(1, int(os.environ.get("URLCHECK_CONFIRM_ATTEMPTS", "3")))
# Quorum can never exceed the number of observations taken — otherwise no
# takedown is confirmable and every dead URL silently lands in `uncertain`.
CONFIRM_QUORUM             = max(1, min(
    int(os.environ.get("URLCHECK_CONFIRM_QUORUM", "2")), CONFIRM_ATTEMPTS
))
CONFIRM_DELAY_MIN          = float(os.environ.get("URLCHECK_CONFIRM_DELAY_MIN", "2.0"))
CONFIRM_DELAY_MAX          = float(os.environ.get("URLCHECK_CONFIRM_DELAY_MAX", "4.0"))


# ── Proxy Rotation ────────────────────────────────────────────────────────────
# Optional pool of upstream proxies to vary the network vantage point. Rotating
# residential/geo exits defeats datacenter-IP bot walls and geo-restriction
# false positives — the biggest accuracy lever for social platforms in prod.
#   export URLCHECK_ENABLE_PROXY_ROTATION=true
#   export URLCHECK_PROXIES=http://user:pass@host1:port,http://user:pass@host2:port
PROXIES: list[str] = [
    p.strip() for p in os.environ.get("URLCHECK_PROXIES", "").split(",") if p.strip()
]


# ── Screenshot Evidence / OCR ─────────────────────────────────────────────────
# Fires only inside the Playwright fallback (the "uncertain" tier), never on the
# fast path. CAPTURE saves a timestamped PNG for defensible takedown evidence;
# OCR reads text off the rendered pixels so JS-injected / image-rendered removal
# notices (invisible to HTML phrase-matching) are still detected.
# OCR additionally requires the system 'tesseract' binary + pytesseract/Pillow.
SCREENSHOT_DIR = os.environ.get(
    "URLCHECK_SCREENSHOT_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence"),
)
# Viewable screenshots render a full browser page per URL — bound how many run
# at once so a large batch can't exhaust memory. Renders are the slow part when
# capture is enabled, so this is effectively the screenshot throughput knob.
SCREENSHOT_CONCURRENCY = int(os.environ.get("URLCHECK_SCREENSHOT_CONCURRENCY", "3"))
# JS-heavy pages render after domcontentloaded. Before shooting, wait up to
# SETTLE_MS for the network to idle, then a fixed PAINT_MS so SPA content (and
# not a blank/logo splash) is on screen. Raise these if captures still look bare.
SCREENSHOT_SETTLE_MS = int(os.environ.get("URLCHECK_SCREENSHOT_SETTLE_MS", "4000"))
SCREENSHOT_PAINT_MS = int(os.environ.get("URLCHECK_SCREENSHOT_PAINT_MS", "1200"))


# ── Playwright Render Settling ────────────────────────────────────────────────
# The browser tier used to read the DOM at `domcontentloaded`, before any JS had
# run. On React-rendered platforms (Facebook, Instagram, YouTube, X, LinkedIn)
# that returns a body containing only <script> tags — no removal notice, no
# profile name, nothing. Both verdicts drawn from it were therefore guesses.
# Wait for the page to actually paint before reading it:
#   SETTLE_MS   — how long to wait for network idle after DOMContentLoaded
#   TEXT_MIN    — body innerText length that counts as "rendered"
#   PAINT_MS    — final grace period for the last paint
PLAYWRIGHT_SETTLE_MS = int(os.environ.get("URLCHECK_PW_SETTLE_MS", "6000"))
PLAYWRIGHT_TEXT_MIN = int(os.environ.get("URLCHECK_PW_TEXT_MIN", "40"))
PLAYWRIGHT_PAINT_MS = int(os.environ.get("URLCHECK_PW_PAINT_MS", "600"))
# Browser renders had no concurrency cap (only screenshots did), so a 50-wide
# batch could open 50 Chromium contexts at once. The resulting contention made
# renders time out and return empty pages, which cost real verdicts: Scribd
# takedowns oscillated between `taken_down` and `uncertain` across runs.
PLAYWRIGHT_CONCURRENCY = int(os.environ.get("URLCHECK_PW_CONCURRENCY", "8"))


# ── Per-Host Concurrency Limits ───────────────────────────────────────────────
# Independent concurrency per social media host to prevent
# any single platform from starving others.

HOST_CONCURRENCY: dict[str, int] = {
    "facebook.com":   5,
    "m.facebook.com": 5,
    "instagram.com":  5,
    "linkedin.com":   3,
    # Cloudflare-fronted; more than a couple in flight triggers challenges that
    # hide the 410 + "Removal Notice" these documents actually return.
    "scribd.com":     2,
    "x.com":          5,
    "twitter.com":    5,
    "youtube.com":    8,
    "youtu.be":       8,
    "t.me":           10,
    "telegram.me":    10,
    "_default":       10,
}


# ── Circuit Breaker Configuration ─────────────────────────────────────────────

CIRCUIT_BREAKER_THRESHOLD  = int(os.environ.get("URLCHECK_CB_THRESHOLD", "5"))
CIRCUIT_BREAKER_COOLDOWN   = int(os.environ.get("URLCHECK_CB_COOLDOWN", "60"))


# ── Networking ────────────────────────────────────────────────────────────────

CONCURRENT_LIMIT           = int(os.environ.get("URLCHECK_CONCURRENT", "50"))
# curl_cffi is synchronous and runs in a thread pool. The stdlib default is only
# ~min(32, cpus+4) workers, which silently serializes curl-heavy platforms
# (Facebook/Instagram/LinkedIn/Scribd/X) below the concurrency limit. Size the
# pool to the concurrency so curl calls don't queue on threads.
CURL_THREAD_WORKERS        = int(os.environ.get("URLCHECK_CURL_THREADS", str(max(32, CONCURRENT_LIMIT))))
TIMEOUT_TOTAL              = float(os.environ.get("URLCHECK_TIMEOUT", "15"))
TCP_CONNECTOR_LIMIT        = int(os.environ.get("URLCHECK_TCP_LIMIT", "100"))
TCP_CONNECTOR_PER_HOST     = int(os.environ.get("URLCHECK_TCP_PER_HOST", "50"))
TCP_KEEPALIVE_TIMEOUT      = int(os.environ.get("URLCHECK_KEEPALIVE", "30"))


# ── CORS ─────────────────────────────────────────────────────────────────────
# Browser origins allowed to call the API. The bundled frontend is served from
# the same origin and needs no CORS entry; server-to-server callers (Java)
# ignore CORS entirely. Add origins only if the frontend is hosted separately:
#     export URLCHECK_ALLOWED_ORIGINS=https://validator.example.com,https://other.example.com

ALLOWED_ORIGINS: list[str] = [
    o.strip() for o in os.environ.get("URLCHECK_ALLOWED_ORIGINS", "").split(",") if o.strip()
]


# ── Helper ────────────────────────────────────────────────────────────────────

def get_all_flags() -> dict[str, Any]:
    """Return all feature flags as a dict (useful for /api/health)."""
    return {
        "confidence": ENABLE_CONFIDENCE,
        "evidence": ENABLE_EVIDENCE,
        "metrics": ENABLE_METRICS,
        "head_optimization": ENABLE_HEAD_OPTIMIZATION,
        "circuit_breaker": ENABLE_CIRCUIT_BREAKER,
        "adaptive_rate_limit": ENABLE_ADAPTIVE_RATE_LIMIT,
        "structured_logging": ENABLE_STRUCTURED_LOGGING,
        "parking_expansion": ENABLE_PARKING_EXPANSION,
        "error_classification": ENABLE_ERROR_CLASSIFICATION,
        "playwright_fallback": ENABLE_PLAYWRIGHT_FALLBACK,
        "temporal_confirmation": ENABLE_TEMPORAL_CONFIRMATION,
        "proxy_rotation": ENABLE_PROXY_ROTATION and bool(PROXIES),
        "screenshot_capture": ENABLE_SCREENSHOT_CAPTURE,
        "screenshot_ocr": ENABLE_SCREENSHOT_OCR,
        "stealth_headers": ENABLE_STEALTH_HEADERS,
        "referer_spoofing": ENABLE_REFERER_SPOOFING,
        "google_cache_verify": ENABLE_GOOGLE_CACHE_VERIFY,
        "wayback_verify": ENABLE_WAYBACK_VERIFY,
        "verdict_audit": ENABLE_VERDICT_AUDIT,
        "baseline_calibration": ENABLE_BASELINE_CALIBRATION,
        "audit_escalation": ENABLE_AUDIT_ESCALATION,
    }


# ── Baseline Calibration ──────────────────────────────────────────────────────
# When a verdict would otherwise be `uncertain`, ask the server what a
# definitely-missing URL looks like and compare. Costs two extra requests, but
# only for URLs that are already unresolved, and it converts a guess into a
# measurement. See backend/verify.classify_against_baseline.
ENABLE_BASELINE_CALIBRATION = _env_bool("ENABLE_BASELINE_CALIBRATION", default=True)
BASELINE_TIMEOUT = float(os.environ.get("URLCHECK_BASELINE_TIMEOUT", "12"))
