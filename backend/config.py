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
ENABLE_SELECTOLAX          = _env_bool("ENABLE_SELECTOLAX")
ENABLE_HTTP2               = _env_bool("ENABLE_HTTP2")
ENABLE_ADVANCED_DNS        = _env_bool("ENABLE_ADVANCED_DNS")
ENABLE_METRICS             = _env_bool("ENABLE_METRICS")
ENABLE_HEAD_OPTIMIZATION   = _env_bool("ENABLE_HEAD_OPTIMIZATION", default=False)
ENABLE_REDIRECT_ANALYSIS   = _env_bool("ENABLE_REDIRECT_ANALYSIS")
ENABLE_STRUCTURED_METADATA = _env_bool("ENABLE_STRUCTURED_METADATA")
ENABLE_HEADER_INTELLIGENCE = _env_bool("ENABLE_HEADER_INTELLIGENCE")
ENABLE_CIRCUIT_BREAKER     = _env_bool("ENABLE_CIRCUIT_BREAKER")
ENABLE_ADAPTIVE_RATE_LIMIT = _env_bool("ENABLE_ADAPTIVE_RATE_LIMIT", default=False)
ENABLE_STRUCTURED_LOGGING  = _env_bool("ENABLE_STRUCTURED_LOGGING")
ENABLE_PARKING_EXPANSION   = _env_bool("ENABLE_PARKING_EXPANSION")
ENABLE_ERROR_CLASSIFICATION = _env_bool("ENABLE_ERROR_CLASSIFICATION")
ENABLE_PLATFORM_METADATA   = _env_bool("ENABLE_PLATFORM_METADATA")
ENABLE_PLAYWRIGHT_FALLBACK  = _env_bool("ENABLE_PLAYWRIGHT_FALLBACK", default=True)


# ── Per-Host Concurrency Limits ───────────────────────────────────────────────
# Independent concurrency per social media host to prevent
# any single platform from starving others.

HOST_CONCURRENCY: dict[str, int] = {
    "facebook.com":   5,
    "m.facebook.com": 5,
    "instagram.com":  5,
    "linkedin.com":   3,
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
TIMEOUT_TOTAL              = float(os.environ.get("URLCHECK_TIMEOUT", "15"))
TCP_CONNECTOR_LIMIT        = int(os.environ.get("URLCHECK_TCP_LIMIT", "100"))
TCP_CONNECTOR_PER_HOST     = int(os.environ.get("URLCHECK_TCP_PER_HOST", "50"))
TCP_KEEPALIVE_TIMEOUT      = int(os.environ.get("URLCHECK_KEEPALIVE", "30"))
TCP_IDLE_TIMEOUT           = int(os.environ.get("URLCHECK_IDLE_TIMEOUT", "60"))


# ── CORS ─────────────────────────────────────────────────────────────────────
# Browser origins allowed to call the API. The bundled frontend is served from
# the same origin and needs no CORS entry; server-to-server callers (Java)
# ignore CORS entirely. Add origins only if the frontend is hosted separately:
#     export URLCHECK_ALLOWED_ORIGINS=https://validator.example.com,https://other.example.com

ALLOWED_ORIGINS: list[str] = [
    o.strip() for o in os.environ.get("URLCHECK_ALLOWED_ORIGINS", "").split(",") if o.strip()
]


# ── Retry Configuration ──────────────────────────────────────────────────────

RETRY_MAX_ATTEMPTS         = int(os.environ.get("URLCHECK_RETRY_MAX", "3"))
RETRY_BASE_DELAY           = float(os.environ.get("URLCHECK_RETRY_DELAY", "0.5"))
RETRY_MAX_DELAY            = float(os.environ.get("URLCHECK_RETRY_MAX_DELAY", "5.0"))

# HTTP status codes that trigger a retry (transient failures only)
RETRY_STATUS_CODES         = {429, 500, 502, 503, 504}
# HTTP status codes that are permanent failures (never retry)
NO_RETRY_STATUS_CODES      = {404, 410, 451}


# ── Helper ────────────────────────────────────────────────────────────────────

def get_all_flags() -> dict[str, Any]:
    """Return all feature flags as a dict (useful for /api/health)."""
    return {
        "confidence": ENABLE_CONFIDENCE,
        "evidence": ENABLE_EVIDENCE,
        "selectolax": ENABLE_SELECTOLAX,
        "http2": ENABLE_HTTP2,
        "advanced_dns": ENABLE_ADVANCED_DNS,
        "metrics": ENABLE_METRICS,
        "head_optimization": ENABLE_HEAD_OPTIMIZATION,
        "redirect_analysis": ENABLE_REDIRECT_ANALYSIS,
        "structured_metadata": ENABLE_STRUCTURED_METADATA,
        "header_intelligence": ENABLE_HEADER_INTELLIGENCE,
        "circuit_breaker": ENABLE_CIRCUIT_BREAKER,
        "adaptive_rate_limit": ENABLE_ADAPTIVE_RATE_LIMIT,
        "structured_logging": ENABLE_STRUCTURED_LOGGING,
        "parking_expansion": ENABLE_PARKING_EXPANSION,
        "error_classification": ENABLE_ERROR_CLASSIFICATION,
        "platform_metadata": ENABLE_PLATFORM_METADATA,
        "playwright_fallback": ENABLE_PLAYWRIGHT_FALLBACK,
    }
