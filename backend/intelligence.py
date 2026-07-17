"""
Error Intelligence — Enterprise URL Validation Engine.

Classifies network/HTTP errors into standardized categories.
All outputs are metadata-only — they never affect status decisions.
"""

from __future__ import annotations


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

def classify_error(error: Exception | None = None,
                   http_status: int | None = None,
                   html: str = "",
                   headers: dict[str, str] | None = None) -> str | None:
    """
    Classify a network or HTTP error into a standardized category.

    Args:
        error: The exception raised (if any).
        http_status: HTTP response status code (if any).
        html: Response body (for challenge detection).
        headers: Response headers.

    Returns:
        Error classification string or None if no error detected.
        Values: DNS_ERROR, SSL_ERROR, TLS_HANDSHAKE, TIMEOUT, RATE_LIMITED,
                CLOUDFLARE_CHALLENGE, BOT_BLOCK, GEO_BLOCK, FIREWALL, WAF,
                CONNECTION_RESET, PROXY_BLOCK, AUTH_REQUIRED
    """
    if error:
        error_msg = str(error).lower()
        error_type = type(error).__name__.lower()

        # DNS errors
        if "getaddrinfo" in error_msg or "nodename" in error_msg or "dns" in error_msg:
            return "DNS_ERROR"

        # SSL/TLS errors
        if "ssl" in error_msg or "certificate" in error_msg:
            if "handshake" in error_msg:
                return "TLS_HANDSHAKE"
            return "SSL_ERROR"

        # Timeout
        if "timeout" in error_type or "timeout" in error_msg:
            return "TIMEOUT"

        # Connection reset
        if "reset" in error_msg or "broken pipe" in error_msg or "connection reset" in error_msg:
            return "CONNECTION_RESET"

        # Connection refused
        if "refused" in error_msg:
            return "FIREWALL"

        # Proxy errors
        if "proxy" in error_msg:
            return "PROXY_BLOCK"

    # HTTP status-based classification
    if http_status:
        if http_status == 429:
            return "RATE_LIMITED"
        if http_status == 401:
            return "AUTH_REQUIRED"
        if http_status == 403:
            # Check for Cloudflare challenge
            lower_html = html.lower() if html else ""
            h = {k.lower(): v for k, v in (headers or {}).items()}

            if "cf-ray" in h or "cf-chl-bypass" in h:
                return "CLOUDFLARE_CHALLENGE"
            if "captcha" in lower_html or "challenge-platform" in lower_html:
                return "CLOUDFLARE_CHALLENGE"
            if "just a moment" in lower_html and "cloudflare" in lower_html:
                return "CLOUDFLARE_CHALLENGE"
            if "access denied" in lower_html:
                return "WAF"

            return "BOT_BLOCK"

        if http_status == 451:
            return "GEO_BLOCK"

        if http_status == 999:
            return "BOT_BLOCK"

        if http_status in (502, 503, 504):
            return "FIREWALL"

    return None
