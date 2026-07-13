"""
HTTP Header, Redirect & Error Intelligence — Enterprise URL Validation Engine.

Provides three classification engines:
  1. Header Intelligence — Detects CDN, WAF, hosting from HTTP headers
  2. Redirect Classifier — Classifies each redirect hop type
  3. Error Classifier — Classifies network/HTTP errors into categories

All outputs are metadata-only — they never affect status decisions.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HEADER INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

# Maps header values → provider name
_CDN_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    # header_name → [(substring_to_match, provider_name), ...]
    "server": [
        ("cloudflare", "Cloudflare"),
        ("cloudfront", "CloudFront"),
        ("netlify", "Netlify"),
        ("vercel", "Vercel"),
        ("github.com", "GitHub Pages"),
        ("fastly", "Fastly"),
        ("akamai", "Akamai"),
        ("sucuri", "Sucuri"),
        ("imperva", "Imperva"),
        ("azure", "Azure"),
        ("gws", "Google"),
        ("openresty", "OpenResty"),
        ("tengine", "Tengine/Alibaba"),
        ("litespeed", "LiteSpeed"),
    ],
    "via": [
        ("cloudfront", "CloudFront"),
        ("akamai", "Akamai"),
        ("fastly", "Fastly"),
        ("varnish", "Varnish"),
    ],
    "x-powered-by": [
        ("express", "Express.js"),
        ("asp.net", "ASP.NET"),
        ("php", "PHP"),
        ("next.js", "Next.js"),
    ],
}

# Special headers that indicate specific providers
_SPECIAL_HEADERS: dict[str, str] = {
    "cf-ray":           "Cloudflare",
    "cf-cache-status":  "Cloudflare",
    "x-amz-cf-id":     "CloudFront",
    "x-amz-request-id": "AWS",
    "x-vercel-id":      "Vercel",
    "x-nf-request-id":  "Netlify",
    "x-github-request-id": "GitHub",
    "x-fastly-request-id": "Fastly",
    "x-served-by":      "Fastly",
    "x-azure-ref":      "Azure",
    "x-ms-request-id":  "Azure",
    "x-sucuri-id":      "Sucuri",
}


def detect_infrastructure(headers: dict[str, str]) -> dict[str, str | None]:
    """
    Analyze HTTP response headers to detect CDN, WAF, server, and hosting provider.

    Args:
        headers: HTTP response headers (case-insensitive keys).

    Returns:
        Dict with keys: server, cdn, waf, hosting (values may be None).
    """
    result: dict[str, str | None] = {
        "server": None,
        "cdn": None,
        "waf": None,
        "hosting": None,
    }

    # Normalize headers to lowercase keys
    h = {k.lower(): v for k, v in headers.items()}

    # Check server header
    server = h.get("server", "")
    if server:
        result["server"] = server[:50]  # Truncate long values

    # Check CDN signatures in standard headers
    for header_name, signatures in _CDN_SIGNATURES.items():
        header_val = h.get(header_name, "").lower()
        if header_val:
            for substring, provider in signatures:
                if substring in header_val:
                    if header_name == "server":
                        result["cdn"] = provider
                    break

    # Check special provider headers
    for header_name, provider in _SPECIAL_HEADERS.items():
        if header_name in h:
            result["cdn"] = result["cdn"] or provider
            break

    # WAF detection
    if "cf-ray" in h:
        result["waf"] = result["waf"] or "Cloudflare"
    if any(k.startswith("x-sucuri") for k in h):
        result["waf"] = "Sucuri"
    if any(k.startswith("x-iinfo") for k in h):
        result["waf"] = "Imperva"

    # Hosting detection
    if "x-vercel-id" in h:
        result["hosting"] = "Vercel"
    elif "x-nf-request-id" in h:
        result["hosting"] = "Netlify"
    elif "x-github-request-id" in h:
        result["hosting"] = "GitHub Pages"
    elif "x-azure-ref" in h:
        result["hosting"] = "Azure"
    elif "x-amz-request-id" in h:
        result["hosting"] = "AWS"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 2. REDIRECT CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

def classify_redirect(from_url: str, to_url: str) -> str:
    """
    Classify a single redirect hop.

    Args:
        from_url: URL before redirect.
        to_url: URL after redirect.

    Returns:
        Classification string, one of:
        - "http_to_https"
        - "www_normalize"
        - "language_redirect"
        - "country_redirect"
        - "tracking_redirect"
        - "cdn_redirect"
        - "parking_redirect"
        - "cross_domain"
        - "path_redirect"
        - "same_domain"
    """
    from_parsed = urlparse(from_url)
    to_parsed = urlparse(to_url)

    from_host = (from_parsed.hostname or "").lower()
    to_host = (to_parsed.hostname or "").lower()
    from_scheme = from_parsed.scheme.lower()
    to_scheme = to_parsed.scheme.lower()

    # HTTP → HTTPS upgrade
    if from_scheme == "http" and to_scheme == "https" and from_host == to_host:
        return "http_to_https"

    # www normalization
    if from_host == f"www.{to_host}" or to_host == f"www.{from_host}":
        return "www_normalize"

    # Same domain, different path
    if from_host == to_host:
        to_path = to_parsed.path.lower()

        # Language redirect (e.g., /en/, /en-us/, /fr/)
        if re.match(r"^/[a-z]{2}(-[a-z]{2})?(/|$)", to_path):
            return "language_redirect"

        # Login/auth redirect
        if any(x in to_path for x in ("/login", "/signin", "/auth", "/accounts/login")):
            return "auth_redirect"

        return "path_redirect"

    # Cross-domain analysis
    from_base = _extract_base_domain(from_host)
    to_base = _extract_base_domain(to_host)

    if from_base == to_base:
        # Same base domain (e.g., m.facebook.com → www.facebook.com)
        return "subdomain_redirect"

    # Known parking domains
    from backend.parking import PARKING_DOMAINS
    if any(pd in to_host for pd in PARKING_DOMAINS):
        return "parking_redirect"

    # Known CDN/tracking domains
    _CDN_HOSTS = {"cdn.", "static.", "assets.", "media.", "img."}
    if any(to_host.startswith(prefix) for prefix in _CDN_HOSTS):
        return "cdn_redirect"

    # Country redirect (different TLD, same brand)
    from_tld = from_host.split(".")[-1]
    to_tld = to_host.split(".")[-1]
    if from_tld != to_tld and from_base.split(".")[0] == to_base.split(".")[0]:
        return "country_redirect"

    # Tracking redirect
    _TRACKING_HOSTS = ["bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly",
                       "buff.ly", "lnkd.in", "fb.me", "rebrand.ly"]
    if from_host in _TRACKING_HOSTS or to_host in _TRACKING_HOSTS:
        return "tracking_redirect"

    return "cross_domain"


def classify_redirect_chain(chain: list[str], final_url: str) -> list[str]:
    """
    Classify each hop in a redirect chain.

    Args:
        chain: List of intermediate URLs (from _fetch_with_redirect_chain).
        final_url: The final URL after all redirects.

    Returns:
        List of classification strings, one per hop.
    """
    if not chain:
        return []

    classifications: list[str] = []
    urls = chain + [final_url]

    for i in range(len(urls) - 1):
        cls = classify_redirect(urls[i], urls[i + 1])
        classifications.append(cls)

    return classifications


def _extract_base_domain(hostname: str) -> str:
    """Extract base domain (e.g., 'sub.example.co.uk' → 'example.co.uk')."""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # Handle two-part TLDs like .co.uk, .com.au
    if len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ERROR CLASSIFIER
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
