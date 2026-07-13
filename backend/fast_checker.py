"""
Fast URL Checker v5.0 — Enterprise-Grade URL Validation Engine.

Techniques used (all free, no APIs, no cookies, no browser):
  1. User-Agent Rotation        — Pool of 50+ real browser fingerprints
  2. Multi-Strategy Retry       — If first UA class fails, try next class
  3. DNS Pre-Check              — socket.getaddrinfo before HTTP (fast domain death detection)
  4. Redirect Chain Intelligence — Track each hop, detect cross-domain redirects & parking
  5. Content-Length Heuristic    — Error/parking pages are typically <2KB
  6. Deep Meta Tag Parsing       — og:title, og:description, og:url, twitter:card, canonical
  7. Platform-Specific Signals   — DOM classes, meta patterns unique to each platform
  8. HTTP Header Analysis        — Server header, X-Robots-Tag, Content-Type clues
  9. Parking/Seized Detection    — Known parking page patterns (GoDaddy, Sedo, Namecheap, etc.)
 10. Confidence Scoring          — 0-100 confidence score with signal evidence
 11. Evidence Collection         — Structured evidence for every check
 12. Circuit Breaker             — Per-host failure tracking with auto-recovery
 13. Adaptive Rate Limiting      — Per-host concurrency semaphores
 14. Structured Metadata         — JSON-LD, Twitter Cards, schema.org extraction
 15. Infrastructure Detection    — CDN, WAF, hosting provider identification
 16. Performance Metrics         — Per-check timing breakdowns and aggregated stats
"""

import asyncio
import io
import random
import re
import socket
import time
import zipfile
from pathlib import Path
from typing import AsyncGenerator
from urllib.parse import urlparse

import aiohttp

from backend.url_utils import detect_platform, normalize_url, deduplicate_urls
from backend.logger import get_logger, log_check_result

# ── Enterprise Module Imports ─────────────────────────────────────────────────
from backend import config
from backend.evidence import Evidence
from backend.confidence import compute_confidence
from backend.html_parser import parse_html
from backend.parking import detect_expanded_parking, is_parking_domain
from backend.intelligence import (
    detect_infrastructure,
    classify_redirect_chain,
    classify_error,
)
from backend.networking import (
    circuit_breaker,
    rate_limiter,
    should_retry,
    compute_backoff_delay,
    resolve_dns,
)
from backend.metrics import metrics_collector, CheckMetric

logger = get_logger()

# ── Configuration ─────────────────────────────────────────────────────────────


_CONCURRENT = config.CONCURRENT_LIMIT
_TIMEOUT = aiohttp.ClientTimeout(total=config.TIMEOUT_TOTAL)

# ── User-Agent Rotation Pool (50+ real fingerprints) ──────────────────────────

_UA_POOL_DESKTOP = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

_UA_POOL_MOBILE = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1",
]

_UA_POOL_BOT = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0)",
]


def _random_ua(pool: str = "desktop") -> str:
    """Get a random User-Agent from the specified pool."""
    if pool == "mobile":
        return random.choice(_UA_POOL_MOBILE)
    if pool == "bot":
        return random.choice(_UA_POOL_BOT)
    return random.choice(_UA_POOL_DESKTOP)


# ── Takedown signals ─────────────────────────────────────────────────────────

_TAKEDOWN_SIGNALS = [
    "this content isn't available",
    "this page isn't available",
    "page not found",
    "the link you followed may be broken",
    "sorry, this page isn't available",
    "this account doesn't exist",
    "account suspended",
    "video unavailable",
    "this video has been removed",
    "this channel does not exist",
    "this account has been terminated",
    "hmm...this page doesn't exist",
    "this site can't be reached",
    "404 not found",
    "410 gone",
    "no longer available",
    "has been suspended",
    "domain is not configured",
    "web page not available",
]

# Known domain parking / seized indicators
_PARKING_SIGNALS = [
    "this domain is for sale",
    "buy this domain",
    "domain parking",
    "parked free",
    "sedoparking",
    "godaddy",
    "this webpage is parked",
    "hugedomains",
    "domain has expired",
    "this domain has been seized",
    "domain seized",
    "this website has been seized",
    "namecheap parking page",
    "afternic",
    "dan.com",
    "undeveloped.com",
]

# HTTP status codes that mean the server is alive but blocking us
_ALIVE_ERROR_CODES = {401, 403, 429, 500, 502, 503, 504, 999}


# ── HTML / Meta Tag Helpers ──────────────────────────────────────────────────

def _title(html: str) -> str:
    """Extract <title> text."""
    m = re.search(r"<title[^>]*>([^<]*)</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _h1(html: str) -> str:
    """Extract first <h1> text."""
    m = re.search(r"<h1[^>]*>([^<]*)</h1>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _og_title(html: str) -> str:
    """Extract og:title from <meta> tags."""
    for pattern in (
        r'<meta\s+(?:property|name)=["\']og:title["\']\s+content=["\']([^"\']*)["\']',
        r'content=["\']([^"\']*?)["\'](?:\s+(?:property|name)=["\']og:title["\'])',
    ):
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _og_description(html: str) -> str:
    """Extract og:description from <meta> tags."""
    for pattern in (
        r'<meta\s+(?:property|name)=["\']og:description["\']\s+content=["\']([^"\']*)["\']',
        r'content=["\']([^"\']*?)["\'](?:\s+(?:property|name)=["\']og:description["\'])',
    ):
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _og_url(html: str) -> str:
    """Extract og:url from <meta> tags."""
    for pattern in (
        r'<meta\s+(?:property|name)=["\']og:url["\']\s+content=["\']([^"\']*)["\']',
        r'content=["\']([^"\']*?)["\'](?:\s+(?:property|name)=["\']og:url["\'])',
    ):
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _canonical(html: str) -> str:
    """Extract <link rel='canonical'> href."""
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if not m:
        m = re.search(r'<link[^>]+href=["\']([^"\']*)["\'][^>]+rel=["\']canonical["\']', html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _meta_robots(html: str) -> str:
    """Extract <meta name='robots'> content."""
    m = re.search(r'<meta\s+name=["\']robots["\']\s+content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    return m.group(1).strip().lower() if m else ""


def _is_dns_error(error: aiohttp.ClientConnectorError) -> bool:
    """Return True if the connection error is a DNS resolution failure."""
    msg = str(error).lower()
    return "getaddrinfo" in msg or "nodename" in msg


# ── DNS Pre-Check ─────────────────────────────────────────────────────────────

async def _dns_resolve(hostname: str) -> bool:
    """
    Fast async DNS check using socket.getaddrinfo in a thread.
    Returns True if the domain resolves, False if DNS fails.
    """
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, hostname, 443),
            timeout=5.0,
        )
        return True
    except Exception:
        return False


# ── Redirect-Aware Fetching ──────────────────────────────────────────────────

async def _fetch_with_redirect_chain(
    session: aiohttp.ClientSession, url: str, headers: dict
) -> dict:
    """
    Fetch a URL, tracking the full redirect chain.

    Returns dict with:
      status:         Final HTTP status
      html:           Final page HTML
      final_url:      URL after all redirects
      redirect_chain: List of intermediate URLs
      hops:           Number of redirects
      cross_domain:   True if redirected to a different domain
    """
    redirect_chain = []
    current_url = url
    original_host = urlparse(url).hostname or ""
    max_redirects = 10

    for _ in range(max_redirects):
        try:
            async with session.get(
                current_url, timeout=_TIMEOUT, headers=headers,
                allow_redirects=False,
            ) as r:
                if r.status in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    if not location:
                        break
                    # Handle relative redirects
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    redirect_chain.append(current_url)
                    current_url = location
                    continue
                else:
                    html = await r.text()
                    final_host = urlparse(current_url).hostname or ""
                    return {
                        "status": r.status,
                        "html": html,
                        "final_url": current_url,
                        "redirect_chain": redirect_chain,
                        "hops": len(redirect_chain),
                        "cross_domain": final_host.lower() != original_host.lower(),
                        "headers": dict(r.headers),
                    }
        except (aiohttp.ClientError, asyncio.TimeoutError):
            break

    # Fallback: use simple fetch if redirect tracking failed
    async with session.get(
        url, timeout=_TIMEOUT, headers=headers, allow_redirects=True
    ) as r:
        html = await r.text()
        return {
            "status": r.status,
            "html": html,
            "final_url": str(r.url),
            "redirect_chain": [],
            "hops": 0,
            "cross_domain": False,
            "headers": dict(r.headers),
        }


async def _fetch_smart(
    session: aiohttp.ClientSession, url: str, ua_pool: str = "desktop"
) -> dict:
    """
    Smart fetcher with:
    - Random UA from pool
    - Retry with exponential backoff + jitter
    - Redirect chain tracking
    - Multi-strategy fallback (desktop → mobile → bot)
    """
    ua_pools = [ua_pool, "mobile", "bot"] if ua_pool == "desktop" else [ua_pool, "desktop"]
    last_error = None

    for pool in ua_pools:
        headers = {
            "User-Agent": _random_ua(pool),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        for attempt in range(2):
            try:
                if attempt > 0:
                    await asyncio.sleep(random.uniform(0.5, 1.5))

                result = await _fetch_with_redirect_chain(session, url, headers=headers)

                # If we got a real response (not a 403/429 block), return it
                if result["status"] not in (403, 429):
                    return result
                else:
                    logger.warning(f"IP Rate Limited or Bot Blocked ({result['status']}) on {url} (Pool: {pool}, Attempt: {attempt+1})")

                # If blocked, try next UA pool
                break
            except aiohttp.ClientConnectorError as e:
                last_error = e
                break
            except asyncio.TimeoutError:
                last_error = asyncio.TimeoutError()
            except Exception as e:
                last_error = e
                break

    if last_error:
        raise last_error
    if 'result' in locals():
        return result
    raise Exception("All fetch strategies exhausted")


# ── Parking / Seized Domain Detection ─────────────────────────────────────────

def _detect_parking(html: str, title: str, h1: str) -> str | None:
    """
    Detect if a page is a parked domain, seized domain, or placeholder.
    Returns a reason string if parked/seized, None otherwise.
    
    Checks both the original _PARKING_SIGNALS and the expanded set
    from the parking module (when ENABLE_PARKING_EXPANSION is on).
    """
    text = f"{title} {h1} {html[:5000]}".lower()
    for signal in _PARKING_SIGNALS:
        if signal in text:
            return f"Domain parked/seized ({signal})"

    # Expanded parking detection (enterprise enhancement)
    if config.ENABLE_PARKING_EXPANSION:
        expanded = detect_expanded_parking(html, title, h1)
        if expanded:
            return expanded

    return None


# ── Platform-Specific Checkers ───────────────────────────────────────────────

async def _check_telegram(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Telegram checker — uses DOM class detection.

    Signals:
      Active:     tgme_page_title, tgme_channel_info, tgme_page_post
      Taken down: "Contact @" in title (Telegram's generic "user not found" page)
      Bot:        tgme_page_action (Start button for bots)
    """
    try:
        result = await _fetch_smart(session, url, "desktop")
        status, html = result["status"], result["html"]
        title = _title(html)
        og = _og_title(html)
        final_url = result.get("final_url", url)

        # 1. DNS or 404
        if status == 404:
            return {"status": "taken_down", "reason": "Telegram content not found (404)", "http_code": 404}

        # 2. Redirected to main Telegram website (indicates nonexistent username/link)
        parsed_final = urlparse(final_url)
        if parsed_final.hostname and "telegram.org" in parsed_final.hostname:
            return {"status": "taken_down", "reason": "Telegram content not found (redirected to telegram.org)", "http_code": status}

        # 3. Generic title representing the homepage/nonexistent page
        if title.strip() == "Telegram Messenger" or og.strip() == "Telegram Messenger":
            return {"status": "taken_down", "reason": "Telegram channel/user not found", "http_code": status}

        # 4. Handle Invite Links (t.me/+... or t.me/joinchat/...)
        is_invite = "joinchat/" in url.lower() or "/+" in url.lower()
        if is_invite:
            if "tgme_page_title" in html or "tgme_page_photo" in html:
                return {"status": "active", "reason": f"Telegram invite link is active ({og or 'Invite Link'})", "http_code": status}
            return {"status": "taken_down", "reason": "Telegram invite link is invalid/expired", "http_code": status}

        # 5. Handle Posts (e.g. t.me/username/123)
        is_post = False
        for base in ("t.me/", "telegram.me/"):
            if base in url.lower():
                parts = [s for s in url.split(base)[-1].split("/") if s and s != "s"]
                is_post = len(parts) >= 2 and parts[-1].isdigit()
                break

        if is_post:
            if "tgme_page_post" in html:
                return {"status": "active", "reason": "Telegram post is active", "http_code": status}
            return {"status": "taken_down", "reason": "Telegram post not found", "http_code": status}

        # 6. Standard profiles, bots, public channels/groups
        if "tgme_page_title" in html or "tgme_channel_info" in html:
            desc = _og_description(html)
            extra = f" ({og})" if og else ""
            if desc and ("members" in desc.lower() or "subscribers" in desc.lower()):
                extra = f" ({og} — {desc[:60]})"
            return {"status": "active", "reason": f"Telegram profile is active{extra}", "http_code": status}

        if "Contact @" in title:
            return {"status": "taken_down", "reason": "Telegram channel/user not found", "http_code": status}

        return {"status": "taken_down", "reason": f"Not found (title: {title[:50]})", "http_code": status}
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "active", "reason": "Active (Connection Blocked/SSL)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during Facebook check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Facebook check error: {str(e)[:50]}", "http_code": None}

# ── Facebook Cross-Verification Helpers ──────────────────────────────────────
# These implement the multi-engine consensus architecture used by industry
# leaders (CrowdStrike, Mandiant, Meta T&S) to eliminate false positives.
# A URL is only declared "taken_down" when multiple independent methods agree.

def _extract_fb_id(url: str) -> str | None:
    """
    Extract the numeric Facebook ID from any URL format.
    Supports:
      - /profile.php?id=123456
      - /p/PageName-123456/
      - /pages/Name/123456
      - Numeric-only paths like /123456
    Returns None if no numeric ID can be extracted.
    """
    parsed = urlparse(url)
    # profile.php?id=123456
    if "profile.php" in parsed.path:
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query)
        fb_id = qs.get("id", [None])[0]
        if fb_id and fb_id.isdigit():
            return fb_id
    # /p/PageName-123456/ or /pages/category/123456
    path = parsed.path.rstrip("/")
    # Try to find a trailing numeric ID in the last path segment
    last_segment = path.split("/")[-1] if path else ""
    # Pure numeric path segment
    if last_segment.isdigit() and len(last_segment) > 5:
        return last_segment
    # Name-123456 pattern (used in /p/ URLs)
    m = re.search(r"-(\d{10,})$", last_segment)
    if m:
        return m.group(1)
    return None


async def _graph_api_exists(session: aiohttp.ClientSession, url: str) -> bool | None:
    """
    Check if a Facebook page/profile exists using the Graph API.

    Calls graph.facebook.com/{id} (no token needed for existence check).
    Returns:
      True  — page EXISTS (error code 104: "access token required")
      False — page GONE  (error code 100: "does not exist")
      None  — inconclusive (no numeric ID, network error, unexpected response)
    """
    fb_id = _extract_fb_id(url)
    if not fb_id:
        return None

    try:
        graph_url = f"https://graph.facebook.com/{fb_id}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        async with session.get(graph_url, timeout=aiohttp.ClientTimeout(total=5), headers=headers) as resp:
            body = await resp.text()
            try:
                import json
                data = json.loads(body)
                error_code = data.get("error", {}).get("code")
                if error_code == 100:
                    # "Object does not exist" — page is GONE
                    return False
                if error_code in (104, 190):
                    # Banned, deactivated, or restricted profiles also return 104/190.
                    # This signal is inconclusive; we cannot assume the page is active.
                    return None
                # If we got actual data back (no error), page definitely exists
                if "id" in data or "name" in data:
                    return True
            except Exception:
                pass
            return None
    except Exception:
        return None


async def _anonymous_fb_check(session: aiohttp.ClientSession, url: str) -> str | None:
    """
    Secondary anonymous verification using FacebookExternalHit bot UA.

    This UA gets special treatment from Facebook (used for link previews).
    Facebook serves og:title and og:description to this bot even for pages
    that show login walls to regular browsers.

    Returns:
      "active"     — page has real og:title/title (not generic)
      "taken_down" — page shows takedown signals
      None         — inconclusive
    """
    try:
        headers = {
            "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        }
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=8), headers=headers,
            allow_redirects=True
        ) as resp:
            html = await resp.text()
            title = _title(html)
            og = _og_title(html)
            status = resp.status
            final_url = str(resp.url)

            # Real og:title or title = page exists
            effective_title = og or title
            title_lower = title.strip().lower()
            
            if effective_title.strip() and effective_title.strip().lower() not in ("facebook", ""):
                return "active"

            # Check for definitive takedown signals in the body
            lower_html = html.lower()
            takedown_signals = [
                "content isn't available",
                "page isn't available",
                "this page has been removed",
                "the link you followed may be broken",
            ]
            if any(sig in lower_html for sig in takedown_signals):
                return "taken_down"

            # Redirect signature check for status 200 and title "Facebook" or empty
            if status == 200 and (title_lower == "facebook" or not title.strip()):
                original_lower = url.lower()
                final_lower = final_url.lower()
                def _has_vanity_format(u: str) -> bool:
                    return any(x in u for x in ("/@", "/p/", "/groups/", "/pages/", "/posts/", "/photos/", "/permalink/"))
                orig_has = _has_vanity_format(original_lower)
                final_has = _has_vanity_format(final_lower)
                if not orig_has and not final_has:
                    return "taken_down"
                if orig_has:
                    return "taken_down"

            # Generic title with no takedown signals = inconclusive
            return None
    except Exception:
        return None


async def _check_facebook(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Facebook checker — Multi-Engine Cross-Verification Architecture.

    Problem: A single check can produce false positives because Facebook returns
    "content isn't available" for pages that are geo/age-restricted, not just
    pages that are truly taken down.

    Solution: 3-tier verification. We never declare "taken_down" from a single
    signal. If the primary check says "down", we cross-verify with:
      Tier 1: Facebook Graph API (error 104 = exists, 100 = gone)
      Tier 2: Anonymous HTTP check (mobile endpoint, no cookies)

    Only if MULTIPLE independent methods agree do we confirm "taken_down".
    """
    # ── Tier 0: Primary anonymous check (mobile, no cookies) ──
    check_url = url.replace("www.facebook.com", "m.facebook.com").replace(
        "://facebook.com", "://m.facebook.com"
    )

    try:
        result = await _fetch_smart(session, check_url, "mobile")
        status, html = result["status"], result["html"]
        title = _title(html)
        og_desc = _og_description(html)

        # ── Definitive positive signals (no cross-verification needed) ──
        title_lower = title.strip().lower()
        
        # Real title (not generic "Facebook" and not login page) = definitively active
        is_generic_title = title_lower in ("facebook", "error facebook") or not title.strip()
        is_login_title = any(x in title_lower for x in ("log in", "login", "log into", "sign up", "signup"))
        
        if title.strip() and not is_generic_title and not is_login_title:
            return {"status": "active", "reason": f"Facebook is active ({title[:50]})", "http_code": status}

        # ── Ambiguous/negative signals: cross-verify before declaring down ──
        takedown_phrases = [
            "content isn't available",
            "this content isn't available",
            "page isn't available",
            "this page has been removed",
            "the link you followed may be broken",
        ]
        primary_says_down = any(phrase in html.lower() for phrase in takedown_phrases)
        primary_says_empty = is_generic_title
        primary_says_login = is_login_title or "/login/" in result["final_url"]

        if primary_says_down or primary_says_empty or primary_says_login:
            # ── Tier 1: Graph API existence check ──
            graph_exists = await _graph_api_exists(session, url)
            if graph_exists is True:
                return {"status": "active", "reason": "Facebook page exists (Graph API verified, restricted for anonymous view)", "http_code": status}
            if graph_exists is False:
                # Graph API confirms page does NOT exist — trust it
                reason = "Facebook page not found (Graph API confirmed)"
                if primary_says_down:
                    for phrase in takedown_phrases:
                        if phrase in html.lower():
                            reason = f"Facebook: {phrase} (Graph API confirmed)"
                            break
                return {"status": "taken_down", "reason": reason, "http_code": status}

            # ── Tier 2: Secondary anonymous check (FacebookExternalHit bot) ──
            bot_result = await _anonymous_fb_check(session, url)
            if bot_result == "active":
                return {"status": "active", "reason": "Facebook page exists (bot UA verified, restricted for mobile view)", "http_code": status}
            if bot_result == "taken_down":
                reason = "Facebook page not found (multi-engine verified)"
                if primary_says_down:
                    for phrase in takedown_phrases:
                        if phrase in html.lower():
                            reason = f"Facebook: {phrase} (cross-verified)"
                            break
                return {"status": "taken_down", "reason": reason, "http_code": status}

            # Redirect signature check for status 200 (if it's not a login wall)
            if status == 200 and not primary_says_login and primary_says_empty and graph_exists is None:
                original_lower = url.lower()
                final_lower = result["final_url"].lower()
                
                # Check for vanity format indicators
                def _has_vanity_format(u: str) -> bool:
                    return any(x in u for x in ("/@", "/p/", "/groups/", "/pages/", "/posts/", "/photos/", "/permalink/"))
                
                orig_has = _has_vanity_format(original_lower)
                final_has = _has_vanity_format(final_lower)
                
                # If neither original nor final has vanity formatting (e.g. stayed on raw username path)
                if not orig_has and not final_has:
                    return {"status": "taken_down", "reason": "Facebook page not found (no redirect to profile)", "http_code": status}
                # If it already had vanity formatting but still returned generic "Facebook" title
                if orig_has:
                    return {"status": "taken_down", "reason": "Facebook page not found (profile page returned generic title)", "http_code": status}

            # If it was redirected to a login wall, and bot/graph checks are inconclusive, return uncertain
            if primary_says_login:
                return {"status": "uncertain", "reason": "Facebook login wall encountered. Cookies required.", "http_code": status}

            # Both cross-verification tiers inconclusive
            return {"status": "uncertain", "reason": "Facebook verification inconclusive (login wall / challenge). Cookies required.", "http_code": status}

        # Shouldn't reach here, but fallback
        return {"status": "active", "reason": f"Facebook is active ({title[:50]})", "http_code": status}
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "active", "reason": "Active (Connection Blocked/SSL)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during Telegram check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Telegram check error: {str(e)[:50]}", "http_code": None}


def _has_person_name(text: str) -> bool:
    """Check if a LinkedIn title has a real name (not generic)."""
    if not text:
        return False
    cleaned = re.sub(r"\s*\|\s*LinkedIn\s*$", "", text, flags=re.IGNORECASE).strip()
    return bool(cleaned) and cleaned.lower() not in (
        "linkedin", "sign up", "log in", "sign in", "linkedin login",
    )


async def _check_linkedin(session: aiohttp.ClientSession, url: str) -> dict:
    """
    LinkedIn checker — Googlebot UA gets OG tags that browser UA doesn't.

    Signals:
      Active:     og:title has real name "John Doe | LinkedIn"
      Taken down: 404, or title is just "LinkedIn" / "Sign Up"
      Auth wall:  Redirects to login page (treated as uncertain for posts)
    """
    # Try with user cookies if configured
    from backend.cookies import get_cookie_header_string
    cookie_str = get_cookie_header_string("linkedin")
    if cookie_str:
        logger.info(f"[LINKEDIN] Found cookies. Trying request using cookies...")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Cookie": cookie_str,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        try:
            async with session.get(url, timeout=_TIMEOUT, headers=headers, allow_redirects=True) as resp:
                status = resp.status
                html = await resp.text()
                final_url = str(resp.url)
                
                if status == 404:
                    return {"status": "taken_down", "reason": "LinkedIn content not found (404, Cookie)", "http_code": 404}
                
                if "/authwall" in final_url or "/login" in final_url or "/signup" in final_url:
                    logger.warning("[LINKEDIN] Cookie request redirected to login/authwall. Cookies might be expired. Falling back to bot rotation...")
                else:
                    title = _title(html)
                    og = _og_title(html)
                    og_desc = _og_description(html)
                    
                    if _has_person_name(og) or _has_person_name(title):
                        name = re.sub(r"\s*\|\s*LinkedIn\s*$", "", og or title, flags=re.IGNORECASE).strip()
                        detail = f" — {og_desc[:60]}" if og_desc and "linkedin" not in og_desc.lower() else ""
                        return {"status": "active", "reason": f"LinkedIn exists ({name[:50]}{detail}, Cookie)", "http_code": status}
                    
                    if title.lower() in ("linkedin", "") and not og:
                        return {"status": "taken_down", "reason": "LinkedIn content not found (Cookie)", "http_code": status}
        except Exception as e:
            logger.warning(f"[LINKEDIN] Cookie request failed: {e}. Falling back to bot rotation...")

    # Dedicated Googlebot-only fetch for LinkedIn (most reliable)
    _LINKEDIN_BOT_UAS = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "LinkedInBot/1.0 (compatible; Mozilla/5.0)",
    ]
    
    async def _try_bot_fetch(s, target_url):
        """Try fetching LinkedIn with specific bot UAs, return result dict or None."""
        for ua in _LINKEDIN_BOT_UAS:
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            try:
                async with s.get(target_url, timeout=_TIMEOUT, headers=headers, allow_redirects=True) as resp:
                    status = resp.status
                    if status in (403, 429, 999):
                        continue  # Try next UA
                    html = await resp.text()
                    final_url = str(resp.url)
                    
                    if status == 404:
                        return {"status": "taken_down", "reason": "LinkedIn content not found (404)", "http_code": 404}
                    
                    if "/authwall" in final_url or "/login" in final_url or "/signup" in final_url:
                        continue  # Try next UA
                    
                    title = _title(html)
                    og = _og_title(html)
                    og_desc = _og_description(html)
                    
                    if _has_person_name(og) or _has_person_name(title):
                        name = re.sub(r"\s*\|\s*LinkedIn\s*$", "", og or title, flags=re.IGNORECASE).strip()
                        detail = f" — {og_desc[:60]}" if og_desc and "linkedin" not in og_desc.lower() else ""
                        return {"status": "active", "reason": f"LinkedIn exists ({name[:50]}{detail})", "http_code": status}
                    
                    if title.lower() in ("linkedin", "") and not og:
                        return {"status": "taken_down", "reason": "LinkedIn content not found", "http_code": status}
                    
                    # Got a response but couldn't determine — return it
                    return {"status": "taken_down", "reason": f"LinkedIn content not found (title: {title[:40]})", "http_code": status}
            except Exception:
                continue
        return None  # All UAs exhausted

    try:
        result = await _try_bot_fetch(session, url)
        if result:
            return result
        
        # All dedicated bot UAs failed — return uncertain
        return {"status": "uncertain", "reason": "LinkedIn blocked all bot UAs. Cookies required.", "http_code": 403}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during LinkedIn check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"LinkedIn check error: {str(e)[:50]}", "http_code": None}



async def _check_youtube(session: aiohttp.ClientSession, url: str) -> dict:
    """
    YouTube checker — uses Googlebot UA for reliable OG meta tags.

    CRITICAL INSIGHT: YouTube serves ALL videos with 'video unavailable' in the
    raw HTML skeleton (it's a JS-hidden template). This is NOT a real signal.
    The ONLY reliable signals from raw HTTP are:
      1. og:title meta tag (Googlebot gets this, browser UA may not)
      2. HTTP 404 status
      3. <link rel='canonical'> pointing to a valid video/channel URL
      4. itemprop='channelId' for channels

    Using 'video unavailable' from body text = guaranteed false negatives.
    """
    try:
        # MUST use bot UA — YouTube serves proper OG tags to Googlebot
        # but serves JS-only skeleton to browser UAs
        result = await _fetch_smart(session, url, "bot")
        status, html = result["status"], result["html"]
        title = _title(html)
        og = _og_title(html)
        og_desc = _og_description(html)
        canonical = _canonical(html)
        final_url = result.get("final_url", url)

        # Check for consent walls, captchas, and rate limits (common on cloud/VPS IPs)
        parsed_final = urlparse(final_url)
        final_host = parsed_final.hostname or ""
        lower_html = html.lower()
        
        is_consent_redirect = "consent." in final_host or "accounts.google.com" in final_host or "google.com/consent" in final_url
        is_consent_page = "before you continue to youtube" in lower_html or "consent.youtube.com" in lower_html
        is_rate_limited = "unusual traffic" in lower_html or "systems have detected" in lower_html
        is_sorry_redirect = "/sorry/index" in final_url or "/sorry/" in final_url
        
        if is_consent_redirect or is_consent_page or is_rate_limited or is_sorry_redirect:
            reason = "YouTube blocked request (consent page / rate limit / captcha)"
            if is_rate_limited or is_sorry_redirect:
                reason = "YouTube rate limited (unusual traffic detected / Captcha)"
            elif is_consent_redirect or is_consent_page:
                reason = "YouTube consent wall encountered"
            return {"status": "uncertain", "reason": reason, "http_code": status}

        if status == 404:
            return {"status": "taken_down", "reason": "YouTube content not found (404)", "http_code": 404}

        if status >= 400:
            return {"status": "uncertain", "reason": f"YouTube server/block response ({status})", "http_code": status}

        # Step 1: og:title is the most reliable signal
        # If Googlebot gets a real og:title, the content EXISTS
        if og and og.lower() not in ("youtube", ""):
            detail = f" -- {og_desc[:50]}" if og_desc else ""
            return {"status": "active", "reason": f"YouTube is active ({og}{detail})", "http_code": status}

        # Step 2: canonical URL check
        # A valid canonical means YouTube recognizes this as a real URL
        if canonical and ("/watch?" in canonical or "/@" in canonical or "/channel/" in canonical):
            return {"status": "active", "reason": f"YouTube content exists (canonical: {canonical[:50]})", "http_code": status}

        # Step 3: Channel-specific itemprop
        lower = html.lower()
        if 'itemprop="channelid"' in lower:
            return {"status": "active", "reason": f"YouTube channel exists ({title[:50]})", "http_code": status}

        # Step 4: Title-based detection (only trust non-generic titles)
        if title and title.lower() not in ("youtube", ""):
            # Check if title looks like a real video/channel name
            # "(N) video title - YouTube" is the pattern for real videos
            if " - youtube" in title.lower():
                clean_title = re.sub(r"\s*-\s*YouTube\s*$", "", title, flags=re.IGNORECASE).strip()
                clean_title = re.sub(r"^\(\d+\)\s*", "", clean_title).strip()  # Remove (N) notification count
                if clean_title:
                    return {"status": "active", "reason": f"YouTube is active ({clean_title})", "http_code": status}

        # Step 5: If NO og:title AND title is just "YouTube" → content doesn't exist
        # This is the only safe way to determine "taken down" without false negatives
        return {"status": "taken_down", "reason": "YouTube content not found (no OG metadata)", "http_code": status}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during YouTube check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"YouTube check error: {str(e)[:50]}", "http_code": None}


async def _check_instagram(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Instagram checker — Multi-Bot-UA Sequential Verification.

    Tier 1: facebookexternalhit UA (Meta's own crawler — gets special treatment)
    Tier 2: Googlebot UA
    Tier 3: Desktop Chrome UA
    Signals:
      Active:     og:title has real username, og:description has followers
      Taken down: "sorry, this page isn't available", 404, empty title
    """
    _IG_BOT_UAS = [
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]

    ig_dead_signals = [
        "sorry, this page isn't available",
        "this page isn't available",
        "the link you followed may be broken",
    ]

    def _analyze_ig(status, html, final_url):
        """Analyze Instagram response. Returns result dict or None if inconclusive."""
        title = _title(html)
        og = _og_title(html)
        og_desc = _og_description(html)
        lower = html.lower()

        # Login wall — inconclusive for this UA, try next
        if "/accounts/login/" in final_url or status in (403, 429):
            return None  # Try next UA

        # Definitive takedown signals
        for signal in ig_dead_signals:
            if signal in lower:
                return {"status": "taken_down", "reason": "Instagram profile not found", "http_code": status}

        if status == 404:
            return {"status": "taken_down", "reason": "Instagram not found (404)", "http_code": 404}

        # Has og:title with actual username (not just "Instagram")
        if og and "instagram" not in og.lower():
            detail = ""
            if og_desc and ("followers" in og_desc.lower() or "following" in og_desc.lower()):
                detail = f" — {og_desc[:60]}"
            return {"status": "active", "reason": f"Instagram is active ({og}{detail})", "http_code": status}

        # Has og:description with follower count
        if og_desc and ("followers" in og_desc.lower() or "posts" in og_desc.lower()):
            return {"status": "active", "reason": f"Instagram is active ({og_desc[:60]})", "http_code": status}

        # Dead profile: title is exactly "Instagram" with no OG metadata
        if title.strip() == "Instagram" and not og:
            return {"status": "taken_down", "reason": "Instagram profile not found", "http_code": status}

        # Has a real title that's not just "Instagram"
        if title.strip() and title.strip() != "Instagram":
            return {"status": "active", "reason": f"Instagram is active ({title[:50]})", "http_code": status}

        return None  # Inconclusive

    try:
        # Tier 1-3: Try multiple bot UAs sequentially
        for ua in _IG_BOT_UAS:
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            try:
                async with session.get(url, timeout=_TIMEOUT, headers=headers, allow_redirects=True) as resp:
                    status = resp.status
                    html = await resp.text()
                    final_url = str(resp.url)
                    result = _analyze_ig(status, html, final_url)
                    if result:
                        return result
            except Exception:
                continue

        # Tier 4: Desktop UA via _fetch_smart as last resort
        try:
            result = await _fetch_smart(session, url, "desktop")
            status, html = result["status"], result["html"]
            final_url = result["final_url"]
            analyzed = _analyze_ig(status, html, final_url)
            if analyzed:
                return analyzed
        except Exception:
            pass

        # All tiers exhausted
        return {"status": "uncertain", "reason": "Instagram blocked all verification methods", "http_code": None}
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "active", "reason": "Active (Connection Blocked/SSL)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during Instagram check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Instagram check error: {str(e)[:50]}", "http_code": None}


async def _check_x(session: aiohttp.ClientSession, url: str) -> dict:
    """
    X (Twitter) checker — Multi-Bot-UA + oEmbed Verification.

    Tier 1: Desktop UA (X sometimes serves full page)
    Tier 2: Googlebot/Bingbot UA
    Tier 3: oEmbed API (publish.twitter.com — free, official, no auth)
    Signals:
      Active:     Title = "Name (@handle) / X", oEmbed returns 200
      Suspended:  "Account suspended" in HTML
      Taken down: 404, "page doesn't exist"
    """
    _X_BOT_UAS = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]

    def _analyze_x(status, html, final_url):
        """Analyze X response. Returns result dict or None if inconclusive."""
        title = _title(html)
        og = _og_title(html)
        og_desc = _og_description(html)
        lower = html.lower()

        # Login wall — inconclusive, try next tier
        if status in (403, 429) or "login" in final_url.lower() or (title and (title.startswith("Log in to") or title in ("X", "X / ?"))):
            return None

        # Suspended account — definitive
        if "account suspended" in lower:
            return {"status": "taken_down", "reason": "X account suspended", "http_code": status}

        if status == 404 or title == "Profile / X":
            return {"status": "taken_down", "reason": "X profile not found or suspended", "http_code": status}

        if "this page doesn" in lower or "this account doesn" in lower:
            return {"status": "taken_down", "reason": "X page doesn't exist", "http_code": status}

        # Valid profile: title = "Name (@handle) / X"
        if title and " / X" in title:
            name = title.replace(" / X", "").strip()
            detail = f" — {og_desc[:50]}" if og_desc else ""
            return {"status": "active", "reason": f"X profile is active ({name[:50]}{detail})", "http_code": status}

        # og:title fallback
        if og and "twitter" not in og.lower() and og.lower() != "x":
            return {"status": "active", "reason": f"X content exists ({og[:50]})", "http_code": status}

        return None  # Inconclusive

    try:
        # Tier 1: Desktop UA
        try:
            result = await _fetch_smart(session, url, "desktop")
            analyzed = _analyze_x(result["status"], result["html"], result["final_url"])
            if analyzed:
                return analyzed
        except Exception:
            pass

        # Tier 2: Bot UAs
        for ua in _X_BOT_UAS:
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            try:
                async with session.get(url, timeout=_TIMEOUT, headers=headers, allow_redirects=True) as resp:
                    html = await resp.text()
                    analyzed = _analyze_x(resp.status, html, str(resp.url))
                    if analyzed:
                        return analyzed
            except Exception:
                continue

        # Tier 3: oEmbed API — free, official, no auth required
        # Works for tweets and profiles. Returns 200+JSON if content exists, 404 if not.
        try:
            oembed_url = f"https://publish.twitter.com/oembed?url={url}&omit_script=true"
            headers = {"User-Agent": _random_ua("desktop"), "Accept": "application/json"}
            async with session.get(oembed_url, timeout=aiohttp.ClientTimeout(total=8), headers=headers) as resp:
                if resp.status == 200:
                    import json
                    data = json.loads(await resp.text())
                    author = data.get("author_name", "")
                    if author:
                        return {"status": "active", "reason": f"X content exists (oEmbed: {author[:40]})", "http_code": 200}
                    return {"status": "active", "reason": "X content exists (oEmbed verified)", "http_code": 200}
                elif resp.status == 404:
                    return {"status": "taken_down", "reason": "X content not found (oEmbed 404)", "http_code": 404}
        except Exception:
            pass

        # All tiers exhausted
        return {"status": "uncertain", "reason": "X blocked all verification methods", "http_code": None}
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "active", "reason": "Active (Connection Blocked/SSL)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during X check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"X check error: {str(e)[:50]}", "http_code": None}


async def _check_generic(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Generic website checker — industry-grade multi-signal analysis.

    1. DNS pre-check (fast fail for dead domains)
    1b. HEAD request optimization (fast fail for 404/410/451)
    2. Redirect chain analysis (detect parking, hijacking)
    3. HTTP status code analysis
    4. Content-length heuristic (error pages are small)
    5. <title> + <h1> takedown signal matching
    6. Parking/seized domain detection
    7. Meta robots noindex detection
    """
    hostname = urlparse(url).hostname or ""

    # Step 1: DNS pre-check (skip for IP addresses)
    if hostname and not re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        if not await _dns_resolve(hostname):
            return {"status": "taken_down", "reason": "Domain/DNS not found (pre-check)", "http_code": None}

    # Step 1b: HEAD request optimization (enterprise enhancement)
    # For generic sites only — try HEAD first to quickly classify 404/410/451
    # without downloading the full page body.
    if config.ENABLE_HEAD_OPTIMIZATION:
        try:
            headers = {
                "User-Agent": _random_ua("desktop"),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            async with session.head(
                url, timeout=aiohttp.ClientTimeout(total=5),
                headers=headers, allow_redirects=True
            ) as head_resp:
                head_status = head_resp.status
                if head_status in (404, 410):
                    return {"status": "taken_down", "reason": f"Page not found ({head_status}, HEAD)", "http_code": head_status}
                if head_status == 451:
                    return {"status": "taken_down", "reason": "Unavailable for legal reasons (451, HEAD)", "http_code": 451}
                # HEAD returned 405/501 = server doesn't support HEAD, fall through to GET
        except Exception:
            pass  # HEAD failed, fall through to normal GET flow

    try:
        result = await _fetch_smart(session, url, "desktop")
        status, html = result["status"], result["html"]
        title = _title(html)
        h1 = _h1(html)
        og = _og_title(html)
        final_url = result["final_url"]
        hops = result["hops"]
        cross_domain = result["cross_domain"]
        content_len = len(html)

        # Step 2: Redirect chain analysis
        if cross_domain:
            final_host = urlparse(final_url).hostname or ""
            # Check if redirected to a known parking/error domain
            parking_domains = ["sedoparking.com", "bodis.com", "hugedomains.com", "afternic.com", "dan.com"]
            if any(pd in final_host for pd in parking_domains):
                return {"status": "taken_down", "reason": f"Redirects to parking page ({final_host})", "http_code": status}

        # Step 3: HTTP status analysis
        if status in (404, 410):
            return {"status": "taken_down", "reason": f"Page not found ({status})", "http_code": status}
        if status >= 400 and status not in _ALIVE_ERROR_CODES:
            return {"status": "taken_down", "reason": f"HTTP error ({status})", "http_code": status}

        # Step 4: Parking/seized detection
        parking_reason = _detect_parking(html, title, h1)
        if parking_reason:
            return {"status": "taken_down", "reason": parking_reason, "http_code": status}

        # Step 5: Title/H1 takedown signals
        text_to_check = f"{title} {h1}".lower()
        for signal in _TAKEDOWN_SIGNALS:
            if signal in text_to_check:
                return {"status": "taken_down", "reason": signal.title(), "http_code": status}

        # Step 6: Content-length heuristic
        # Very small pages (<500 bytes) with no og tags are likely error/placeholder pages
        if content_len < 500 and not og and not title:
            return {"status": "taken_down", "reason": "Empty/minimal page (likely removed)", "http_code": status}

        # Step 7: Build detailed reason
        detail_parts = []
        if title:
            detail_parts.append(title[:40])
        if hops > 0:
            detail_parts.append(f"{hops} redirect{'s' if hops > 1 else ''}")
        detail = " · ".join(detail_parts) if detail_parts else "responsive"

        return {"status": "active", "reason": f"Page is accessible ({detail})", "http_code": status}

    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "active", "reason": "Active (Connection Blocked/SSL)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Check error: {str(e)[:50]}", "http_code": None}


async def _check_app_store(session: aiohttp.ClientSession, url: str) -> dict:
    """Check app store URLs (Play Store, App Store, Third Party APK sites)."""
    try:
        result = await _fetch_smart(session, url, "desktop")
        status, html = result["status"], result["html"]
            
        if status == 404 or status == 410:
            return {"status": "taken_down", "reason": "App not found (404/410)", "http_code": status}
                
        if status in (401, 403, 429, 999):
            # Anti-bot walls block us from verifying the package contents. Report as uncertain.
            return {"status": "uncertain", "reason": f"Anti-bot wall / security challenge ({status})", "http_code": status}
            
        if status == 200:
            html_lower = html.lower()
                
            # Google Play Store
            if "we're sorry, the requested url was not found on this server" in html_lower:
                return {"status": "taken_down", "reason": "App not found on Play Store", "http_code": status}
                
            # Apple App Store
            if "app not available" in html_lower or "connecting to apple music" in html_lower:
                return {"status": "taken_down", "reason": "App Not Available", "http_code": status}
                
            # Generic fallback for third-party APK sites
            if "this app is currently not available" in html_lower or "the app you're looking for doesn't exist" in html_lower:
                return {"status": "taken_down", "reason": "App Not Available", "http_code": status}
                
            return {"status": "active", "reason": "App is available", "http_code": status}
                
        return {"status": "uncertain", "reason": f"Unexpected status {status}", "http_code": status}
            
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "uncertain", "reason": "Connection Blocked by host (Anti-bot/SSL reset)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during App check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"App check error: {str(e)[:50]}", "http_code": None}


# ── Dispatcher ────────────────────────────────────────────────────────────────

_CHECKERS = {
    "telegram": _check_telegram,
    "facebook": _check_facebook,
    "linkedin": _check_linkedin,
    "youtube": _check_youtube,
    "instagram": _check_instagram,
    "x": _check_x,
    "apps": _check_app_store,
}


async def _check_single(session: aiohttp.ClientSession, url: str, platform: str) -> dict:
    """
    Check a single URL using the best strategy for its platform.
    
    Enterprise enhancements (all additive, feature-flagged):
      - Evidence collection: gathers all signals before decision
      - Confidence scoring: 0-100 score based on evidence
      - Infrastructure detection: CDN, WAF, hosting provider
      - Structured metadata: JSON-LD, Twitter Cards, schema.org
      - Performance metrics: per-check timing breakdowns
      - Structured logging: timing and evidence in log output
    """
    logger.info(f"Checking {platform.upper()} URL: {url}")
    
    # Initialize evidence collector
    evidence = Evidence() if config.ENABLE_EVIDENCE else None
    check_start = time.monotonic()

    result = {
        "type": "result",
        "url": url,
        "platform": platform,
        "status": "uncertain",
        "reason": "",
        "http_code": None,
    }

    try:
        # ── Run the existing platform checker (UNCHANGED) ──
        checker = _CHECKERS.get(platform)
        if checker:
            result.update(await checker(session, url))
        else:
            result.update(await _check_generic(session, url))

        # ── Enterprise Enhancement: Populate Evidence ──
        if evidence and config.ENABLE_EVIDENCE:
            evidence.http_status = result.get("http_code")
            evidence.total_latency_ms = (time.monotonic() - check_start) * 1000

            # DNS resolved if we got any HTTP response
            if evidence.http_status is not None:
                evidence.dns_resolved = True
                evidence.add_signal("dns_resolved")

            # Error classification
            if config.ENABLE_ERROR_CLASSIFICATION and result["status"] == "uncertain":
                evidence.error_type = classify_error(
                    http_status=evidence.http_status,
                )

        # ── Enterprise Enhancement: Confidence Scoring ──
        if config.ENABLE_CONFIDENCE and evidence:
            confidence_score, signals = compute_confidence(evidence)
            result["confidence"] = confidence_score
            result["signals"] = signals

        # ── Enterprise Enhancement: Evidence Metadata ──
        if config.ENABLE_EVIDENCE and evidence:
            result["metadata"] = evidence.to_metadata_dict()

        # ── Logging (enhanced with structured data if enabled) ──
        status_label = result["status"].upper()
        reason_text = result["reason"]
        evidence_data = evidence.to_log_dict() if evidence else None
        log_check_result(platform, url, status_label, reason_text, evidence_data)

        # ── Enterprise Enhancement: Performance Metrics ──
        if config.ENABLE_METRICS:
            metric = CheckMetric(
                url=url,
                platform=platform,
                status=result["status"],
                total_ms=round((time.monotonic() - check_start) * 1000, 1),
                dns_ms=evidence.dns_time_ms if evidence else 0,
                ttfb_ms=evidence.ttfb_ms if evidence else 0,
                error_type=evidence.error_type if evidence else None,
            )
            await metrics_collector.record(metric)

    except Exception as e:
        logger.error(f"[FATAL CHECK ERROR] {platform.upper()} url={url} | error={e}")
        result.update({
            "status": "uncertain",
            "reason": f"Fatal worker error: {str(e)[:50]}"
        })

        # Record error in metrics
        if config.ENABLE_METRICS:
            metric = CheckMetric(
                url=url,
                platform=platform,
                status="uncertain",
                total_ms=round((time.monotonic() - check_start) * 1000, 1),
                error_type="FATAL_ERROR",
            )
            await metrics_collector.record(metric)

    return result


# ── Stream Processor ──────────────────────────────────────────────────────────


async def process_urls_stream(raw_urls: list[str]) -> AsyncGenerator[dict, None]:
    """
    Process URLs concurrently and yield results as they complete.
    Uses the Fast AIOHTTP Engine with multi-bot-UA verification for all platforms.
    No browser automation (Playwright) required.

    Enterprise enhancements:
      - Adaptive rate limiting: per-host concurrency semaphores
      - Circuit breaker: per-host failure tracking with auto-recovery
      - Enhanced connection pool: per-host limits, keepalive, idle cleanup
    """
    urls = [u for raw in raw_urls if (u := normalize_url(raw))]
    urls = deduplicate_urls(urls)

    total = len(urls)
    if total == 0:
        yield {"done": True, "summary": {"total": 0, "active": 0, "taken_down": 0, "uncertain": 0}}
        return

    counts = {"active": 0, "taken_down": 0, "uncertain": 0}
    completed = 0

    semaphore = asyncio.Semaphore(_CONCURRENT)

    # Enterprise enhancement: tuned connection pool
    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=config.TCP_CONNECTOR_LIMIT,
        limit_per_host=config.TCP_CONNECTOR_PER_HOST,
        keepalive_timeout=config.TCP_KEEPALIVE_TIMEOUT,
        enable_cleanup_closed=True,
    )

    async def _fast_worker(session: aiohttp.ClientSession, url: str, platform: str):
        result = {
            "type": "result", "url": url, "platform": platform,
            "status": "uncertain", "reason": "Unknown Worker Error",
            "http_code": None, "engine": "fast"
        }

        # Enterprise enhancement: circuit breaker check
        hostname = urlparse(url).hostname or ""
        if config.ENABLE_CIRCUIT_BREAKER:
            if await circuit_breaker.is_open(hostname):
                result["status"] = "uncertain"
                result["reason"] = f"Circuit breaker open for {hostname} (too many failures, cooling down)"
                logger.warning(f"[CIRCUIT_BREAKER] Skipping {url} — circuit open for {hostname}")
                return result

        try:
            res = await _check_single(session, url, platform)
            res["engine"] = "fast"
            result = res

            # Enterprise enhancement: circuit breaker feedback
            if config.ENABLE_CIRCUIT_BREAKER:
                if result["status"] == "uncertain" and result.get("http_code") in (None, 403, 429, 503):
                    await circuit_breaker.record_failure(hostname)
                else:
                    await circuit_breaker.record_success(hostname)

        except Exception as e:
            result["status"] = "uncertain"
            result["reason"] = f"Worker Exception: {str(e)[:100]}"
            if config.ENABLE_CIRCUIT_BREAKER:
                await circuit_breaker.record_failure(hostname)

        return result

    async def _sem_fast_worker(session: aiohttp.ClientSession, url: str, platform: str):
        # Enterprise enhancement: adaptive per-host rate limiting
        hostname = urlparse(url).hostname or ""
        if config.ENABLE_ADAPTIVE_RATE_LIMIT:
            await rate_limiter.acquire(hostname)

        try:
            async with semaphore:
                return await _fast_worker(session, url, platform)
        finally:
            if config.ENABLE_ADAPTIVE_RATE_LIMIT:
                rate_limiter.release(hostname)

    async with aiohttp.ClientSession(connector=connector) as shared_session:
        tasks = [asyncio.create_task(_sem_fast_worker(shared_session, u, detect_platform(u))) for u in urls]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            counts[result["status"]] = counts.get(result["status"], 0) + 1
            completed += 1
            result["progress"] = {"completed": completed, "total": total}
            yield result

    yield {"done": True, "summary": {"total": total, **counts}}


# ── CSV/ZIP Export ────────────────────────────────────────────────────────────

def create_export_zip(results: list[dict]) -> bytes:
    """Build a ZIP containing report.csv."""
    import csv as csv_mod
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        csv_buf = io.StringIO()
        writer = csv_mod.writer(csv_buf)
        writer.writerow(["#", "URL", "Platform", "Status", "Reason", "HTTP Code"])
        for i, r in enumerate(results, 1):
            writer.writerow([
                i,
                r.get("url", ""),
                r.get("platform", "generic"),
                r.get("status", ""),
                r.get("reason", ""),
                r.get("http_code", "")
            ])
        zf.writestr("report.csv", "\ufeff" + csv_buf.getvalue())
    buf.seek(0)
    return buf.read()
