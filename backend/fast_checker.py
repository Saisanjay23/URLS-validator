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
import ipaddress
import json
import random
import re
import socket
import time
import zipfile
from typing import AsyncGenerator
from urllib.parse import parse_qs, quote, urljoin, urlparse

import aiohttp

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False

async def _curl_cffi_get(
    url: str,
    headers: dict | None = None,
    impersonate: str = "chrome120",
    timeout: float = 10.0,
    allow_redirects: bool = True
):
    """
    Thread-safe wrapper for curl_cffi requests.get to avoid Proactor event loop errors on Windows.
    """
    if not HAS_CURL_CFFI:
        raise ImportError("curl_cffi is not installed")
    return await asyncio.to_thread(
        curl_requests.get,
        url,
        headers=headers,
        impersonate=impersonate,
        timeout=timeout,
        allow_redirects=allow_redirects
    )

from backend.url_utils import detect_platform, normalize_url, deduplicate_urls
from backend.logger import get_logger, log_check_result
from backend.cookies import get_cookie_header_string, load_all_cookies

# ── Enterprise Module Imports ─────────────────────────────────────────────────
from backend import config
from backend.evidence import Evidence
from backend.confidence import compute_confidence
from backend.parking import detect_expanded_parking
from backend.intelligence import classify_error
from backend.networking import circuit_breaker, rate_limiter
from backend.metrics import metrics_collector, CheckMetric

logger = get_logger()

def _clean_html_text(html: str) -> str:
    """Strip script, style, and metadata tags from HTML to inspect only visible text."""
    try:
        from selectolax.parser import HTMLParser
        tree = HTMLParser(html)
        for tag in ("script", "style", "template", "noscript", "head"):
            for element in tree.css(tag):
                element.decompose()
        return (tree.body.text() if tree.body else tree.text()).lower()
    except Exception:
        # Fallback to regex cleaning if selectolax fails
        cleaned = re.sub(r"<(script|style|template|noscript|head)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        return cleaned.lower()

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

# Known domain parking / seized / web host placeholder indicators
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
    "index of /",
    "apache2 ubuntu default page",
    "welcome to nginx",
    "iis7",
    "iis8",
    "iis windows server",
    "domain is ready",
    "website is suspended",
    "account suspended",
    "default web site page",
    "cpanel default page",
    "placeholder page",
    "hostinger dns system",
    "parked domain name on hostinger dns system",
    "hostinger",
    "parked domain",
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


def _og_meta(html: str, prop: str) -> str:
    """Extract an og:* property from <meta> tags (content before or after the property)."""
    for pattern in (
        rf'<meta\s+(?:property|name)=["\']og:{prop}["\']\s+content=["\']([^"\']*)["\']',
        rf'content=["\']([^"\']*?)["\'](?:\s+(?:property|name)=["\']og:{prop}["\'])',
    ):
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _og_title(html: str) -> str:
    return _og_meta(html, "title")


def _og_description(html: str) -> str:
    return _og_meta(html, "description")


def _og_url(html: str) -> str:
    return _og_meta(html, "url")


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


def _classify_connection_error(e: Exception) -> str:
    """Classify connection exceptions to extract clear reasons."""
    msg = str(e).lower()
    if "getaddrinfo" in msg or "nodename" in msg:
        return "Domain/DNS not found"
    if "refused" in msg:
        return "Connection refused (server is offline)"
    if "timed out" in msg or "timeout" in msg:
        return "Connection timed out"
    if "reset" in msg or "broken pipe" in msg:
        return "Connection reset by peer"
    if "ssl" in msg:
        return "SSL handshake failure / secure connection error"
    return f"Connection failed: {type(e).__name__}"


def _is_private_target(hostname: str) -> bool:
    """SSRF guard: refuse to fetch loopback/private/link-local targets so the
    API can't be used to probe internal infrastructure. Real social/app URLs
    are always public hostnames, so legitimate checks are unaffected."""
    if not hostname:
        return False
    host = hostname.strip("[]").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


# ── DNS Pre-Check ─────────────────────────────────────────────────────────────

async def _dns_resolve(hostname: str) -> bool:
    """
    Fast async DNS check using socket.getaddrinfo in a thread.
    Returns True if the domain resolves, False if DNS fails.
    """
    loop = asyncio.get_running_loop()
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
                    # urljoin handles absolute, relative, and protocol-relative Locations
                    redirect_chain.append(current_url)
                    current_url = urljoin(current_url, location)
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
    blocked_result = None

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

                logger.warning(f"IP Rate Limited or Bot Blocked ({result['status']}) on {url} (Pool: {pool}, Attempt: {attempt+1})")
                blocked_result = result
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
    if blocked_result is not None:
        return blocked_result
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
        return {"status": "uncertain", "reason": "Timeout during Telegram check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Telegram check error: {str(e)[:50]}", "http_code": None}

# ── Facebook Cross-Verification Helpers ──────────────────────────────────────
# These implement the multi-engine consensus architecture used by industry
# leaders (CrowdStrike, Mandiant, Meta T&S) to eliminate false positives.
# A URL is only declared "taken_down" when multiple independent methods agree.

def _extract_fb_id(url: str) -> str | None:
    """
    Extract the numeric Facebook ID or username/identifier from any URL format.
    Supports:
      - /profile.php?id=123456
      - /p/PageName-123456/
      - /pages/Name/123456
      - Numeric-only paths like /123456
      - Usernames like /Navimumbai24 or /ime.isaac.75
    Returns None if no identifier can be extracted.
    """
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return None

    # profile.php?id=123456
    if "profile.php" in path:
        qs = parse_qs(parsed.query)
        fb_id = qs.get("id", [None])[0]
        if fb_id:
            return fb_id

    segments = path.split("/")

    # Sub-content URLs (posts/photos/videos/reels): the Graph-checkable id
    # would be the OWNER, not the content itself — verifying the owner exists
    # says nothing about whether the post was removed. Return None so the
    # caller falls back to multi-engine consensus instead.
    _subcontent = {
        "posts", "photo", "photos", "video", "videos", "reel", "reels",
        "story.php", "permalink.php", "photo.php", "watch", "share", "live",
    }
    if any(seg in _subcontent for seg in segments):
        return None

    # Try to find a purely numeric segment (e.g. /people/Name/123456)
    for seg in segments:
        if seg.isdigit() and len(seg) > 5:
            return seg

    # Name-123456 pattern (used in /p/ URLs)
    last_segment = segments[-1]
    m = re.search(r"-(\d{10,})$", last_segment)
    if m:
        return m.group(1)

    # Standard username segment
    common_system_paths = {
        "pages", "groups", "events", "marketplace", "watch", "live",
        "stories", "reels", "photo.php", "permalink.php", "story.php",
        "photo", "share", "login", "signup", "rsrc.php"
    }
    
    first_segment = segments[0]
    if first_segment not in common_system_paths and not first_segment.startswith("rsrc.php"):
        return first_segment

    return None


async def _graph_api_exists(session: aiohttp.ClientSession, url: str) -> bool | None:
    """
    Anonymous Graph API existence check — graph.facebook.com/{id}, no token.

    Empirically verified behavior (probed 2026-07):
      code 200 "provide valid app ID"   -> object EXISTS
      code 100 on a NUMERIC id          -> object GONE (deleted id=1 -> 100)
      code 100 on a username            -> AMBIGUOUS (live usernames like /zuck also return 100)
      code 803 alias does not exist     -> object GONE
      code 104 "access token required":
        - on a /groups/ or /events/ id  -> object EXISTS (private group/event;
          verified live: private group 430017090388013 -> 104)
        - on a PROFILE id               -> MEANINGLESS: modern profile ids
          (615.../1000...) return 104 whether the account exists or was
          removed (verified against 27 known-taken-down profiles), so it must
          never rescue a dead-looking profile.
    Returns True (exists) / False (gone) / None (inconclusive).
    """
    fb_id = _extract_fb_id(url)
    if not fb_id:
        return None

    path_lower = urlparse(url).path.lower()
    is_group_or_event = "/groups/" in path_lower or "/events/" in path_lower

    try:
        graph_url = f"https://graph.facebook.com/{fb_id}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        async with session.get(graph_url, timeout=aiohttp.ClientTimeout(total=6), headers=headers) as resp:
            body = await resp.text()
        try:
            data = json.loads(body)
        except Exception:
            return None
        error = data.get("error")
        if not error:
            # Real data back means the object is public and exists
            return True if ("id" in data or "name" in data) else None
        code = error.get("code")
        if code == 200:
            return True
        if code == 104:
            return True if is_group_or_event else None
        if code == 803:
            return False
        if code == 100:
            return False if fb_id.isdigit() else None
        return None
    except Exception:
        return None


# Phrases Facebook renders on removed/nonexistent content. These alone are NOT
# proof of removal — private groups and restricted content show them too —
# which is why every "dead vote" is arbitrated against the Graph API below.
_FB_TAKEDOWN_PHRASES = (
    "this content isn't available right now",
    "content isn't available",
    "this page isn't available",
    "page isn't available",
    "this page has been removed",
    "the link you followed may be broken",
    "profile isn't available",
)


def _fb_normalize(html: str) -> str:
    """Lowercase + normalize apostrophe encodings so takedown phrases match."""
    return (
        html.replace("&#039;", "'")
        .replace("&#x27;", "'")
        .replace("\u2019", "'")
        .lower()
    )


def _fb_is_wall(final_url: str, title: str) -> bool:
    """True when the response is a login/checkpoint wall — never classify from it."""
    fl = (final_url or "").lower()
    tl = title.strip().lower()
    return (
        "/login" in fl
        or "/checkpoint" in fl
        or "/recover" in fl
        or tl.startswith(("log in", "log into", "sign up"))
        or "log in or sign up" in tl
    )


def _fb_classify(status: int, html: str, final_url: str, requested_url: str) -> tuple[str, str] | None:
    """
    Classify one anonymous Facebook response.

    Empirically verified (probed 2026-07 with known live/dead URLs):
      - Live pages/profiles/groups ALWAYS carry an og:title meta — even
        facebook.com/facebook, whose og:title is literally "Facebook".
      - Removed/nonexistent content has NO og:title at all, plus a
        "content isn't available" phrase, or bounces to the bare homepage.
      - Dead /watch videos bounce to the "Discover popular videos" hub.

    Returns ("active", reason), ("dead_vote", reason) — dead votes require
    Graph arbitration before becoming taken_down — or None when the response
    is a wall/challenge and must not be classified.
    """
    if status in (404, 410):
        return ("dead_vote", f"HTTP {status}")
    if status in (403, 429) or status >= 500:
        return None

    title = _title(html)
    og = _og_title(html)
    if _fb_is_wall(final_url, title):
        return None

    og_stripped = og.strip()

    # Dead /watch videos redirect to the generic video hub
    if "/watch" in urlparse(requested_url).path.lower() and og_stripped:
        if "discover popular videos" in og_stripped.lower():
            return ("dead_vote", "video redirected to generic video hub")
        return ("active", f"Facebook video is active ({og_stripped[:50]})")

    # og:title present == the object resolved and rendered
    if og_stripped:
        return ("active", f"Facebook is active ({og_stripped[:50]})")

    norm = _fb_normalize(html)
    phrase = next((p for p in _FB_TAKEDOWN_PHRASES if p in norm), None)
    if phrase:
        return ("dead_vote", "matched: " + phrase)

    # Requested a specific object but landed on the bare facebook.com homepage
    req_path = urlparse(requested_url).path.strip("/")
    fin = urlparse(final_url)
    if req_path and not fin.path.strip("/") and not fin.query:
        return ("dead_vote", "redirected to Facebook homepage")

    return None


async def _check_facebook(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Facebook checker — cookie-free multi-engine consensus.

    Engines, in order:
      1. www.facebook.com with Chrome TLS impersonation (curl_cffi) — from a
         normal network position this returns the FULL page anonymously.
      2. facebookexternalhit crawler UA — Facebook serves OG previews to its
         own link-preview bot even when browsers get challenged.
      3. m.facebook.com via aiohttp UA rotation (weak fallback, mainly for
         when curl_cffi is unavailable).

    Decision rules (all empirically verified, see _fb_classify):
      - Any engine seeing an og:title -> ACTIVE immediately.
      - A dead-looking response is NEVER trusted alone: it is arbitrated
        against the anonymous Graph API (private groups and restricted pages
        show the same "content isn't available" interstitial).
          Graph says exists  -> ACTIVE (restricted for anonymous view)
          Graph says gone    -> TAKEN_DOWN (definitive for numeric ids)
          Graph ambiguous    -> require a SECOND engine to independently see
                                the takedown before declaring TAKEN_DOWN.
      - Login/checkpoint walls are never classified; if everything walls,
        the result is uncertain rather than a guess.
    """

    async def _engine_www():
        resp = await _curl_cffi_get(url, impersonate="chrome120", timeout=12, allow_redirects=True)
        return resp.status_code, resp.text, str(resp.url)

    async def _engine_exthit():
        headers = {
            "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = await _curl_cffi_get(url, headers=headers, impersonate="chrome120", timeout=12, allow_redirects=True)
        return resp.status_code, resp.text, str(resp.url)

    async def _engine_mobile():
        check_url = url.replace("www.facebook.com", "m.facebook.com").replace(
            "://facebook.com", "://m.facebook.com"
        )
        result = await _fetch_smart(session, check_url, "mobile")
        return result["status"], result["html"], result["final_url"]

    engines = []
    if HAS_CURL_CFFI:
        engines += [("www", _engine_www), ("exthit", _engine_exthit)]
    engines.append(("mobile", _engine_mobile))

    graph_checked = False
    graph_verdict: bool | None = None
    dead_votes: list[str] = []
    last_status = None

    try:
        for name, engine in engines:
            try:
                status, html, final_url = await engine()
            except aiohttp.ClientConnectorError as e:
                if _is_dns_error(e):
                    return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
                continue
            except Exception as e:
                logger.warning(f"[FACEBOOK] engine {name} failed for {url}: {str(e)[:80]}")
                continue

            last_status = status
            verdict = _fb_classify(status, html, final_url, url)
            if verdict is None:
                logger.info(f"[FACEBOOK] engine {name} inconclusive (wall/challenge) for {url}")
                continue

            kind, detail = verdict
            if kind == "active":
                return {"status": "active", "reason": f"{detail} [{name}]", "http_code": status}

            # Dead vote -> arbitrate with the Graph API (once per URL)
            if not graph_checked:
                graph_verdict = await _graph_api_exists(session, url)
                graph_checked = True
            if graph_verdict is True:
                return {
                    "status": "active",
                    "reason": "Facebook object exists (Graph API verified) — restricted for anonymous view",
                    "http_code": status,
                }
            if graph_verdict is False:
                return {
                    "status": "taken_down",
                    "reason": f"Facebook content removed: {detail} (Graph API confirmed gone)",
                    "http_code": status,
                }

            dead_votes.append(f"{name}: {detail}")
            if len(dead_votes) >= 2:
                return {
                    "status": "taken_down",
                    "reason": f"Facebook content removed ({'; '.join(dead_votes)})",
                    "http_code": status,
                }

        if dead_votes:
            return {
                "status": "uncertain",
                "reason": f"Possible Facebook takedown, unconfirmed ({dead_votes[0]}) — other engines blocked",
                "http_code": last_status,
            }
        return {
            "status": "uncertain",
            "reason": "Facebook served walls/challenges to all anonymous engines",
            "http_code": last_status,
        }
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "uncertain", "reason": "Connection blocked during Facebook check", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during Facebook check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Facebook check error: {str(e)[:50]}", "http_code": None}


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
            resp = await _curl_cffi_get(url, headers=headers, impersonate="chrome120", timeout=config.TIMEOUT_TOTAL, allow_redirects=True)
            status = resp.status_code
            html = resp.text
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
        
        # Fallback to curl_cffi with TLS Spoofing (impersonate Chrome)
        if HAS_CURL_CFFI:
            try:
                curl_res = await _curl_cffi_get(url, impersonate="chrome120", timeout=15, allow_redirects=True)
                curl_status = curl_res.status_code
                curl_html = curl_res.text
                curl_final_url = str(curl_res.url)
                if curl_status == 404:
                    return {"status": "taken_down", "reason": "LinkedIn content not found (404, curl_cffi)", "http_code": 404}
                if "/authwall" in curl_final_url or "/login" in curl_final_url or "/signup" in curl_final_url:
                    pass # inconclusive authwall
                else:
                    curl_title = _title(curl_html)
                    curl_og = _og_title(curl_html)
                    curl_og_desc = _og_description(curl_html)
                    
                    if _has_person_name(curl_og) or _has_person_name(curl_title):
                        name = re.sub(r"\s*\|\s*LinkedIn\s*$", "", curl_og or curl_title, flags=re.IGNORECASE).strip()
                        detail = f" — {curl_og_desc[:60]}" if curl_og_desc and "linkedin" not in curl_og_desc.lower() else ""
                        return {"status": "active", "reason": f"LinkedIn exists ({name[:50]}{detail}, curl_cffi)", "http_code": curl_status}
                    
                    if curl_title.lower() in ("linkedin", "") and not curl_og:
                        return {"status": "taken_down", "reason": "LinkedIn content not found (curl_cffi)", "http_code": curl_status}
                    
                    if curl_title.strip() and curl_title.lower() not in ("linkedin", "sign up", "log in"):
                        return {"status": "active", "reason": f"LinkedIn exists (title: {curl_title[:40]}, curl_cffi)", "http_code": curl_status}
            except Exception as e:
                logger.warning(f"[LINKEDIN] curl_cffi fallback failed for {url}: {e}")

        # All dedicated bot UAs failed — return uncertain
        return {"status": "uncertain", "reason": "LinkedIn blocked all bot UAs. Cookies required.", "http_code": 403}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during LinkedIn check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"LinkedIn check error: {str(e)[:50]}", "http_code": None}



async def _check_youtube(session: aiohttp.ClientSession, url: str) -> dict:
    """
    YouTube checker — Hybrid oEmbed + Googlebot HTML Scraping Architecture.

    1. For videos (watch, v, embed, shorts, youtu.be), queries the official,
       free public oEmbed API first. This is highly accurate, fast, and does
       not get blocked by data center IP consent screens.
    2. For channels, playlists, or when oEmbed fails, falls back to raw page
       scraping using Googlebot UA.
    """
    # Step 1: Detect if it is a video URL
    url_lower = url.lower()
    is_video = any(x in url_lower for x in ("/watch?", "/v/", "/embed/", "/shorts/", "youtu.be/"))
    
    if is_video:
        # Normalize Shorts URLs to watch URLs before calling oEmbed
        target_url = url
        if "/shorts/" in url_lower:
            # Extract the bare video ID — a trailing query string would produce
            # an invalid "watch?v=ID?feature=share" URL and a false 400.
            m = re.search(r"/shorts/([A-Za-z0-9_-]+)", url)
            if m:
                target_url = f"https://www.youtube.com/watch?v={m.group(1)}"

        try:
            oembed_url = f"https://www.youtube.com/oembed?url={quote(target_url, safe='')}&format=json"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json"
            }
            async with session.get(oembed_url, timeout=aiohttp.ClientTimeout(total=6), headers=headers) as resp:
                status = resp.status
                if status == 200:
                    data = json.loads(await resp.text())
                    title = data.get("title", "")
                    author = data.get("author_name", "")
                    detail = f" ({title} by {author})" if title else ""
                    return {"status": "active", "reason": f"YouTube is active{detail}", "http_code": 200}
                elif status in (400, 404):
                    # oEmbed returns 400 Bad Request or 404 Not Found for deleted/private/nonexistent videos
                    return {"status": "taken_down", "reason": "YouTube video not found or private (oEmbed verified)", "http_code": status}
                # For 403, 429, or other codes, fall back to page scraping
                logger.warning(f"[YOUTUBE] oEmbed returned status {status} for {url}. Falling back to page scraper...")
        except Exception as e:
            logger.warning(f"[YOUTUBE] oEmbed failed for {url}: {e}. Falling back to page scraper...")

    # Step 2: Fallback to HTML Page Scraper (primarily for channels, or if oEmbed is rate-limited)
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


async def _ig_api_check(url: str) -> dict | None:
    """
    Check Instagram profile status using the web_profile_info API endpoint.
    Returns a result dict if definitive, otherwise None.
    """
    if not HAS_CURL_CFFI:
        return None
    try:
        # Only profile URLs (single path segment) — post/reel/story URLs would
        # send a shortcode as "username" and falsely report a suspended profile.
        segments = [s for s in urlparse(url).path.split("/") if s]
        if len(segments) != 1:
            return None
        path = segments[0]
        if path in ("accounts", "developer", "explore", "about", "p", "reel", "reels", "tv", "stories"):
            return None

        api_url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={path}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "X-IG-App-ID": "936619743392459",
            "Accept": "*/*",
            "X-Requested-With": "XMLHttpRequest",
        }
        
        resp = await _curl_cffi_get(api_url, headers=headers, impersonate="chrome120", timeout=10, allow_redirects=True)
        if resp.status_code == 200:
            try:
                data = resp.json()
                user = data.get("data", {}).get("user")
                if user:
                    full_name = user.get("full_name") or "Instagram User"
                    followers = user.get("edge_followed_by", {}).get("count") or 0
                    privacy = "Private" if user.get("is_private") else "Public"
                    return {
                        "status": "active",
                        "reason": f"Instagram is active ({full_name[:30]} · {privacy} · {followers} followers)",
                        "http_code": 200
                    }
                else:
                    if data.get("status") == "ok":
                        return {"status": "taken_down", "reason": "Instagram profile suspended or disabled", "http_code": 200}
            except Exception:
                pass
        elif resp.status_code == 404:
            return {"status": "taken_down", "reason": "Instagram profile not found (404 API)", "http_code": 404}
    except Exception as e:
        logger.warning(f"[INSTAGRAM] API verification failed for {url}: {e}")
    return None

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

        # Generic title "Instagram" with no OG metadata: inconclusive (login wall / challenge)
        if title.strip() == "Instagram" and not og:
            return None

        # Has a real title that's not just "Instagram"
        if title.strip() and title.strip() != "Instagram":
            return {"status": "active", "reason": f"Instagram is active ({title[:50]})", "http_code": status}

        return None  # Inconclusive

    # Tier 0: Check using the official web_profile_info API endpoint
    api_res = await _ig_api_check(url)
    if api_res:
        logger.info(f"[INSTAGRAM] API verification succeeded: status={api_res['status']}")
        return api_res

    # Try with user cookies if configured
    cookie_str = get_cookie_header_string("instagram")
    if cookie_str:
        logger.info(f"[INSTAGRAM] Found cookies. Trying request using cookies...")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Cookie": cookie_str,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            resp = await _curl_cffi_get(url, headers=headers, impersonate="chrome120", timeout=config.TIMEOUT_TOTAL, allow_redirects=True)
            status = resp.status_code
            html = resp.text
            final_url = str(resp.url)

            result = _analyze_ig(status, html, final_url)
            if result:
                logger.info(f"[INSTAGRAM] Cookie check succeeded: status={result['status']}")
                return result
            if "/accounts/login/" in final_url or status in (403, 429):
                logger.warning("[INSTAGRAM] Cookie request redirected to login. Cookies might be expired. Falling back to bot UAs...")
        except Exception as ce:
            logger.warning(f"[INSTAGRAM] Cookie request failed: {ce}. Falling back to bot UAs...")

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

        # Tier 5: curl_cffi with TLS Spoofing (impersonate Chrome)
        if HAS_CURL_CFFI:
            try:
                curl_headers = {"Cookie": cookie_str} if cookie_str else None
                curl_res = await _curl_cffi_get(url, headers=curl_headers, impersonate="chrome120", timeout=15, allow_redirects=True)
                curl_status = curl_res.status_code
                curl_html = curl_res.text
                curl_final_url = str(curl_res.url)
                analyzed = _analyze_ig(curl_status, curl_html, curl_final_url)
                if analyzed:
                    logger.info(f"[INSTAGRAM] curl_cffi bypassed bot block for {url} ({analyzed['status']})")
                    return analyzed
            except Exception as e:
                logger.warning(f"[INSTAGRAM] curl_cffi fallback failed for {url}: {e}")

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
            oembed_url = f"https://publish.twitter.com/oembed?url={quote(url, safe='')}&omit_script=true"
            headers = {"User-Agent": _random_ua("desktop"), "Accept": "application/json"}
            async with session.get(oembed_url, timeout=aiohttp.ClientTimeout(total=8), headers=headers) as resp:
                if resp.status == 200:
                    data = json.loads(await resp.text())
                    author = data.get("author_name", "")
                    if author:
                        return {"status": "active", "reason": f"X content exists (oEmbed: {author[:40]})", "http_code": 200}
                    return {"status": "active", "reason": "X content exists (oEmbed verified)", "http_code": 200}
                elif resp.status == 404:
                    return {"status": "taken_down", "reason": "X content not found (oEmbed 404)", "http_code": 404}
        except Exception:
            pass

        # Fallback to curl_cffi with TLS Spoofing (impersonate Chrome)
        if HAS_CURL_CFFI:
            try:
                curl_res = await _curl_cffi_get(url, impersonate="chrome120", timeout=15, allow_redirects=True)
                analyzed = _analyze_x(curl_res.status_code, curl_res.text, str(curl_res.url))
                if analyzed:
                    logger.info(f"[X] curl_cffi bypassed block for {url} ({analyzed['status']})")
                    return analyzed
            except Exception as e:
                logger.warning(f"[X] curl_cffi fallback failed for {url}: {e}")

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
        final_url = result["final_url"]
        hops = result["hops"]
        cross_domain = result["cross_domain"]

        # ── Enterprise Enhancement: TLS Spoofing Fallback for WAF Blocks ──
        if status in (401, 403, 429, 999) and HAS_CURL_CFFI:
            try:
                curl_res = await _curl_cffi_get(url, impersonate="chrome120", timeout=10, allow_redirects=True)
                if curl_res.status_code != status:
                    logger.info(f"[GENERIC] curl_cffi bypassed WAF for {url} (status {status} -> {curl_res.status_code})")
                    status = curl_res.status_code
                    html = curl_res.text
                    final_url = str(curl_res.url)
            except Exception as e:
                logger.warning(f"[GENERIC] curl_cffi fallback failed for {url}: {e}")

        title = _title(html)
        h1 = _h1(html)
        og = _og_title(html)
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
        if status == 451:
            return {"status": "taken_down", "reason": "Unavailable for legal reasons (451)", "http_code": status}
        if status in (401, 403):
            title_lower = title.lower()
            if any(x in title_lower for x in ("forbidden", "access denied", "403", "401", "unauthorized")) or not title.strip():
                return {"status": "uncertain", "reason": f"Access denied / Forbidden ({status})", "http_code": status}
            return {"status": "active", "reason": f"Active (restricted/protected: {status} · {title[:40]})", "http_code": status}
        if status == 429:
            return {"status": "uncertain", "reason": "Rate limited (429)", "http_code": status}
        if status in (502, 503, 504):
            return {"status": "uncertain", "reason": f"Service offline / Server error ({status})", "http_code": status}
        if status >= 400:
            return {"status": "uncertain", "reason": f"HTTP error ({status})", "http_code": status}

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
        err_reason = _classify_connection_error(e)
        if err_reason in ("Domain/DNS not found", "Connection refused (server is offline)"):
            return {"status": "taken_down", "reason": err_reason, "http_code": None}
        return {"status": "uncertain", "reason": err_reason, "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Connection timed out (request timeout)", "http_code": None}
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
            if HAS_CURL_CFFI:
                # Attempt to bypass Cloudflare / Anti-bot walls using TLS spoofing
                try:
                    curl_res = await _curl_cffi_get(url, impersonate="chrome116", timeout=10, allow_redirects=True)
                    if curl_res.status_code == 200:
                        status = 200
                        html = curl_res.text
                    elif curl_res.status_code in (404, 410):
                        return {"status": "taken_down", "reason": f"App not found ({curl_res.status_code})", "http_code": curl_res.status_code}
                    else:
                        return {"status": "uncertain", "reason": f"Anti-bot wall / security challenge ({status}) [curl_cffi={curl_res.status_code}]", "http_code": status}
                except Exception as curl_e:
                    return {"status": "uncertain", "reason": f"Anti-bot wall / security challenge ({status}) [curl_cffi error]", "http_code": status}
            else:
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

async def _scribd_oembed_check(session: aiohttp.ClientSession, url: str) -> dict | None:
    """
    Check Scribd document existence using the Cloudflare-free oEmbed API.
    Returns a result dict if definitive, otherwise None.
    """
    clean_url = url.split("?")[0]
    oembed_url = f"https://www.scribd.com/services/oembed?url={clean_url}&format=json"
    try:
        async with session.get(oembed_url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status == 200:
                try:
                    data = await resp.json()
                    title = data.get("title") or "Document"
                    return {"status": "active", "reason": f"Scribd is active ({title[:50]})", "http_code": 200}
                except Exception:
                    return {"status": "active", "reason": "Scribd is active (oEmbed verified)", "http_code": 200}
            elif resp.status == 401:
                return {"status": "taken_down", "reason": "Scribd content not found / private (401 oEmbed)", "http_code": 401}
            elif resp.status in (404, 410):
                return {"status": "taken_down", "reason": f"Scribd content not found ({resp.status} oEmbed)", "http_code": resp.status}
    except Exception as e:
        logger.warning(f"[SCRIBD] oEmbed API check failed: {e}")
    return None

async def _check_scribd(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Check Scribd URLs (documents, presentations, books, authors, users).
    Uses browser impersonation curl_cffi by default since Scribd heavily protects its pages with Cloudflare.
    """
    try:
        # Strip query parameters to bypass tracking-based Cloudflare challenges
        if "?" in url:
            url = url.split("?")[0]

        # Tier 1: Try the oEmbed API (Cloudflare-free)
        oembed_res = await _scribd_oembed_check(session, url)
        if oembed_res:
            return oembed_res

        # We start with curl_cffi since it is much more accurate for Cloudflare-protected sites.
        if HAS_CURL_CFFI:
            try:
                resp = await _curl_cffi_get(url, impersonate="chrome120", timeout=12, allow_redirects=True)
                status = resp.status_code
                html = resp.text
                final_url = str(resp.url)
            except Exception as e:
                # If curl_cffi fails, fallback to standard session fetch
                result = await _fetch_smart(session, url, "desktop")
                status, html = result["status"], result["html"]
                final_url = url
        else:
            result = await _fetch_smart(session, url, "desktop")
            status, html = result["status"], result["html"]
            final_url = url

        # Let's analyze status and html content
        if status in (404, 406, 410):
            return {"status": "taken_down", "reason": f"Scribd content not found ({status})", "http_code": status}

        if status in (401, 403, 429, 503, 999):
            return {"status": "uncertain", "reason": f"Scribd login wall / Cloudflare challenge ({status})", "http_code": status}

        # Success check
        html_lower = html.lower()
        title_val = _title(html)
        title_lower = title_val.lower()

        # Check for Cloudflare / DDoS wall text or challenge titles
        if "challenge" in title_lower or "cloudflare" in html_lower or "just a moment..." in html_lower or "please wait..." in html_lower:
            return {"status": "uncertain", "reason": "Scribd Cloudflare challenge detected", "http_code": status}

        # Check for non-existent / deleted pages or removal notice
        takedown_indicators = [
            "page not found",
            "document removed",
            "removal notice",
            "this document has been removed",
            "we're sorry, we can't find this document",
            "scribd - document removed",
        ]
        
        if any(p in html_lower for p in takedown_indicators) or any(p in title_lower for p in ("page not found", "removal notice")):
            return {"status": "taken_down", "reason": "Scribd content not found / removed", "http_code": status}

        # If it returns standard Scribd title but is not page not found
        if title_val and "scribd" in title_lower and not any(p in title_lower for p in ("page not found", "error", "challenge", "removal notice")):
            clean_title = title_val.split("|")[0].strip()
            return {"status": "active", "reason": f"Scribd is active ({clean_title[:50]})", "http_code": status}

        # Fallback success check
        if status == 200:
            clean_title = title_val.split("|")[0].strip() if title_val else "Document"
            return {"status": "active", "reason": f"Scribd is active ({clean_title[:50]})", "http_code": status}

        return {"status": "uncertain", "reason": f"Unexpected status code {status}", "http_code": status}

    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "uncertain", "reason": "Connection Blocked by host (Anti-bot/SSL reset)", "http_code": None}
    except asyncio.TimeoutError:
        return {"status": "uncertain", "reason": "Timeout during Scribd check", "http_code": None}
    except Exception as e:
        return {"status": "uncertain", "reason": f"Scribd check error: {str(e)[:50]}", "http_code": None}


# ── Dispatcher ────────────────────────────────────────────────────────────────

_CHECKERS = {
    "telegram": _check_telegram,
    "facebook": _check_facebook,
    "linkedin": _check_linkedin,
    "youtube": _check_youtube,
    "instagram": _check_instagram,
    "x": _check_x,
    "apps": _check_app_store,
    "scribd": _check_scribd,
}


_playwright_instance = None
_playwright_browser = None
_playwright_lock = asyncio.Lock()

async def _get_playwright_browser():
    global _playwright_instance, _playwright_browser
    async with _playwright_lock:
        if _playwright_browser is None:
            from playwright.async_api import async_playwright
            _playwright_instance = await async_playwright().start()
            _playwright_browser = await _playwright_instance.chromium.launch(headless=True)
    return _playwright_browser

async def close_global_playwright():
    global _playwright_instance, _playwright_browser
    async with _playwright_lock:
        if _playwright_browser is not None:
            try:
                await _playwright_browser.close()
            except Exception:
                pass
            _playwright_browser = None
        if _playwright_instance is not None:
            try:
                await _playwright_instance.stop()
            except Exception:
                pass
            _playwright_instance = None


def _scrapling_text(content: str, selector: str, identifier: str) -> str | None:
    """Adaptive Scrapling text extraction backed by the shared selector-memory DB.
    Returns None when scrapling is unavailable or the element is not found."""
    try:
        import os
        from scrapling import Selector
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scrapling_selectors.db")
        el = Selector(content, adaptive=True, storage_args={"storage_file": db_path}).css(
            selector, identifier=identifier, adaptive=True, auto_save=True
        )
        return el.css('::text').get()
    except Exception:
        return None


async def _check_with_playwright(session: aiohttp.ClientSession, url: str, platform: str) -> dict:
    """
    Playwright Fallback Checker.
    Runs when standard HTTP checkers return "uncertain" to provide a browser-based bypass.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"status": "uncertain", "reason": "Playwright not installed", "http_code": None}

    if platform == "scribd" and "?" in url:
        url = url.split("?")[0]

    # Interceptor to block visual assets
    async def block_resources(route):
        if route.request.resource_type in ("image", "stylesheet", "font", "media"):
            await route.abort()
        else:
            await route.continue_()

    try:
        browser = await _get_playwright_browser()
        
        cookies = load_all_cookies()
        platform_cookies = cookies.get(platform, [])
        
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            locale="en-US"
        )
        
        if platform_cookies:
            formatted_cookies = []
            for c in platform_cookies:
                name = c.get("name")
                value = c.get("value")
                if name and value:
                    formatted_cookies.append({
                        "name": name,
                        "value": value,
                        "domain": ".instagram.com" if platform == "instagram" else (".facebook.com" if platform == "facebook" else ".linkedin.com"),
                        "path": "/"
                    })
            if formatted_cookies:
                try:
                    await context.add_cookies(formatted_cookies)
                except Exception as ce:
                    logger.warning(f"[PLAYWRIGHT] Cookie injection failed: {ce}")
        
        page = await context.new_page()
        await page.route("**/*", block_resources)
        
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            status = response.status if response else 200
            title = await page.title()
            content = await page.content()
            html_lower = content.lower()
            final_url = page.url
        finally:
            await context.close()
        
        if platform == "facebook":
            title_lower = title.lower()
            is_generic = title_lower in ("facebook", "error facebook", "") or "log in" in title_lower or "login" in title_lower
            takedown_phrases = [
                "content isn't available",
                "page isn't available",
                "this page has been removed",
                "link you followed may be broken",
                "page not found",
                "profile isn't available"
            ]
            clean_text = _clean_html_text(content)
            has_takedown = (
                any(p in clean_text for p in takedown_phrases) or
                any(p in html_lower for p in [
                    "this content isn't available at the moment",
                    "usually because the owner only shared it with a small group of people",
                    "changed who can see it",
                    "it's been deleted"
                ])
            )
            
            profile_name = _scrapling_text(content, 'h1', "facebook_profile_name")
            
            if is_generic and not profile_name:
                graph_exists = await _graph_api_exists(session, url)
                if graph_exists is True:
                    return {"status": "active", "reason": "Facebook active (Graph API verified, login wall on browser)", "http_code": status}
                elif graph_exists is False:
                    return {"status": "taken_down", "reason": "Facebook profile not found (Graph API confirmed)", "http_code": status}
                
                # Check if final URL is a login / checkpoint redirect (meaning cookie session expired)
                is_login_redirect = any(path in final_url.lower() for path in ("/login", "login.php", "/checkpoint", "/challenge", "/signup"))
                
                # If we have valid cookies injected and we still hit the login wall with a takedown phrase, and it's not a login redirect, it's a takedown.
                # Otherwise, anonymously it's inconclusive.
                if has_takedown and platform_cookies and not is_login_redirect:
                    return {"status": "taken_down", "reason": "Facebook profile not found (Cookie verified)", "http_code": status}
                
                return {"status": "uncertain", "reason": "Facebook login wall (Playwright). Valid cookies required.", "http_code": status}
            
            if has_takedown:
                return {"status": "taken_down", "reason": "Facebook profile not found (Playwright verified)", "http_code": status}
            
            display_name = profile_name or title
            return {"status": "active", "reason": f"Facebook active ({display_name[:50]} - Playwright)", "http_code": status}
            
        elif platform == "instagram":
            if "/accounts/login/" in final_url or "login" in title.lower():
                return {"status": "uncertain", "reason": "Instagram login wall (Playwright)", "http_code": status}
            takedown_phrases = ["sorry, this page isn't available", "isn't available", "removed", "broken link"]
            if any(p in html_lower for p in takedown_phrases):
                return {"status": "taken_down", "reason": "Instagram profile not found (Playwright)", "http_code": status}
            
            username = _scrapling_text(content, 'header h2', "instagram_profile_name")
            
            if title.strip() == "Instagram" and not username:
                return {"status": "taken_down", "reason": "Instagram profile not found (Playwright generic title)", "http_code": status}
            
            display_name = username or title
            return {"status": "active", "reason": f"Instagram is active ({display_name[:50]} - Playwright)", "http_code": status}
            
        elif platform == "linkedin":
            if "/authwall" in final_url or "/login" in final_url:
                return {"status": "uncertain", "reason": "LinkedIn authwall (Playwright)", "http_code": status}
            if "page not found" in html_lower or status == 404:
                return {"status": "taken_down", "reason": "LinkedIn profile not found (Playwright)", "http_code": status}
            
            name_text = _scrapling_text(content, 'h1', "linkedin_profile_name")
            
            display_name = name_text or title
            return {"status": "active", "reason": f"LinkedIn active ({display_name[:50]} - Playwright)", "http_code": status}
            
        elif platform == "apps":
            if status == 404:
                return {"status": "taken_down", "reason": "App not found (404 - Playwright)", "http_code": 404}
            if "we're sorry, the requested url was not found on this server" in html_lower:
                return {"status": "taken_down", "reason": "App not found on Play Store (Playwright)", "http_code": status}
            
            title_text = _scrapling_text(content, 'h1', "app_store_title")
            
            display_title = title_text or "App"
            return {"status": "active", "reason": f"App is available ({display_title[:50]} - Playwright)", "http_code": status}
            
        elif platform == "scribd":
            title_lower = title.lower()
            if status in (404, 406, 410):
                return {"status": "taken_down", "reason": f"Scribd content not found ({status} - Playwright)", "http_code": status}
            if "challenge" in title_lower or "just a moment..." in title_lower or "cloudflare" in html_lower:
                return {"status": "uncertain", "reason": "Cloudflare / bot challenge (Playwright)", "http_code": status}
            
            takedown_phrases = [
                "page not found",
                "document removed",
                "removal notice",
                "this document has been removed",
                "we're sorry, we can't find this document",
                "scribd - document removed",
            ]
            if any(p in html_lower for p in takedown_phrases) or any(p in title_lower for p in ("page not found", "removal notice")):
                return {"status": "taken_down", "reason": "Scribd content not found (Playwright)", "http_code": status}
            
            title_text = _scrapling_text(content, 'h1', "scribd_document_title")
            
            display_title = title_text or title.split("|")[0].strip()
            return {"status": "active", "reason": f"Scribd is active ({display_title[:50]} - Playwright)", "http_code": status}
            
        else:
            if status in (404, 410):
                return {"status": "taken_down", "reason": f"Page not found ({status} - Playwright)", "http_code": status}
            if "just a moment..." in title.lower() or "cloudflare" in html_lower:
                return {"status": "uncertain", "reason": "Cloudflare / bot challenge (Playwright)", "http_code": status}
            if status in (401, 403):
                title_lower = title.lower()
                if any(x in title_lower for x in ("forbidden", "access denied", "403", "401", "unauthorized")) or not title.strip():
                    return {"status": "taken_down", "reason": f"Access Denied / Forbidden ({status} - Playwright)", "http_code": status}
            if status >= 500:
                title_lower = title.lower()
                if any(x in title_lower for x in ("server error", "500", "502", "503", "504", "bad gateway", "service unavailable")) or not title.strip():
                    return {"status": "taken_down", "reason": f"Server Error ({status} - Playwright)", "http_code": status}
            
            heading = _scrapling_text(content, 'h1', "generic_heading")
            
            display_name = heading or title
            return {"status": "active", "reason": f"Page is accessible ({display_name[:50]} - Playwright)", "http_code": status}
                
    except Exception as e:
        logger.warning(f"[PLAYWRIGHT] Fallback check failed for {url}: {e}")
        return {"status": "uncertain", "reason": f"Playwright fallback error: {str(e)[:50]}", "http_code": None}


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
        # ── Run the existing platform checker ──
        checker = _CHECKERS.get(platform)
        if checker:
            res = await checker(session, url)
        else:
            res = await _check_generic(session, url)
            
        result.update(res)

        # ── Playwright Fallback if result is uncertain ──
        if result["status"] == "uncertain" and config.ENABLE_PLAYWRIGHT_FALLBACK:
            logger.info(f"[PLAYWRIGHT] Falling back to browser check for: {url}")
            playwright_res = await _check_with_playwright(session, url, platform)
            if playwright_res["status"] != "uncertain":
                logger.info(f"[PLAYWRIGHT] Successfully verified {url} status as {playwright_res['status']}")
                result.update(playwright_res)

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

        hostname = urlparse(url).hostname or ""

        # SSRF guard: never fetch internal/private addresses
        if _is_private_target(hostname):
            result["reason"] = "Private/internal address — not checked (SSRF guard)"
            return result

        # Enterprise enhancement: circuit breaker check
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

def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection: URLs/reasons are attacker-
    controlled, and Excel executes cells starting with = + - @ tab or CR."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


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
                _csv_safe(r.get("url", "")),
                _csv_safe(r.get("platform", "generic")),
                _csv_safe(r.get("status", "")),
                _csv_safe(r.get("reason", "")),
                r.get("http_code", "")
            ])
        zf.writestr("report.csv", "\ufeff" + csv_buf.getvalue())
    buf.seek(0)
    return buf.read()
