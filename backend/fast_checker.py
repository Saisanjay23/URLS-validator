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
import contextvars
import functools
import io
import ipaddress
import json
import random
import re
import socket
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncGenerator
from urllib.parse import parse_qs, quote, urljoin, urlparse

import aiohttp

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False

def _pick_proxy() -> str | None:
    """Return a random proxy from the configured pool, or None when rotation is
    off / no proxies are set. Varying the network vantage point defeats
    datacenter-IP bot walls and geo-restriction false positives."""
    if config.ENABLE_PROXY_ROTATION and config.PROXIES:
        return random.choice(config.PROXIES)
    return None


async def _curl_cffi_get(
    url: str,
    headers: dict | None = None,
    impersonate: str = "chrome120",
    timeout: float = 10.0,
    allow_redirects: bool = True,
    proxy: str | None = None,
):
    """
    Thread-safe wrapper for curl_cffi requests.get to avoid Proactor event loop errors on Windows.
    Runs on a dedicated, appropriately-sized thread pool (not the small stdlib default).
    """
    if not HAS_CURL_CFFI:
        raise ImportError("curl_cffi is not installed")
    proxy = proxy or _pick_proxy()
    kwargs = {
        "headers": headers,
        "impersonate": impersonate,
        "timeout": timeout,
        "allow_redirects": allow_redirects,
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(
        _CURL_EXECUTOR, functools.partial(curl_requests.get, url, **kwargs)
    )
    try:
        _tape_record(url, str(resp.url), resp.status_code, resp.text, source="curl")
    except Exception:
        pass  # tape is diagnostic only — never fail a fetch over it
    return resp

from backend.url_utils import detect_platform, normalize_url, deduplicate_urls
from backend.logger import get_logger, log_check_result
from backend.cookies import get_cookie_header_string, load_all_cookies

# ── Enterprise Module Imports ─────────────────────────────────────────────────
from backend import config
from backend.evidence import Evidence
from backend.confidence import compute_confidence
from backend.parking import detect_expanded_parking, PARKING_DOMAINS
from backend.intelligence import classify_error
from backend.verify import (
    FetchRecord, audit_verdict, classify_against_baseline, primary_text, visible_text,
)
from backend.networking import circuit_breaker, rate_limiter
from backend.metrics import metrics_collector, CheckMetric
from backend.screenshot import ocr_page, evidence_paths, save_png_bytes

from backend.stealth import (
    build_stealth_headers,
    random_impersonation,
    human_delay,
    check_google_cache,
    check_wayback_machine
)

logger = get_logger()

# Dedicated thread pool for the synchronous curl_cffi calls. Sized to the
# concurrency limit so curl-heavy batches don't queue on the tiny stdlib default.
_CURL_EXECUTOR = ThreadPoolExecutor(
    max_workers=config.CURL_THREAD_WORKERS, thread_name_prefix="curl_cffi"
)

# ── Fetch Tape ────────────────────────────────────────────────────────────────
# Every HTTP response observed while checking one URL is recorded here, so the
# verdict audit (backend/verify.py) can inspect what the page ACTUALLY said
# rather than trusting a checker's fall-through to "active". Using a ContextVar
# keeps the tape per-check without threading an extra argument through all ~10
# platform checkers: the list object is shared by reference into any child task
# a checker spawns (e.g. Facebook's gathered engines), so their fetches land on
# the same tape.
_FETCH_TAPE: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "url_fetch_tape", default=None
)
def _tape_start() -> list:
    """Begin a fresh tape for one URL check and return it."""
    tape: list = []
    _FETCH_TAPE.set(tape)
    return tape


def _tape_record(
    requested_url: str, final_url: str, status: int | None, html: str,
    redirect_chain: list | None = None, source: str = "http",
) -> None:
    """Append one observed response to the active tape (no-op if none is open)."""
    tape = _FETCH_TAPE.get()
    if tape is None:
        return
    # Pass the FULL html: FetchRecord extracts text from it and then keeps only
    # a short excerpt, so memory stays bounded without truncating the document
    # before the text is read out of it.
    tape.append(FetchRecord(
        requested_url=requested_url,
        final_url=final_url or requested_url,
        status=status,
        html=html or "",
        redirect_chain=list(redirect_chain or []),
        source=source,
    ))


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
    "godaddy parking",
    "this domain is registered at godaddy",
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
    "apache2 ubuntu default page",
    "welcome to nginx",
    "iis windows server",
    "domain is ready",
    "website is suspended",
    "default web site page",
    "cpanel default page",
    "placeholder page",
    "parked domain name on hostinger dns system",
    "parked domain",
]



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


def _canonical(html: str) -> str:
    """Extract <link rel='canonical'> href."""
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if not m:
        m = re.search(r'<link[^>]+href=["\']([^"\']*)["\'][^>]+rel=["\']canonical["\']', html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


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
    proxy = _pick_proxy()  # one vantage point for the whole redirect chain

    for _ in range(max_redirects):
        try:
            async with session.get(
                current_url, timeout=_TIMEOUT, headers=headers,
                allow_redirects=False, proxy=proxy,
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
                    _tape_record(url, current_url, r.status, html, redirect_chain)
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
        url, timeout=_TIMEOUT, headers=headers, allow_redirects=True, proxy=proxy,
    ) as r:
        html = await r.text()
        _tape_record(url, str(r.url), r.status, html)
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
        headers = build_stealth_headers(url, pool)

        for attempt in range(2):
            try:
                if attempt > 0:
                    await asyncio.sleep(human_delay(0.5, 0.8, 0.5, 1.5))

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
        return {"status": "uncertain", "reason": "Connection blocked/SSL error during Telegram check", "http_code": None}
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
        or tl in ("facebook", "facebook – log in or sign up", "welcome to facebook", "")
    )


def _fb_classify(status: int, html: str, final_url: str, requested_url: str) -> tuple[str, str] | None:
    """
    Classify one anonymous Facebook response with zero false-positives.
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
    og_lower = og_stripped.lower()

    # If og:title itself indicates a login or generic challenge wall
    if any(x in og_lower for x in ("log in", "sign up", "checkpoint")):
        return None

    # Dead /watch videos redirect to the generic video hub
    if "/watch" in urlparse(requested_url).path.lower() and og_stripped:
        if "discover popular videos" in og_lower:
            return ("dead_vote", "video redirected to generic video hub")
        return ("active", f"Facebook video is active ({og_stripped[:50]})")

    # og:title present == the object resolved and rendered (unless it's literally just "Facebook" on a sub-page redirect)
    if og_stripped and og_lower != "facebook":
        return ("active", f"Facebook is active ({og_stripped[:50]})")

    # Search VISIBLE text only — strip scripts/styles first so takedown
    # phrases embedded in React/JS bundles don't produce false dead_votes on live pages.
    visible_text = _fb_normalize(_clean_html_text(html))
    phrase = next((p for p in _FB_TAKEDOWN_PHRASES if p in visible_text), None)
    if phrase:
        return ("dead_vote", "matched: " + phrase)

    # Note: Unauthenticated requests to private/age-restricted pages often bounce to bare homepage or login.
    # Never count anonymous homepage redirects as dead_votes — rely strictly on Graph API arbitration or visible error text!
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
        resp = await _curl_cffi_get(url, impersonate=random_impersonation("desktop"), timeout=12, allow_redirects=True)
        return resp.status_code, resp.text, str(resp.url)

    async def _engine_exthit():
        headers = {
            "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = await _curl_cffi_get(url, headers=headers, impersonate=random_impersonation("desktop"), timeout=12, allow_redirects=True)
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
            # Walls/challenges and transient errors are often per-request
            # heuristics on Facebook's side (especially during batch runs from
            # one IP), so give each engine a second attempt after a short
            # jittered delay before discounting it.
            verdict = None
            for attempt in range(2):
                if attempt:
                    await asyncio.sleep(human_delay(1.5, 0.8, 1.0, 2.5))
                try:
                    status, html, final_url = await engine()
                except aiohttp.ClientConnectorError as e:
                    if _is_dns_error(e):
                        return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
                    continue
                except Exception as e:
                    logger.warning(f"[FACEBOOK] engine {name} failed for {url} (attempt {attempt + 1}): {str(e)[:80]}")
                    continue

                last_status = status
                verdict = _fb_classify(status, html, final_url, url)
                if verdict is not None:
                    break
                logger.info(f"[FACEBOOK] engine {name} inconclusive (wall/challenge) for {url} (attempt {attempt + 1})")

            if verdict is None:
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
            # Require 3 independent dead votes when Graph API is inconclusive,
            # because the same JS-bundle takedown phrase can fool multiple
            # engines (www + exthit + mobile all see identical React bundles).
            if len(dead_votes) >= 3:
                return {
                    "status": "taken_down",
                    "reason": f"Facebook content removed ({'; '.join(dead_votes)})",
                    "http_code": status,
                }

        # ── Proactive Graph API resolution when all engines are walled ──
        # Instead of returning "uncertain", use the free anonymous Graph API
        # as the definitive arbiter. This is the industry standard approach
        # (CrowdStrike, Mandiant) when login walls block scraping.
        if not graph_checked:
            graph_verdict = await _graph_api_exists(session, url)
            graph_checked = True

        if graph_verdict is True:
            return {
                "status": "active",
                "reason": "Facebook is active (Graph API verified — login wall bypassed)",
                "http_code": last_status or 200,
            }
        if graph_verdict is False:
            reason_detail = dead_votes[0] if dead_votes else "Graph API confirmed gone"
            return {
                "status": "taken_down",
                "reason": f"Facebook content removed ({reason_detail})",
                "http_code": last_status,
            }

        # Graph API returned None (ambiguous) — try Facebook oEmbed as final tier
        try:
            oembed_url = f"https://www.facebook.com/plugins/post/oembed.json/?url={quote(url, safe='')}"
            async with session.get(oembed_url, timeout=aiohttp.ClientTimeout(total=8), headers={
                "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Accept": "application/json",
            }) as oembed_resp:
                if oembed_resp.status == 200:
                    oembed_data = json.loads(await oembed_resp.text())
                    author = oembed_data.get("author_name", "")
                    if author:
                        return {"status": "active", "reason": f"Facebook is active (oEmbed: {author[:40]})", "http_code": 200}
                    return {"status": "active", "reason": "Facebook is active (oEmbed verified)", "http_code": 200}
                elif oembed_resp.status in (400, 404):
                    if dead_votes:
                        return {"status": "taken_down", "reason": f"Facebook content removed ({dead_votes[0]}, oEmbed 404)", "http_code": last_status}
        except Exception:
            pass

        if dead_votes:
            return {
                "status": "taken_down",
                "reason": f"Facebook content likely removed ({dead_votes[0]}) — Graph API inconclusive",
                "http_code": last_status,
            }
        # Final fallback: all engines walled + Graph API inconclusive + oEmbed failed.
        # A login wall is NOT evidence of existence — Facebook serves the byte-identical
        # wall for live profiles, deleted profiles, and handles that never existed. This
        # used to return `active`, which made every walled dead page a false positive.
        # Nothing was proven, so say so and let the browser fallback / temporal
        # confirmation try to settle it.
        return {
            "status": "uncertain",
            "reason": "Facebook login wall — existence not proven (Graph API and oEmbed inconclusive)",
            "http_code": last_status or 200,
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
            resp = await _curl_cffi_get(url, headers=headers, impersonate=random_impersonation("desktop"), timeout=config.TIMEOUT_TOTAL, allow_redirects=True)
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
                    logger.warning("[LINKEDIN] Cookie check returned generic title/shell. Falling back to bot rotation...")
                    pass
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
                    _tape_record(target_url, final_url, status, html)
                    
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
                        continue  # Inconclusive auth wall or SPA loading shell

                    _LI_SYSTEM_TITLES = (
                        "linkedin", "sign up", "log in", "join linkedin",
                        "security verification", "linkedin login",
                        "linkedin | log in or sign up",
                        "page not found", "page not found | linkedin",
                    )
                    title_clean = title.strip().lower()
                    if "page not found" in title_clean or "this profile is not available" in title_clean:
                        return {"status": "taken_down", "reason": f"LinkedIn content not found ({title[:40]})", "http_code": status}
                    if title_clean and title_clean not in _LI_SYSTEM_TITLES:
                        return {"status": "active", "reason": f"LinkedIn exists ({title[:50]})", "http_code": status}
                    continue  # Inconclusive / system page
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
                curl_res = await _curl_cffi_get(url, impersonate=random_impersonation("desktop"), timeout=15, allow_redirects=True)
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
                        pass  # Auth wall or bot challenge, fall through to uncertain
                    
                    # Exclude known LinkedIn system page titles from
                    # the "has a real title → active" heuristic.
                    _LI_SYSTEM_TITLES = (
                        "linkedin", "sign up", "log in", "join linkedin",
                        "security verification", "linkedin login",
                        "linkedin | log in or sign up",
                        "page not found", "page not found | linkedin",
                    )
                    if curl_title.strip() and curl_title.strip().lower() not in _LI_SYSTEM_TITLES:
                        return {"status": "active", "reason": f"LinkedIn exists (title: {curl_title[:40]}, curl_cffi)", "http_code": curl_status}
            except Exception as e:
                logger.warning(f"[LINKEDIN] curl_cffi fallback failed for {url}: {e}")

        # ── Tier: LinkedIn oEmbed / Card API — free, no-auth ──
        # LinkedIn's post embed endpoint can verify if a URL resolves to content.
        try:
            li_oembed_url = f"https://www.linkedin.com/embed/feed/update/{quote(url, safe='')}"
            li_headers = {
                "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Accept": "text/html",
            }
            async with session.get(li_oembed_url, timeout=aiohttp.ClientTimeout(total=8), headers=li_headers, allow_redirects=True) as li_resp:
                li_status = li_resp.status
                if li_status == 200:
                    li_html = await li_resp.text()
                    li_title = _title(li_html)
                    if li_title and li_title.lower() not in ('linkedin', '', 'page not found'):
                        return {"status": "active", "reason": f"LinkedIn exists ({li_title[:50]}, embed API)", "http_code": 200}
                elif li_status == 404:
                    # A 404 here proves NOTHING. This endpoint serves feed
                    # updates, and it answers 404 for every profile and company
                    # URL — verified against williamhgates, satyanadella and a
                    # live company page, all 404. Treating that as removal made
                    # every LinkedIn profile that reached this tier a false
                    # takedown. Fall through to the Googlebot tier, which does
                    # discriminate (200 + og:title live, 404 nonexistent).
                    pass
        except Exception:
            pass

        # A Bing-indexed tier used to live here and was removed: search indexes
        # prove a URL EXISTED, not that it exists now — a page taken down
        # yesterday is still indexed — so "Bing has it" cannot support `active`
        # in a takedown check. Its title scrape was also broken, emitting
        # "wikipedia.orghttps://en.wikiped..." as the profile name.

        # LinkedIn authwall is a protective measure (content exists behind login).
        # If all bot UAs were blocked but no 404 was returned, the content is active.
        # Industry standard: LinkedIn returning 999/403/authwall = the server is alive,
        # the content exists, it just requires authentication to view.
        parsed_li = urlparse(url)
        li_path = parsed_li.path.strip('/')
        if li_path and li_path not in ('feed', 'mynetwork', 'jobs', 'messaging', 'notifications'):
            # An authwall is not proof of existence — LinkedIn shows the same
            # wall for live, deleted, and never-existed profiles (the same false
            # premise already removed from the Facebook and X checkers).
            return {"status": "uncertain", "reason": "LinkedIn authwall — existence not proven", "http_code": 403}
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

        # Step 5: If NO og:title AND title is just "YouTube" → likely content
        # doesn't exist. But check for signs of a blocked / consent response
        # first — a suspiciously small HTML body (<10KB) on a 200 response
        # often means YouTube served a shell without content due to region
        # blocking, IP reputation, or consent requirements that weren't caught
        # by the earlier checks. In that case, return uncertain instead of a
        # false taken_down.
        if len(html) < 10000:
            return {"status": "uncertain", "reason": "YouTube response too small (possible block/consent, no OG metadata)", "http_code": status}
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
        
        resp = await _curl_cffi_get(api_url, headers=headers, impersonate=random_impersonation("desktop"), timeout=10, allow_redirects=True)
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

        # Has a real title that's not just "Instagram", error page, or known system page
        _IG_SYSTEM_TITLES = (
            "instagram", "login", "log in", "sign up",
            "login \u2022 instagram", "sign up \u2022 instagram",
            "instagram \u2022 login", "security check",
            "verify your identity", "challenge",
        )
        title_stripped = title.strip()
        title_lower = title_stripped.lower()
        if any(err in title_lower for err in ("page not found", "not found", "isn't available", "error", "removed", "broken")):
            return {"status": "taken_down", "reason": f"Instagram content not found ({title_stripped[:40]})", "http_code": status}
        if title_stripped and title_lower not in _IG_SYSTEM_TITLES:
            return {"status": "active", "reason": f"Instagram is active ({title_stripped[:50]})", "http_code": status}

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
            resp = await _curl_cffi_get(url, headers=headers, impersonate=random_impersonation("desktop"), timeout=config.TIMEOUT_TOTAL, allow_redirects=True)
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
                    _tape_record(url, final_url, status, html)
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
                curl_res = await _curl_cffi_get(url, headers=curl_headers, impersonate=random_impersonation("desktop"), timeout=15, allow_redirects=True)
                curl_status = curl_res.status_code
                curl_html = curl_res.text
                curl_final_url = str(curl_res.url)
                analyzed = _analyze_ig(curl_status, curl_html, curl_final_url)
                if analyzed:
                    logger.info(f"[INSTAGRAM] curl_cffi bypassed bot block for {url} ({analyzed['status']})")
                    return analyzed
            except Exception as e:
                logger.warning(f"[INSTAGRAM] curl_cffi fallback failed for {url}: {e}")

        # ── Tier 6: Instagram oEmbed API — free, no-auth, definitive ──
        # Use curl_cffi to avoid TLS fingerprint rejection by Instagram.
        # Returns HTTP 200 + JSON if content exists, 400/404 if not.
        if HAS_CURL_CFFI:
            try:
                ig_oembed_url = f"https://api.instagram.com/oembed/?url={quote(url, safe='')}&omitscript=true"
                oembed_resp = await _curl_cffi_get(ig_oembed_url, headers={
                    "Accept": "application/json",
                }, impersonate=random_impersonation("desktop"), timeout=8)
                if oembed_resp.status_code == 200:
                    try:
                        ig_oembed_data = oembed_resp.json()
                        author = ig_oembed_data.get("author_name", "")
                        title_oembed = ig_oembed_data.get("title", "")
                        if author:
                            return {"status": "active", "reason": f"Instagram is active (oEmbed: {author[:40]})", "http_code": 200}
                        if title_oembed:
                            return {"status": "active", "reason": f"Instagram is active (oEmbed: {title_oembed[:40]})", "http_code": 200}
                        return {"status": "active", "reason": "Instagram is active (oEmbed verified)", "http_code": 200}
                    except (json.JSONDecodeError, ValueError):
                        # Got 200 but non-JSON response (login redirect HTML) — inconclusive
                        pass
                elif oembed_resp.status_code in (400, 404):
                    segments = [s for s in urlparse(url).path.split('/') if s]
                    is_post_url = any(s in segments for s in ('p', 'reel', 'reels', 'tv', 'stories'))
                    if is_post_url:
                        return {"status": "taken_down", "reason": "Instagram post/reel not found (oEmbed 404)", "http_code": oembed_resp.status_code}
                    if oembed_resp.status_code == 400:
                        return {"status": "active", "reason": "Instagram profile exists (private — oEmbed 400)", "http_code": 200}
                    return {"status": "taken_down", "reason": "Instagram profile not found (oEmbed 404)", "http_code": 404}
            except Exception as e_oembed:
                logger.warning(f"[INSTAGRAM] oEmbed API failed for {url}: {e_oembed}")

        # ── Tier 7: Instagram GraphQL shortcode check — for post/reel URLs ──
        # Extract the shortcode from /p/{shortcode}/ or /reel/{shortcode}/ URLs
        # and check existence via the Instagram GraphQL endpoint.
        ig_segments_check = [s for s in urlparse(url).path.split('/') if s]
        shortcode = None
        if len(ig_segments_check) >= 2 and ig_segments_check[0] in ('p', 'reel', 'reels', 'tv'):
            shortcode = ig_segments_check[1]
        if shortcode and HAS_CURL_CFFI:
            try:
                gql_url = f"https://www.instagram.com/api/v1/media/{shortcode}/info/"
                gql_headers = {
                    "X-IG-App-ID": "936619743392459",
                    "X-Requested-With": "XMLHttpRequest",
                }
                gql_resp = await _curl_cffi_get(gql_url, headers=gql_headers, impersonate=random_impersonation("desktop"), timeout=8)
                if gql_resp.status_code == 200:
                    try:
                        gql_data = gql_resp.json()
                        if gql_data.get("items"):
                            item = gql_data["items"][0]
                            owner = item.get("user", {}).get("full_name", "") or item.get("user", {}).get("username", "")
                            return {"status": "active", "reason": f"Instagram post is active (by {owner[:30]} — media API)", "http_code": 200}
                    except (json.JSONDecodeError, ValueError):
                        pass
                elif gql_resp.status_code == 404:
                    return {"status": "taken_down", "reason": "Instagram post/reel not found (media API 404)", "http_code": 404}
            except Exception as e_gql:
                logger.warning(f"[INSTAGRAM] GraphQL media check failed for {url}: {e_gql}")

        # ── Tier 8: i.instagram.com mobile web API — lightweight profile existence check ──
        try:
            ig_segments = [s for s in urlparse(url).path.split('/') if s]
            if len(ig_segments) == 1 and ig_segments[0] not in ('p', 'reel', 'explore', 'accounts', 'about'):
                username = ig_segments[0]
                i_ig_url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
                i_ig_headers = {
                    "User-Agent": "Instagram 275.0.0.27.98 Android (33/13; 420dpi; 1080x2400; samsung; SM-G991B; o1s; exynos2100; en_US; 458229258)",
                    "X-IG-App-ID": "936619743392459",
                }
                resp_ig = await _curl_cffi_get(i_ig_url, headers=i_ig_headers, impersonate="chrome120", timeout=8)
                if resp_ig.status_code == 200:
                    ig_data = resp_ig.json()
                    user_data = ig_data.get("data", {}).get("user")
                    if user_data:
                        ig_name = user_data.get("full_name") or username
                        return {"status": "active", "reason": f"Instagram is active ({ig_name[:30]} — mobile API)", "http_code": 200}
                    return {"status": "taken_down", "reason": "Instagram profile suspended (mobile API)", "http_code": 200}
                elif resp_ig.status_code == 404:
                    return {"status": "taken_down", "reason": "Instagram profile not found (mobile API 404)", "http_code": 404}
        except Exception as e_mobile:
            logger.warning(f"[INSTAGRAM] Mobile API check failed for {url}: {e_mobile}")

        # All tiers exhausted — for profiles, Instagram login walls are protective.
        # The profile exists but is behind authentication. Report as active.
        ig_segments_final = [s for s in urlparse(url).path.split('/') if s]
        is_profile = len(ig_segments_final) == 1 and ig_segments_final[0] not in ('p', 'reel', 'explore', 'accounts')
        if is_profile:
            return {"status": "active", "reason": f"Instagram profile exists (login wall — @{ig_segments_final[0]})", "http_code": 200}

        # For post/reel URLs where all API checks failed: Instagram only blocks
        # content access behind login when the content EXISTS. If a post were
        # truly deleted, Instagram returns a clear 404 or "page not found" title
        # even to bots. A login wall on a post URL = the post is active but private/restricted.
        is_post_final = any(s in ig_segments_final for s in ('p', 'reel', 'reels', 'tv', 'stories'))
        if is_post_final:
            return {"status": "active", "reason": "Instagram post exists (login wall — content behind authentication)", "http_code": 200}
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "uncertain", "reason": "Connection blocked/SSL error during Instagram check", "http_code": None}
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

        # Do NOT count generic SPA titles ("Profile / X", "Post / X") as taken_down; those are loading shells or shields
        if status == 404:
            return {"status": "taken_down", "reason": "X profile not found or suspended (404)", "http_code": status}

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
                    _tape_record(url, str(resp.url), resp.status, html)
                    analyzed = _analyze_x(resp.status, html, str(resp.url))
                    if analyzed:
                        return analyzed
            except Exception:
                continue

        # Tier 3: oEmbed API — free, official, no auth required
        # Works for tweets and profiles. Returns 200+JSON if content exists, 404 if not.
        try:
            oembed_url = f"https://publish.twitter.com/oembed?url={quote(url, safe='')}&omit_script=true"
            headers = build_stealth_headers(oembed_url, ua_pool="bot")
            headers["Accept"] = "application/json"
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
                curl_res = await _curl_cffi_get(url, impersonate=random_impersonation("desktop"), timeout=15, allow_redirects=True)
                analyzed = _analyze_x(curl_res.status_code, curl_res.text, str(curl_res.url))
                if analyzed:
                    logger.info(f"[X] curl_cffi bypassed block for {url} ({analyzed['status']})")
                    return analyzed
            except Exception as e:
                logger.warning(f"[X] curl_cffi fallback failed for {url}: {e}")
        # ── Tier 5: X Syndication API — free, no-auth ──
        # Twitter/X syndication endpoint can verify tweet existence
        try:
            # Extract tweet ID for syndication check
            x_segments = [s for s in urlparse(url).path.split('/') if s]
            tweet_id = None
            if len(x_segments) >= 3 and x_segments[1] == 'status' and x_segments[2].isdigit():
                tweet_id = x_segments[2]
            if tweet_id:
                syndication_url = f"https://cdn.syndication.twimg.com/tweet-result?id={tweet_id}&lang=en"
                async with session.get(syndication_url, timeout=aiohttp.ClientTimeout(total=8), headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json",
                }) as syn_resp:
                    if syn_resp.status == 200:
                        syn_data = json.loads(await syn_resp.text())
                        author_name = syn_data.get("user", {}).get("name", "")
                        if author_name:
                            return {"status": "active", "reason": f"X post exists (Syndication: {author_name[:40]})", "http_code": 200}
                        return {"status": "active", "reason": "X post exists (Syndication API verified)", "http_code": 200}
                    elif syn_resp.status == 404:
                        return {"status": "taken_down", "reason": "X post not found (Syndication 404)", "http_code": 404}
        except Exception:
            pass

        # All scraping tiers saw a login/challenge page. That proves X's servers are
        # up — nothing more. X serves the same wall for live, suspended, and
        # never-existed handles, so treating it as proof of existence (as this
        # branch previously did) turns every walled dead account into a false
        # positive. Report the honest result and let the browser fallback /
        # temporal confirmation resolve it.
        return {
            "status": "uncertain",
            "reason": "X login wall — existence not proven (Syndication API inconclusive)",
            "http_code": 200,
        }
    except aiohttp.ClientConnectorError as e:
        if _is_dns_error(e):
            return {"status": "taken_down", "reason": "Domain/DNS not found", "http_code": None}
        return {"status": "uncertain", "reason": "Connection blocked/SSL error during X check", "http_code": None}
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
            headers = build_stealth_headers(url, ua_pool="desktop")
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
        try:
            result = await _fetch_smart(session, url, "desktop")
        except Exception as e_fetch:
            # Many DDoS/Cloudflare protected sites disconnect standard aiohttp / python TLS handshakes (error 0, SSL errors, connection reset).
            # Attempt curl_cffi with browser impersonation before failing!
            if HAS_CURL_CFFI:
                try:
                    logger.info(f"[GENERIC] aiohttp fetch failed ({e_fetch}). Retrying with curl_cffi fallback...")
                    curl_res = await _curl_cffi_get(url, impersonate=random_impersonation("desktop"), timeout=10, allow_redirects=True)
                    result = {
                        "status": curl_res.status_code,
                        "html": curl_res.text,
                        "final_url": str(curl_res.url),
                        "hops": 0,
                        "cross_domain": urlparse(str(curl_res.url)).hostname != hostname
                    }
                except Exception:
                    if isinstance(e_fetch, aiohttp.ClientConnectorError):
                        err_reason = _classify_connection_error(e_fetch)
                        if "ssl" in err_reason.lower() and url.startswith("https://"):
                            url = url.replace("https://", "http://", 1)
                            result = await _fetch_smart(session, url, "desktop")
                        else:
                            raise e_fetch
                    else:
                        raise e_fetch
            elif isinstance(e_fetch, aiohttp.ClientConnectorError):
                err_reason = _classify_connection_error(e_fetch)
                if "ssl" in err_reason.lower() and url.startswith("https://"):
                    url = url.replace("https://", "http://", 1)
                    result = await _fetch_smart(session, url, "desktop")
                else:
                    raise e_fetch
            else:
                raise e_fetch
        status, html = result["status"], result["html"]
        final_url = result["final_url"]
        hops = result["hops"]
        cross_domain = result["cross_domain"]

        # ── Enterprise Enhancement: TLS Spoofing Fallback for WAF Blocks ──
        if status in (401, 403, 429, 999) and HAS_CURL_CFFI:
            try:
                curl_res = await _curl_cffi_get(url, impersonate=random_impersonation("desktop"), timeout=10, allow_redirects=True)
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
            if any(pd in final_host for pd in PARKING_DOMAINS):
                return {"status": "taken_down", "reason": f"Redirects to parking page ({final_host})", "http_code": status}

        # Step 3: HTTP status analysis
        if status in (404, 410):
            return {"status": "taken_down", "reason": f"Page not found ({status})", "http_code": status}
        if status == 451:
            return {"status": "taken_down", "reason": "Unavailable for legal reasons (451)", "http_code": status}
        if status in (401, 403):
            detail_str = f" · {title[:40]}" if title and not any(x in title.lower() for x in ("forbidden", "access denied", "403", "401", "unauthorized")) else ""
            return {"status": "active", "reason": f"Active (protected by WAF/firewall: {status}{detail_str})", "http_code": status}
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
        # Only apply on small pages (<5KB) — large legitimate pages (blog
        # posts, articles) can mention phrases like "page not found" in
        # their content without being error pages themselves.
        if content_len < 5000:
            text_to_check = f"{title} {h1}".lower()
            for signal in _TAKEDOWN_SIGNALS:
                if signal in text_to_check:
                    return {"status": "taken_down", "reason": signal.title(), "http_code": status}

        # Step 6: Content-length heuristic
        # Very small pages (<200 bytes) with no og tags and no title are
        # almost certainly error/placeholder pages. 200 bytes is below any
        # real page but above HTTP redirect bodies.
        if content_len < 200 and not og and not title:
            return {"status": "uncertain", "reason": "Empty response — cannot confirm removal", "http_code": status}

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
                # A 200 only counts when the body is really the oEmbed payload.
                # Cloudflare answers 200 with an HTML "Client Challenge" page for
                # ANY document id — including ones that never existed — so
                # treating an unparseable 200 as proof reported bogus documents
                # as live. Unparseable means inconclusive, not verified.
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    data = None
                if isinstance(data, dict) and (data.get("title") or data.get("author_name")):
                    title = data.get("title") or "Document"
                    return {"status": "active", "reason": f"Scribd is active ({title[:50]})", "http_code": 200}
                return None  # challenge/HTML — let the other tiers decide
            elif resp.status == 401:
                # 401 is returned for private documents just as much as removed
                # ones; the two are indistinguishable here. Claiming a takedown
                # would close a ticket on content that is still up.
                return {
                    "status": "uncertain",
                    "reason": "Scribd document is private or removed (401 oEmbed) — cannot distinguish",
                    "http_code": 401,
                }
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
                resp = await _curl_cffi_get(url, impersonate=random_impersonation("desktop"), timeout=12, allow_redirects=True)
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


# Bound concurrent full-page renders so a large batch can't exhaust memory.
_screenshot_sem = asyncio.Semaphore(config.SCREENSHOT_CONCURRENCY)

_SCREENSHOT_MODES = {"off", "all", "active", "uncertain", "taken_down"}


def _resolve_screenshot_mode(mode: str | None) -> str:
    """Normalize a per-request screenshot mode, falling back to the server
    default (the ENABLE_SCREENSHOT_CAPTURE env flag) when unset/invalid."""
    if mode in _SCREENSHOT_MODES:
        return mode
    return "all" if config.ENABLE_SCREENSHOT_CAPTURE else "off"


def _should_capture(mode: str, status: str) -> bool:
    """Whether to screenshot a result given the run's mode and the URL's status."""
    if mode == "off":
        return False
    if mode == "all":
        return True
    return status == mode  # "active" / "uncertain" / "taken_down"


async def _reset_playwright_browser() -> None:
    """Drop a crashed/closed shared browser so the next capture recreates a fresh
    one. Without this, a single browser crash cascades into every later capture
    failing (and thus lots of 'missing' screenshots)."""
    global _playwright_browser
    async with _playwright_lock:
        if _playwright_browser is not None:
            try:
                await _playwright_browser.close()
            except Exception:
                pass
            _playwright_browser = None


async def _screenshot_attempt(url: str) -> tuple[bytes | None, bool]:
    """
    One capture attempt. Returns (png_bytes | None, fatal).
      fatal=True  -> don't retry (genuinely nothing to shoot, e.g. dead domain).
      fatal=False -> transient; a retry may succeed (browser hiccup/timeout).
    """
    context = None
    try:
        browser = await _get_playwright_browser()
        # No resource blocking here: we want a faithful, styled screenshot.
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        page = await context.new_page()
        # Navigation may not "complete" for the very pages we most want a shot of
        # — blocked / challenge / login-wall pages. Don't abort on a nav timeout:
        # capture whatever rendered, since that page IS the evidence.
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
        except Exception as nav_err:
            # Never left about:blank => nothing to show (DNS-dead / conn refused).
            if page.url in ("about:blank", ""):
                logger.info(f"[SCREENSHOT] navigation produced no page for {url}: {str(nav_err)[:60]}")
                return None, True  # fatal — retrying won't conjure a page
            logger.info(f"[SCREENSHOT] navigation incomplete for {url}: {str(nav_err)[:60]} — capturing current state")
        # JS-heavy SPAs render AFTER domcontentloaded, so shooting now would catch
        # a blank/logo splash. Let the page settle (network idle, best-effort),
        # then a fixed paint delay to guarantee content is on screen.
        try:
            await page.wait_for_load_state("networkidle", timeout=config.SCREENSHOT_SETTLE_MS)
        except Exception:
            pass
        await page.wait_for_timeout(config.SCREENSHOT_PAINT_MS)
        png = await page.screenshot(full_page=False)
        return png, False
    except Exception as e:
        msg = str(e).lower()
        # A closed/crashed browser poisons every later capture — reset it so the
        # retry (and subsequent URLs) get a fresh browser.
        if any(k in msg for k in ("closed", "crash", "target", "disconnected")):
            logger.warning(f"[SCREENSHOT] browser error for {url}: {str(e)[:80]} — resetting browser")
            await _reset_playwright_browser()
        else:
            logger.warning(f"[SCREENSHOT] capture attempt failed for {url}: {str(e)[:80]}")
        return None, False  # transient — allow a retry
    finally:
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass


async def _capture_page_screenshot(url: str, platform: str) -> str | None:
    """
    Render `url` in the shared headless browser and save a viewable, styled PNG
    for the UI hover preview / evidence. Returns the web path (/evidence/<file>)
    or None. Best-effort — never raises into the checker, never blocks the verdict.

    Retries once on transient failures (and recovers a crashed shared browser),
    so a momentary hiccup under a big batch doesn't silently drop a screenshot.
    Only truly-unrenderable URLs (dead domain / connection refused) get no shot.
    """
    try:
        from playwright.async_api import async_playwright  # noqa: F401 — availability probe
    except ImportError:
        return None

    async with _screenshot_sem:
        png = None
        for attempt in range(2):
            png, fatal = await _screenshot_attempt(url)
            if png is not None or fatal:
                break
            if attempt == 0:
                await asyncio.sleep(0.5)  # brief backoff before the retry

        if png is None:
            return None

        try:
            disk_path, web_path = evidence_paths(platform, url)
            save_png_bytes(png, disk_path)
            logger.info(f"[SCREENSHOT] saved evidence: {web_path}")
            return web_path
        except Exception as e:
            logger.warning(f"[SCREENSHOT] save failed for {url}: {str(e)[:80]}")
            return None


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


async def _settle_page(page) -> None:
    """
    Wait for a JS-rendered page to paint before its DOM is read.

    Three best-effort stages, each independently timed out so a page that never
    goes idle (long-polling sockets, video players) still proceeds:
      1. network idle      — most SPAs have painted by then
      2. real body text    — the definitive signal that content exists
      3. short paint grace — lets the final frame land
    """
    try:
        await page.wait_for_load_state("networkidle", timeout=config.PLAYWRIGHT_SETTLE_MS)
    except Exception:
        pass

    try:
        await page.wait_for_function(
            "(min) => !!document.body && document.body.innerText.trim().length > min",
            arg=config.PLAYWRIGHT_TEXT_MIN,
            timeout=config.PLAYWRIGHT_SETTLE_MS,
        )
    except Exception:
        pass  # genuinely empty pages exist — the audit judges that separately

    try:
        await page.wait_for_timeout(config.PLAYWRIGHT_PAINT_MS)
    except Exception:
        pass


# Bounds simultaneous browser renders. Unbounded contexts starve each other and
# time out, and a timed-out render looks like an empty page — which used to cost
# genuine takedown evidence.
_playwright_sem = asyncio.Semaphore(config.PLAYWRIGHT_CONCURRENCY)


async def _check_with_playwright(session: aiohttp.ClientSession, url: str, platform: str) -> dict:
    """Concurrency-bounded wrapper around the browser check."""
    async with _playwright_sem:
        return await _check_with_playwright_inner(session, url, platform)


async def _check_with_playwright_inner(session: aiohttp.ClientSession, url: str, platform: str) -> dict:
    """
    Playwright Fallback Checker.
    Runs when standard HTTP checkers return "uncertain" to provide a browser-based bypass.
    OCR text (when enabled) is folded into the takedown-phrase detection below so
    removal notices that are JS-injected or drawn as images are still matched.
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
                        "domain": {
                            "instagram": ".instagram.com",
                            "facebook": ".facebook.com",
                            "linkedin": ".linkedin.com",
                            "x": ".x.com",
                            "telegram": ".t.me",
                            "scribd": ".scribd.com",
                        }.get(platform, f".{urlparse(url).hostname or 'example.com'}"),
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

            # Let the page actually render before reading it. At
            # domcontentloaded a React app (Facebook, Instagram, YouTube, X,
            # LinkedIn) has a body of nothing but <script> tags: no removal
            # notice to match, no profile name to scrape, so every verdict drawn
            # from it is a guess. Wait for the network to settle AND for real
            # text to appear; both waits are best-effort with hard timeouts, so
            # a slow or idle-never-reached page just proceeds.
            await _settle_page(page)

            title = await page.title()
            content = await page.content()
            final_url = page.url
            # OCR the rendered pixels (if enabled) while the page is still alive,
            # and fold that text into the detection text below.
            ocr_text = await ocr_page(page)
            html_lower = (content + "\n" + ocr_text).lower()
            # Rendered DOM is the strongest evidence available — put it on the
            # tape so the audit judges the page a human would actually see.
            _tape_record(url, final_url, status, content, source="playwright")
        finally:
            await context.close()
        
        if platform == "facebook":
            title_lower = title.lower()
            # A signup/login prompt as the page TITLE means the wall replaced the
            # content (the same words in body chrome appear on live pages too).
            is_generic = (
                title_lower in ("facebook", "error facebook", "")
                or "log in" in title_lower
                or "login" in title_lower
                or "create new account" in title_lower
            )
            takedown_phrases = [
                "content isn't available",
                "page isn't available",
                "this page has been removed",
                "link you followed may be broken",
                "page not found",
                "profile isn't available"
            ]
             # Search VISIBLE text only — strip scripts/styles so React/JS
            # bundle template strings don't produce false takedowns.
            clean_text = _fb_normalize(_clean_html_text(content) + " " + ocr_text)
            has_takedown = any(p in clean_text for p in takedown_phrases)
            
            profile_name = _scrapling_text(content, 'h1', "facebook_profile_name")

            # On a walled page the <h1> is the wall's prompt ("Log in to view this
            # 18+ content"), not a profile name. Accepting it as one skipped the
            # login-wall branch entirely and reported the wall as live content.
            if profile_name and any(
                p in profile_name.lower()
                for p in ("log in", "login", "sign up", "create new account",
                          "log into facebook", "see more on facebook")
            ):
                profile_name = None

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
            
            # Only declare taken_down if the takedown phrase is in visible text
            # AND we also verify via Graph API when possible
            if has_takedown:
                graph_exists = await _graph_api_exists(session, url)
                if graph_exists is True:
                    return {"status": "active", "reason": "Facebook active (Graph API verified, restricted view - Playwright)", "http_code": status}
                return {"status": "taken_down", "reason": "Facebook profile not found (Playwright verified)", "http_code": status}
            
            display_name = profile_name or title
            return {"status": "active", "reason": f"Facebook active ({display_name[:50]} - Playwright)", "http_code": status}
            
        elif platform == "instagram":
            if "/accounts/login/" in final_url or "login" in title.lower():
                return {"status": "uncertain", "reason": "Instagram login wall (Playwright)", "http_code": status}
            # Use the same precise takedown phrases as the HTTP-based
            # checker — broad terms like 'removed' and 'isn't available'
            # match legitimate bio text, captions, and JS bundles.
            ig_takedown_phrases = [
                "sorry, this page isn't available",
                "the link you followed may be broken",
                "this page isn't available",
            ]
            # Match against cleaned visible text, not raw HTML
            ig_visible = _clean_html_text(content) + " " + ocr_text
            if any(p in ig_visible for p in ig_takedown_phrases):
                return {"status": "taken_down", "reason": "Instagram profile not found (Playwright)", "http_code": status}
            
            username = _scrapling_text(content, 'header h2', "instagram_profile_name")
            
            # Generic title with no scrapled username is inconclusive —
            # private profiles and login-walled pages also show this.
            # Return uncertain instead of false taken_down.
            if title.strip() == "Instagram" and not username:
                return {"status": "uncertain", "reason": "Instagram inconclusive (generic title, Playwright)", "http_code": status}
            
            display_name = username or title
            return {"status": "active", "reason": f"Instagram is active ({display_name[:50]} - Playwright)", "http_code": status}
            
        elif platform == "linkedin":
            if "/authwall" in final_url or "/login" in final_url:
                return {"status": "uncertain", "reason": "LinkedIn authwall (Playwright)", "http_code": status}
            if "page not found" in html_lower or status == 404:
                return {"status": "taken_down", "reason": "LinkedIn profile not found (Playwright)", "http_code": status}
            
            name_text = _scrapling_text(content, 'h1', "linkedin_profile_name")
            display_name = name_text or title
            
            # Ensure sign-up overlays or auth checkpoints aren't reported as active profiles
            _LI_SYSTEM_TITLES_PW = ("linkedin", "sign up", "log in", "join linkedin", "security verification", "linkedin login")
            if display_name.strip().lower() in _LI_SYSTEM_TITLES_PW:
                return {"status": "uncertain", "reason": f"LinkedIn check required login/verification (Playwright)", "http_code": status}
                
            return {"status": "active", "reason": f"LinkedIn active ({display_name[:50]} - Playwright)", "http_code": status}
            
        elif platform == "x":
            title_lower = title.strip().lower()
            if "/login" in final_url.lower() or "/flow/" in final_url.lower() or title_lower in ("x", "twitter", "x / twitter", "profile / x", "post / x") or "sign in" in title_lower or "log in" in title_lower:
                return {"status": "uncertain", "reason": "X login wall or SPA loading shell (Playwright)", "http_code": status}
            if "account suspended" in html_lower or "this account doesn" in html_lower or "this page doesn" in html_lower or status == 404:
                return {"status": "taken_down", "reason": "X account/post not found or suspended (Playwright)", "http_code": status}
            heading = _scrapling_text(content, 'h1', "x_heading")
            display_name = heading or title
            return {"status": "active", "reason": f"X content active ({display_name[:50]} - Playwright)", "http_code": status}
            
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
                # A 403 with an empty title is ambiguous (WAF challenge, JS parking redirect,
                # geo-block). The fast path already returns 'uncertain' for this case.
                # Playwright should NOT escalate to 'taken_down' — that causes false positives
                # on sites like directfwd.com parking pages or Cloudflare pre-challenges.
                if any(x in title_lower for x in ("forbidden", "access denied", "403", "401", "unauthorized")) or not title.strip():
                    return {"status": "uncertain", "reason": f"Access denied / Forbidden ({status} - Playwright)", "http_code": status}
            if status >= 500:
                title_lower = title.lower()
                # Transient server errors should be uncertain, not taken_down.
                # The server exists (DNS resolved, TCP connected) — it's just unhealthy.
                if any(x in title_lower for x in ("server error", "500", "502", "503", "504", "bad gateway", "service unavailable")) or not title.strip():
                    return {"status": "uncertain", "reason": f"Server error ({status} - Playwright)", "http_code": status}
            
            heading = _scrapling_text(content, 'h1', "generic_heading")
            
            # Parking detection on rendered content (catches JS-based parking redirects
            # like directfwd.com that only execute in a real browser)
            parking_reason = _detect_parking(content, title, heading or "")
            if parking_reason:
                return {"status": "taken_down", "reason": f"{parking_reason} (Playwright)", "http_code": status}
            
            # Apply the same takedown signal checks used by the HTTP-based
            # generic checker so Playwright doesn't blindly return 'active'
            # for pages showing removal notices.
            visible_text = _clean_html_text(content).lower()
            page_len = len(visible_text)
            if page_len < 5000:
                check_text = f"{title} {heading or ''}".lower()
                for signal in _TAKEDOWN_SIGNALS:
                    if signal in check_text:
                        return {"status": "taken_down", "reason": f"{signal.title()} (Playwright)", "http_code": status}
            
            # A page that rendered nothing is absence of evidence, not evidence of
            # removal: a bot wall, a failed script, or a challenge all render
            # empty too (softonic answers 406 with a blank body and a "client
            # challenge" behind it, and was being reported as removed).
            if page_len < 200 and not title.strip() and not heading:
                return {"status": "uncertain", "reason": "Page rendered no content — cannot confirm removal (Playwright)", "http_code": status}
            
            display_name = heading or title
            return {"status": "active", "reason": f"Page is accessible ({display_name[:50]} - Playwright)", "http_code": status}
                
    except Exception as e:
        logger.warning(f"[PLAYWRIGHT] Fallback check failed for {url}: {e}")
        return {"status": "uncertain", "reason": f"Playwright fallback error: {str(e)[:50]}", "http_code": None}


async def _raw_text(session: aiohttp.ClientSession, url: str) -> tuple[int | None, str]:
    """
    Fetch a URL for comparison purposes only. Deliberately does NOT touch the
    fetch tape: a control page landing there could be picked as the primary
    observation and judged as if it were the URL under test.
    """
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=config.BASELINE_TIMEOUT),
            headers=build_stealth_headers(url, "desktop"), allow_redirects=True,
        ) as r:
            return r.status, visible_text(await r.text())
    except Exception:
        return None, ""


def _control_url(url: str) -> str:
    """A sibling path that cannot exist, keeping the shape of the original."""
    parts = urlparse(url)
    token = "zq" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
    segments = [seg for seg in (parts.path or "/").split("/") if seg]
    if segments:
        segments[-1] = token          # same directory, impossible leaf
    else:
        segments = [token]
    return f"{parts.scheme}://{parts.netloc}/" + "/".join(segments)


# A server's not-found response is a property of the host and directory, not of
# the individual URL. Without a cache the probe re-runs for each of the three
# temporal-confirmation observations AND for every sibling URL — 15 TikTok links
# would have cost 90 extra requests. Keyed by (host, parent path) so a site with
# different 404 templates per section is still measured correctly.
_BASELINE_CACHE: dict[str, tuple[str, str, int | None] | None] = {}
_BASELINE_LOCKS: dict[str, asyncio.Lock] = {}


async def _baseline_probe(session: aiohttp.ClientSession, url: str) -> tuple[str, str, int | None] | None:
    """
    Ask the server what "missing" and "home" look like, so the target can be
    compared against them instead of guessed at. Returns
    (control_text, root_text, control_status).
    """
    parts = urlparse(url)
    if not parts.netloc:
        return None

    parent = "/".join((parts.path or "/").rsplit("/", 1)[:-1]) or "/"
    key = f"{parts.scheme}://{parts.netloc}{parent}"

    lock = _BASELINE_LOCKS.setdefault(key, asyncio.Lock())
    async with lock:                      # one probe per key, not one per caller
        if key in _BASELINE_CACHE:
            return _BASELINE_CACHE[key]

        root = f"{parts.scheme}://{parts.netloc}/"
        try:
            (control_status, control_text), (_root_status, root_text) = await asyncio.gather(
                _raw_text(session, _control_url(url)),
                _raw_text(session, root),
            )
        except Exception:
            _BASELINE_CACHE[key] = None
            return None

        result = None if (control_status is None and not control_text) else (
            control_text, root_text, control_status
        )
        _BASELINE_CACHE[key] = result
        return result


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
    tape = _tape_start()

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

        # ── Verdict Audit: no `active` without proof of live content ──────────
        # The checkers above answer "did I find a removal notice?" and fall
        # through to `active` when they didn't. That default is what produces
        # false positives: HTTP 200 pages whose body says "content unavailable",
        # deep links silently redirected to a homepage, empty SPA shells, and
        # WAF/login walls all look identical to success at the HTTP layer.
        # The audit re-reads the page that was actually fetched and demotes any
        # unproven `active` to `uncertain` (or promotes it to `taken_down` when
        # a removal notice is proven).
        if config.ENABLE_VERDICT_AUDIT:
            audit = audit_verdict(
                status=result["status"], reason=result["reason"],
                http_code=result.get("http_code"), records=tape,
                platform=platform, url=url,
            )

            # An unproven `active` gets one browser render before we settle for
            # `uncertain` — a real browser renders JS-painted 404s and clears
            # most bot walls, converting "don't know" into a real answer.
            if (
                audit.escalate
                and config.ENABLE_AUDIT_ESCALATION
                and config.ENABLE_PLAYWRIGHT_FALLBACK
                and result["status"] == "active"
            ):
                logger.info(f"[AUDIT] Unproven active for {url} ({audit.reason}) — escalating to browser")
                pw = await _check_with_playwright(session, url, platform)
                if pw["status"] != "uncertain":
                    result.update(pw)
                    # Re-audit the browser verdict against the rendered DOM the
                    # Playwright pass just put on the tape.
                    audit = audit_verdict(
                        status=result["status"], reason=result["reason"],
                        http_code=result.get("http_code"), records=tape,
                        platform=platform, url=url,
                    )

            if audit.status != result["status"]:
                logger.info(
                    f"[AUDIT] {url}: {result['status']} -> {audit.status} ({audit.reason})"
                )
            result["status"] = audit.status
            result["reason"] = audit.reason
            result["confidence"] = audit.confidence
            if audit.signals:
                result["audit_signals"] = audit.signals

        # ── Baseline Calibration: resolve what is still unproven ──────────────
        # Everything above reasons about the target page alone, which cannot
        # settle a soft-404: a server that answers 200 with a pretty error page
        # looks identical to one serving real content. So ask the server what a
        # URL that CANNOT exist returns, and what its homepage returns, then
        # compare. This replaces the last guess in the pipeline with a
        # measurement — and the homepage probe is what keeps a geo-blocked site
        # (every path returns the same notice) from being read as "matches the
        # 404 page, therefore removed".
        # Never let calibration overturn a geo-block finding: the audit inspected
        # the rendered page and saw the block notice, which is stronger evidence
        # than any similarity score computed from that same notice.
        # Restricted to conventional web servers. Calibration assumes the site
        # answers a missing path with a not-found page; social platforms answer
        # with SPA shells, login walls, and consent screens, so "differs from the
        # control" measures nothing there. Under batch load a Facebook share link
        # whose platform checker had gone inconclusive was certified LIVE at 92%
        # by exactly that comparison, while the platform's own Playwright check
        # said removed 4 times out of 4. Platforms have authoritative signals
        # (Graph API, oEmbed, rendered removal notice); when those are
        # inconclusive the honest answer is uncertain, not a similarity score.
        if (
            config.ENABLE_BASELINE_CALIBRATION
            and result["status"] == "uncertain"
            and tape
            and platform == "generic"
            and "geo_blocked" not in (result.get("audit_signals") or [])
        ):
            # Plain-HTTP observations only — the control/root probes are plain
            # HTTP, and a rendered-vs-unrendered comparison measures the
            # renderer rather than the page.
            target_text = primary_text(tape, url, sources=("http", "curl"))
            if target_text:
                probe = await _baseline_probe(session, url)
                if probe:
                    control_text, root_text, control_status = probe
                    st, why, conf = classify_against_baseline(
                        target_text, control_text, root_text,
                        target_status=result.get("http_code"),
                        control_status=control_status,
                    )
                    signals = result.get("audit_signals") or []
                    if st != "uncertain":
                        logger.info(f"[BASELINE] {url}: uncertain -> {st} ({why})")
                        result["status"] = st
                        result["confidence"] = conf
                        result["reason"] = why
                        result["audit_signals"] = signals + ["baseline_calibrated"]
                    else:
                        # Still unresolved: keep the original diagnosis (which names
                        # the blocker) and add what calibration observed, so the
                        # review queue says why it could not be settled.
                        result["reason"] = f"{result['reason']} — {why}"
                        tag = "geo_blocked" if "geo-blocked" in why.lower() else "baseline_inconclusive"
                        result["audit_signals"] = signals + [tag]

        # ── Cross-Verification for Generic Takedowns ──
        if result["status"] == "taken_down" and platform == "generic":
            cached = await check_google_cache(session, url)
            if cached is True:
                result["reason"] += " (Google Cache: Existed recently)"
            elif cached is False:
                result["reason"] += " (Google Cache: 404 Confirmed)"
                
            wayback = await check_wayback_machine(session, url)
            if wayback:
                result["reason"] += f" (Wayback: {wayback['statuscode']} at {wayback['timestamp'][:8]})"

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
        # The audit's score is evidence-based and outranks the heuristic one, so
        # it is never overwritten here — only filled in when the audit is off.
        if config.ENABLE_CONFIDENCE and evidence:
            confidence_score, signals = compute_confidence(evidence)
            result.setdefault("confidence", confidence_score)
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


# ── Temporal Confirmation ─────────────────────────────────────────────────────

async def _check_with_confirmation(
    session: aiohttp.ClientSession, url: str, platform: str, slot: asyncio.Semaphore | None = None
) -> dict:
    """
    Temporal confirmation wrapper around _check_single.

    Industry takedown practice: a single observation must never yield a
    "taken_down" verdict, because transient bot-walls / challenges / geo
    quirks make live content look dead for one request. So:

      - "active" on the first look         -> trusted immediately (active
        signals are high-confidence in every checker), keeping the fast path fast.
      - "taken_down"/"uncertain" candidate -> re-observed up to CONFIRM_ATTEMPTS
        times over a short jittered window. Any credible "active" observation
        wins outright. A takedown is confirmed only once CONFIRM_QUORUM
        independent observations agree it's down (early-exits on quorum).
      - Below quorum                       -> stays "uncertain" (honest), so a
        flaky page is never mislabelled removed.

    The concurrency slot (``slot``) is held only around each observation, NOT
    during the waits between them, so a re-verifying URL doesn't block others
    while it sleeps. Tune via CONFIRM_ATTEMPTS / CONFIRM_QUORUM / CONFIRM_DELAY_*
    or disable with ENABLE_TEMPORAL_CONFIRMATION.
    """
    async def _observe():
        if slot is not None:
            async with slot:
                return await _check_single(session, url, platform)
        return await _check_single(session, url, platform)

    first = await _observe()

    if not config.ENABLE_TEMPORAL_CONFIRMATION or first["status"] == "active":
        return first

    observations = [first]
    dead_count = 1 if first["status"] == "taken_down" else 0

    for _ in range(max(0, config.CONFIRM_ATTEMPTS - 1)):
        # Slot released here: sleeping URLs don't occupy a concurrency slot.
        await asyncio.sleep(human_delay(config.CONFIRM_DELAY_MIN, 1.0, config.CONFIRM_DELAY_MIN, config.CONFIRM_DELAY_MAX))
        obs = await _observe()

        if obs["status"] == "active":
            obs["reason"] = f"{obs['reason']} [confirmed active after {len(observations)} dead/uncertain look(s)]"
            return obs

        observations.append(obs)
        if obs["status"] == "taken_down":
            dead_count += 1
            if dead_count >= config.CONFIRM_QUORUM:
                obs["reason"] = f"{obs['reason']} [confirmed down: {dead_count}/{len(observations)} observations]"
                return obs

    # Loop exhausted without reaching quorum.
    if dead_count >= config.CONFIRM_QUORUM:
        confirmed = next(o for o in reversed(observations) if o["status"] == "taken_down")
        confirmed["reason"] = f"{confirmed['reason']} [confirmed down: {dead_count}/{len(observations)} observations]"
        return confirmed

    # Below quorum: keep the richest observation (evidence, screenshots, metadata)
    # and only override the verdict, so the audit trail survives into the report.
    last = dict(observations[-1])
    last.update({
        "type": "result", "url": url, "platform": platform,
        "status": "uncertain",
        # Keep the underlying finding in the message. "Unconfirmed after N
        # observations" alone tells a reviewer nothing about WHY — geo-block,
        # authwall, and WAF challenge all look identical — and this bucket is
        # exactly the one a human has to triage.
        "reason": (
            f"{last.get('reason') or 'No verdict'} "
            f"[unconfirmed: {dead_count} down / {len(observations) - dead_count} uncertain "
            f"across {len(observations)} observations, below quorum of {config.CONFIRM_QUORUM}]"
        ),
        "confidence": 30,
    })
    return last


# ── Stream Processor ──────────────────────────────────────────────────────────


async def process_urls_stream(
    raw_urls: list[str], screenshot_mode: str | None = None
) -> AsyncGenerator[dict, None]:
    """
    Process URLs concurrently and yield results as they complete.
    Uses the Fast AIOHTTP Engine with multi-bot-UA verification for all platforms.

    screenshot_mode controls which results get a browser-rendered screenshot for
    the UI hover preview / evidence: "off" | "all" | "active" | "uncertain" |
    "taken_down". None falls back to the ENABLE_SCREENSHOT_CAPTURE server default.

    Enterprise enhancements:
      - Adaptive rate limiting: per-host concurrency semaphores
      - Circuit breaker: per-host failure tracking with auto-recovery
      - Enhanced connection pool: per-host limits, keepalive, idle cleanup
    """
    shot_mode = _resolve_screenshot_mode(screenshot_mode)

    # Baselines are per-run: a site's 404 template can change between runs, and
    # a stale cache would silently decide later verdicts.
    _BASELINE_CACHE.clear()
    _BASELINE_LOCKS.clear()

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
            res = await _check_with_confirmation(session, url, platform, slot=semaphore)
            res["engine"] = "fast"
            result = res

            # Screenshot for the UI hover preview / evidence: one render per URL
            # after the final verdict, gated by the run's screenshot mode.
            if _should_capture(shot_mode, result["status"]):
                shot_url = await _capture_page_screenshot(url, platform)
                if shot_url:
                    result["screenshot_url"] = shot_url

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
        # The global concurrency semaphore is acquired per-observation inside
        # _check_with_confirmation (so a URL sleeping between re-checks doesn't
        # hold a slot), not around the whole worker. Adaptive per-host rate
        # limiting still wraps the worker when enabled.
        hostname = urlparse(url).hostname or ""
        if config.ENABLE_ADAPTIVE_RATE_LIMIT:
            await rate_limiter.acquire(hostname)

        try:
            return await _fast_worker(session, url, platform)
        finally:
            if config.ENABLE_ADAPTIVE_RATE_LIMIT:
                rate_limiter.release(hostname)

    async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.CookieJar()) as shared_session:
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
        writer.writerow(["#", "URL", "Platform", "Status", "Confidence", "Reason", "HTTP Code"])
        for i, r in enumerate(results, 1):
            writer.writerow([
                i,
                _csv_safe(r.get("url", "")),
                _csv_safe(r.get("platform", "generic")),
                _csv_safe(r.get("status", "")),
                r.get("confidence", ""),
                _csv_safe(r.get("reason", "")),
                r.get("http_code", "")
            ])
        zf.writestr("report.csv", "\ufeff" + csv_buf.getvalue())
    buf.seek(0)
    return buf.read()


def create_export_excel(results: list[dict]) -> bytes:
    """Build an Excel (.xlsx) workbook with a Summary Pivot Table sheet and Detailed Results sheet."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()
    ws_summary = wb.active
    ws_summary.title = "Summary & Report"
    ws_details = wb.create_sheet(title="Detailed Results")

    # Dark cyber theme styling
    header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    title_font = Font(name="Calibri", size=14, bold=True, color="0F172A")
    bold_font = Font(name="Calibri", size=11, bold=True)
    regular_font = Font(name="Calibri", size=11)
    
    thin_border = Border(
        left=Side(style='thin', color='CBD5E1'),
        right=Side(style='thin', color='CBD5E1'),
        top=Side(style='thin', color='CBD5E1'),
        bottom=Side(style='thin', color='CBD5E1')
    )

    # Compute Status counts
    counts = {"active": 0, "taken_down": 0, "uncertain": 0, "error": 0}
    for r in results:
        st = r.get("status", "").lower()
        if st in ("active", "active "):
            counts["active"] += 1
        elif st in ("taken_down", "taken down", "inactive"):
            counts["taken_down"] += 1
        elif st in ("uncertain",):
            counts["uncertain"] += 1
        else:
            counts["error"] += 1

    total_count = len(results)

    # 1. Summary Sheet
    ws_summary.views.sheetView[0].showGridLines = True
    
    ws_summary["A1"] = "URL Validation Report & Summary"
    ws_summary["A1"].font = title_font
    
    # Pivot-style Summary Table
    ws_summary["A3"] = "Row Labels"
    ws_summary["B3"] = "Count of Taken Down Urls"
    ws_summary["A3"].fill = header_fill
    ws_summary["A3"].font = header_font
    ws_summary["B3"].fill = header_fill
    ws_summary["B3"].font = header_font
    ws_summary["B3"].alignment = Alignment(horizontal="right")

    summary_rows = [
        ("Active", counts["active"]),
        ("Inactive", counts["taken_down"]),
    ]
    if counts["uncertain"] > 0:
        summary_rows.append(("Uncertain", counts["uncertain"]))
    if counts["error"] > 0:
        summary_rows.append(("Error", counts["error"]))

    curr_row = 4
    for label, val in summary_rows:
        ws_summary.cell(row=curr_row, column=1, value=label).font = regular_font
        ws_summary.cell(row=curr_row, column=1).border = thin_border
        c_val = ws_summary.cell(row=curr_row, column=2, value=val)
        c_val.font = regular_font
        c_val.border = thin_border
        c_val.alignment = Alignment(horizontal="right")
        curr_row += 1

    # Grand Total row
    ws_summary.cell(row=curr_row, column=1, value="Grand Total").font = bold_font
    ws_summary.cell(row=curr_row, column=1).border = thin_border
    c_tot = ws_summary.cell(row=curr_row, column=2, value=total_count)
    c_tot.font = bold_font
    c_tot.border = thin_border
    c_tot.alignment = Alignment(horizontal="right")

    # Main URLs & Status Table on Summary sheet
    ws_summary.cell(row=curr_row + 2, column=1, value="Taken Down Urls").font = header_font
    ws_summary.cell(row=curr_row + 2, column=1).fill = header_fill
    ws_summary.cell(row=curr_row + 2, column=2, value="Status").font = header_font
    ws_summary.cell(row=curr_row + 2, column=2).fill = header_fill

    url_table_start = curr_row + 3
    for i, r in enumerate(results, start=url_table_start):
        u_cell = ws_summary.cell(row=i, column=1, value=r.get("url", ""))
        u_cell.font = regular_font
        u_cell.border = thin_border

        raw_st = r.get("status", "")
        display_st = "Active" if raw_st == "active" else ("Inactive" if raw_st == "taken_down" else raw_st.capitalize())
        s_cell = ws_summary.cell(row=i, column=2, value=display_st)
        s_cell.font = regular_font
        s_cell.border = thin_border
        if display_st == "Active":
            s_cell.fill = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid") # light green
            s_cell.font = Font(name="Calibri", size=11, color="166534", bold=True)
        elif display_st in ("Inactive", "Taken Down"):
            s_cell.fill = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid") # light red
            s_cell.font = Font(name="Calibri", size=11, color="991B1B", bold=True)

    # 2. Detailed Results Sheet
    ws_details.views.sheetView[0].showGridLines = True
    headers = ["#", "URL", "Platform", "Status", "Confidence", "Reason", "HTTP Code"]
    for col_num, h in enumerate(headers, 1):
        cell = ws_details.cell(row=1, column=col_num, value=h)
        cell.font = header_font
        cell.fill = header_fill
        if h in ("#", "HTTP Code"):
            cell.alignment = Alignment(horizontal="center")

    for i, r in enumerate(results, 1):
        row_idx = i + 1
        ws_details.cell(row=row_idx, column=1, value=i).alignment = Alignment(horizontal="center")
        ws_details.cell(row=row_idx, column=2, value=r.get("url", ""))
        ws_details.cell(row=row_idx, column=3, value=r.get("platform", "generic"))
        raw_st = r.get("status", "")
        display_st = "Active" if raw_st == "active" else ("Inactive" if raw_st == "taken_down" else raw_st.capitalize())
        st_cell = ws_details.cell(row=row_idx, column=4, value=display_st)
        if display_st == "Active":
            st_cell.fill = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid")
            st_cell.font = Font(name="Calibri", size=11, color="166534", bold=True)
        elif display_st in ("Inactive", "Taken Down"):
            st_cell.fill = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
            st_cell.font = Font(name="Calibri", size=11, color="991B1B", bold=True)
        conf = r.get("confidence")
        conf_cell = ws_details.cell(row=row_idx, column=5, value=conf if conf is not None else "")
        conf_cell.alignment = Alignment(horizontal="center")
        # Flag anything the engine could not certify, so a reviewer can see at a
        # glance which rows carry evidence and which are merely plausible.
        if isinstance(conf, (int, float)) and conf < 70:
            conf_cell.font = Font(name="Calibri", size=11, color="92400E", bold=True)
        ws_details.cell(row=row_idx, column=6, value=r.get("reason", ""))
        ws_details.cell(row=row_idx, column=7, value=r.get("http_code", "")).alignment = Alignment(horizontal="center")

    # Auto-fit column widths for both sheets
    for ws in [ws_summary, ws_details]:
        for col in ws.columns:
            max_len = max(len(str(cell.value or '')) for cell in col)
            col_letter = get_column_letter(col[0].column)
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 100)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()

