"""
Stealth & Accuracy Hardening — Enterprise URL Validation Engine.

Provides anti-detection features to avoid bot fingerprinting:
1. Browser-accurate header order and Client Hints (sec-ch-ua)
2. JA3/TLS fingerprint rotation
3. Referer spoofing
4. Log-normal request timing (humanized delays)
5. Google Cache & Wayback Machine cross-verification
"""

import json
import random
from collections import OrderedDict
from urllib.parse import quote, urlparse

from backend.logger import get_logger
from backend import config

logger = get_logger()

# ── 1. Browser Profiles (Headers & TLS Impersonation) ─────────────────────────

_DESKTOP_PROFILES = [
    {
        "impersonate": "chrome120",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "ch_platform": '"Windows"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    },
    {
        "impersonate": "chrome116",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "ch_ua": '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
        "ch_platform": '"macOS"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    },
    {
        "impersonate": "edge101",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53",
        "ch_ua": '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
        "ch_platform": '"Windows"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    },
    {
        "impersonate": "safari17_0",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "ch_ua": None, # Safari doesn't send Client Hints
        "ch_platform": None,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
]

_MOBILE_PROFILES = [
    {
        "impersonate": "chrome120",
        "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "ch_platform": '"Android"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    },
    {
        "impersonate": "safari15_5",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
        "ch_ua": None,
        "ch_platform": None,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
]

_BOT_PROFILES = [
    {
        "impersonate": "chrome120", # Bots often don't have distinct TLS, just use a modern one
        "ua": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "ch_ua": None,
        "ch_platform": None,
        "accept": "*/*",
    },
    {
        "impersonate": "chrome120",
        "ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "ch_ua": None,
        "ch_platform": None,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    {
        "impersonate": "chrome120",
        "ua": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "ch_ua": None,
        "ch_platform": None,
        "accept": "*/*",
    },
]

def random_impersonation(ua_pool: str = "desktop") -> str:
    """Get a random curl_cffi impersonation target based on the pool."""
    if ua_pool == "mobile":
        profile = random.choice(_MOBILE_PROFILES)
    elif ua_pool == "bot":
        profile = random.choice(_BOT_PROFILES)
    else:
        profile = random.choice(_DESKTOP_PROFILES)
    return profile["impersonate"]

def build_stealth_headers(url: str, ua_pool: str = "desktop") -> OrderedDict:
    """
    Build highly realistic, order-preserved headers.
    Includes Client Hints and Referer spoofing if enabled.
    """
    if ua_pool == "mobile":
        profile = random.choice(_MOBILE_PROFILES)
        is_mobile = "?1"
    elif ua_pool == "bot":
        profile = random.choice(_BOT_PROFILES)
        is_mobile = "?0"
    else:
        profile = random.choice(_DESKTOP_PROFILES)
        is_mobile = "?0"

    # Use OrderedDict to preserve insertion order for aiohttp
    # Real browsers have specific header order.
    headers = OrderedDict()
    
    # 1. Host is handled by aiohttp/curl_cffi automatically
    # 2. Connection
    headers["Connection"] = "keep-alive"
    
    # 3. Client Hints (Crucial for modern Chrome/Edge)
    if getattr(config, "ENABLE_STEALTH_HEADERS", True) and profile.get("ch_ua"):
        headers["sec-ch-ua"] = profile["ch_ua"]
        headers["sec-ch-ua-mobile"] = is_mobile
        headers["sec-ch-ua-platform"] = profile["ch_platform"]
        
    # 4. Upgrade-Insecure-Requests
    if ua_pool != "bot":
        headers["Upgrade-Insecure-Requests"] = "1"
        
    # 5. User-Agent
    headers["User-Agent"] = profile["ua"]
    
    # 6. Accept
    headers["Accept"] = profile["accept"]
    
    # 7. Sec-Fetch-* (Modern fetch metadata)
    if getattr(config, "ENABLE_STEALTH_HEADERS", True) and profile.get("ch_ua"):
        headers["Sec-Fetch-Site"] = "none" # assuming direct navigation or cross-site
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
        headers["Sec-Fetch-Dest"] = "document"

    # 8. Accept-Encoding
    headers["Accept-Encoding"] = "gzip, deflate, br"
    
    # 9. Accept-Language
    headers["Accept-Language"] = "en-US,en;q=0.9"

    # 10. Referer Spoofing
    if getattr(config, "ENABLE_REFERER_SPOOFING", True) and ua_pool != "bot":
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        
        # Decide referrer strategy
        strategy = random.choice(["google", "google_search", "direct", "linktree"])
        
        if strategy == "google":
            headers["Referer"] = "https://www.google.com/"
        elif strategy == "google_search":
            headers["Referer"] = f"https://www.google.com/search?q={quote(url)}"
        elif strategy == "linktree":
            headers["Referer"] = "https://linktr.ee/"
        elif strategy == "direct":
            pass # No referer for direct navigation
            
        if strategy != "direct" and getattr(config, "ENABLE_STEALTH_HEADERS", True) and profile.get("ch_ua"):
            headers["Sec-Fetch-Site"] = "cross-site"

    return headers


# ── 2. Humanized Timing ───────────────────────────────────────────────────────

def human_delay(mean: float = 0.5, sigma: float = 0.8, min_val: float = 0.5, max_val: float = 4.0) -> float:
    """
    Generate a delay from a log-normal distribution.
    Humans don't wait uniformly; most clicks are fast, with a long tail of slower clicks.
    """
    # stdlib equivalent of numpy's lognormal — both draw exp(normal(mu, sigma)).
    # Not worth a ~20MB numpy dependency for one call.
    delay = random.lognormvariate(mean, sigma)
    return float(max(min_val, min(delay, max_val)))


# ── 3. Cross-Verification Engines ─────────────────────────────────────────────

async def check_google_cache(session, url: str) -> bool | None:
    """
    Check if Google has a cached copy of the URL.
    Returns:
      True if cached (page existed recently)
      False if 404 (Google explicitly says not found)
      None if inconclusive (captcha, timeout, etc.)
    """
    if not getattr(config, "ENABLE_GOOGLE_CACHE_VERIFY", True):
        return None
        
    cache_url = f"https://webcache.googleusercontent.com/search?q=cache:{quote(url)}"
    headers = build_stealth_headers(cache_url, ua_pool="desktop")
    
    try:
        async with session.get(cache_url, headers=headers, timeout=5) as resp:
            if resp.status == 200:
                return True
            elif resp.status == 404:
                return False
            else:
                return None
    except Exception as e:
        logger.debug(f"[STEALTH] Google cache check failed for {url}: {e}")
        return None

async def check_wayback_machine(session, url: str) -> dict | None:
    """
    Check the Internet Archive CDX API for the URL.
    Returns dict with 'timestamp' and 'statuscode', or None.
    """
    if not getattr(config, "ENABLE_WAYBACK_VERIFY", True):
        return None
        
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={quote(url)}&output=json&limit=1&fl=timestamp,statuscode"
    # Wayback API doesn't need stealth headers, just a polite UA
    headers = {"User-Agent": "Social-URL-Validator/5.0"}
    
    try:
        async with session.get(cdx_url, headers=headers, timeout=5) as resp:
            if resp.status == 200:
                text = await resp.text()
                try:
                    data = json.loads(text)
                    if len(data) > 1: # Row 0 is headers, Row 1 is data
                        return {
                            "timestamp": data[1][0],
                            "statuscode": data[1][1]
                        }
                except json.JSONDecodeError:
                    pass
            return None
    except Exception as e:
        logger.debug(f"[STEALTH] Wayback check failed for {url}: {e}")
        return None
