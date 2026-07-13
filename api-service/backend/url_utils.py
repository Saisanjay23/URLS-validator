"""URL normalization and platform detection utilities."""

import re
from urllib.parse import urlparse


# ── Platform registry — maps hostnames to canonical platform names ────────────

_PLATFORM_MAP: dict[str, str] = {
    # Telegram
    "t.me": "telegram",
    "telegram.me": "telegram",
    # YouTube
    "youtube.com": "youtube",
    "www.youtube.com": "youtube",
    "m.youtube.com": "youtube",
    "youtu.be": "youtube",
    # Facebook
    "facebook.com": "facebook",
    "www.facebook.com": "facebook",
    "m.facebook.com": "facebook",
    "web.facebook.com": "facebook",
    # Instagram
    "instagram.com": "instagram",
    "www.instagram.com": "instagram",
    # X / Twitter
    "x.com": "x",
    "twitter.com": "x",
    "www.x.com": "x",
    "www.twitter.com": "x",
    "mobile.twitter.com": "x",
    # LinkedIn
    "linkedin.com": "linkedin",
    "www.linkedin.com": "linkedin",
    # Google
    "maps.app.goo.gl": "google_maps",
    "goo.gl": "google",
    "share.google": "google",
    # App Stores
    "play.google.com": "apps",
    "apps.apple.com": "apps",
    # Third Party App Stores
    "apkpure.com": "apps",
    "www.apkpure.com": "apps",
    "apkmirror.com": "apps",
    "www.apkmirror.com": "apps",
    "uptodown.com": "apps",
    "www.uptodown.com": "apps",
    "f-droid.org": "apps",
}


def normalize_url(raw: str) -> str | None:
    """
    Clean and normalize a raw URL string.

    Handles leading/trailing whitespace, spaces inside scheme ("https ://"),
    missing scheme (bare domains like "example.com"), and empty/garbage input.
    """
    if not raw:
        return None

    url = raw.strip()
    if not url:
        return None

    # Fix common copy-paste malformations
    if url.startswith("http://https%20//"):
        url = url.replace("http://https%20//", "https://")
    elif url.startswith("http://https://"):
        url = url.replace("http://https://", "https://")

    # Fix spaces in scheme — e.g. "https ://" → "https://"
    url = re.sub(r"^(https?)\s*:\s*//", r"\1://", url, flags=re.IGNORECASE)

    # If there's no scheme, prepend https://
    if not re.match(r"^https?://", url, re.IGNORECASE):
        if "." not in url:
            return None
        url = f"https://{url}"

    # Final validation — must parse to something with a hostname
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
    except Exception:
        return None

    return url


def detect_platform(url: str) -> str:
    """
    Return a canonical platform key for the given URL.
    Falls back to "generic" for unrecognized hosts.
    """
    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower().rstrip(".")

        if hostname in _PLATFORM_MAP:
            return _PLATFORM_MAP[hostname]

        bare = hostname.removeprefix("www.")
        if bare in _PLATFORM_MAP:
            return _PLATFORM_MAP[bare]
            
        # Smart detection for third-party app stores and game sites
        url_lower = url.lower()
        if "/app/" in url_lower or "/apps/" in url_lower or "apk" in bare or "/game/" in url_lower:
            return "apps"
            
    except Exception:
        pass

    return "generic"


def deduplicate_urls(urls: list[str]) -> list[str]:
    """Remove exact duplicates while preserving order."""
    return list(dict.fromkeys(urls))
