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
    # Scribd
    "scribd.com": "scribd",
    "www.scribd.com": "scribd",
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


def is_email(raw: str) -> bool:
    """Return True if the raw string represents an email address, not an HTTP web URL."""
    if not raw:
        return False
    s = raw.strip()
    if s.lower().startswith("mailto:"):
        s = s[7:].strip()
    return bool(re.match(r"^[^/\s@]+@[^/\s@]+\.[^/\s@]+$", s))


def normalize_email(raw: str) -> str | None:
    """Clean and normalize a raw email address string.

    Strips mailto: prefix, cleans leading/trailing punctuation and whitespace,
    and returns lowercase email or None if invalid.
    """
    if not raw:
        return None
    s = raw.strip()
    if s.lower().startswith("mailto:"):
        s = s[7:].strip()
    s = s.rstrip(".,;:>\"')}]")
    s = s.lstrip("<([{\"'` \t")
    if not re.match(r"^[^/\s@]+@[^/\s@]+\.[^/\s@]+$", s):
        return None
    return s.lower()


def detect_email_provider(email: str) -> str:
    """Detect email provider for platform badge (gmail, outlook, yahoo, icloud, proton, or email)."""
    norm = normalize_email(email)
    if not norm:
        return "email"
    domain = norm.split("@")[-1].lower()
    if domain in ("gmail.com", "googlemail.com"):
        return "gmail"
    if domain in ("outlook.com", "hotmail.com", "live.com", "msn.com"):
        return "outlook"
    if domain in ("yahoo.com", "ymail.com", "myyahoo.com"):
        return "yahoo"
    if domain in ("icloud.com", "me.com", "mac.com"):
        return "icloud"
    if domain in ("proton.me", "protonmail.com"):
        return "proton"
    return "email"


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

    # Unwrap URLs pasted out of prose or a document: '"https://x.com"',
    # '<https://x.com>', '(see https://x.com)', 'Profile: https://x.com'.
    # Left unhandled, the leading character defeats the scheme check below, the
    # string gets an extra "https://" prefix, and the resulting garbage host
    # fails DNS — reported as a confidently dead domain.
    scheme_at = re.search(r"https?://", url, re.IGNORECASE)
    if scheme_at and scheme_at.start() > 0:
        url = url[scheme_at.start():]
    else:
        url = url.lstrip("<([{\"'` \t")

    # Fix spaces in scheme — e.g. "https ://" → "https://"
    url = re.sub(r"^(https?)\s*:\s*//", r"\1://", url, flags=re.IGNORECASE)

    # Strip any trailing copy-pasted contact/phone numbers (e.g. "+91 9638992878" or "+919876543210" tacked onto URLs)
    url = re.sub(r"\+\d{1,4}(\s*[\s-]\s*\d+)+$", "", url).strip()
    # Handle concatenated phone numbers or country codes without space (e.g., id=61581807675905+91)
    url = re.sub(r"(?<=[a-zA-Z0-9/&=_])\+\d{8,15}$", "", url).strip()
    url = re.sub(r"(?<=\d)\+\d{1,4}$", "", url).strip()

    # If there is any remaining whitespace (e.g., URL followed by text or comments), take only the URL part
    if " " in url or "\t" in url:
        url = url.split()[0]

    # Email addresses are not web URLs
    if is_email(url):
        return None

    # If there's no scheme, prepend https://
    if not re.match(r"^https?://", url, re.IGNORECASE):
        if "." not in url:
            return None
        url = f"https://{url}"
    
    # Strip trailing quotes/punctuation picked up by copy-paste.
    #
    # A closing bracket is only noise when it is UNBALANCED. Stripping it
    # unconditionally truncates legitimate URLs that end in one — Wikipedia
    # titles ("..._(programming_language)", "..._(film)") are the common case —
    # and the shortened URL then returns a real 404, so a live page is reported
    # taken down with full confidence. Balance-check before removing.
    while url:
        tail = url[-1]
        if tail in ",;>'\"":
            url = url[:-1]
        elif tail == ")" and url.count(")") > url.count("("):
            url = url[:-1]
        elif tail == "]" and url.count("]") > url.count("["):
            url = url[:-1]
        else:
            break

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
    Return a canonical platform key for the given URL or email.
    Falls back to "generic" for unrecognized hosts.
    """
    if is_email(url):
        return detect_email_provider(url)

    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower().rstrip(".")

        if hostname in _PLATFORM_MAP:
            return _PLATFORM_MAP[hostname]

        bare = hostname.removeprefix("www.")
        if bare in _PLATFORM_MAP:
            return _PLATFORM_MAP[bare]

        # Regional / functional subdomains of a known platform still belong to
        # that platform: id.scribd.com is Scribd, not a generic website. Without
        # this they fell through to the generic checker, which reads Cloudflare's
        # "Client Challenge" interstitial as a normal page and reports it active.
        for known, platform in _PLATFORM_MAP.items():
            if bare.endswith("." + known):
                return platform

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
