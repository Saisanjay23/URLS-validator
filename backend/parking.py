"""
Expanded Parking / Placeholder Detection — Enterprise URL Validation Engine.

Supplements the existing _PARKING_SIGNALS in fast_checker.py with 40+ new
signatures for modern hosting providers, CDN placeholder pages, domain
registrars, and cloud platform error pages.

Never removes any existing signatures — only adds new ones.
"""

from __future__ import annotations


# ── Expanded Parking / Placeholder Signatures ─────────────────────────────────
# Each entry is a lowercase substring to match against the page HTML.
# Organized by provider for maintainability.

EXPANDED_PARKING_SIGNALS: list[str] = [
    # ── Domain Registrar Parking ──
    "this domain is for sale on opensea",
    "this domain name has been registered",
    "this domain may be for sale",
    "domain name is available at",
    "register this domain at",
    "this web page is parked for free",
    "domain is parked by service",
    "this domain has been registered with",
    "this is a brand-registrable domain",
    "this domain is available for purchase",
    "domain expired",
    "this domain name expired",
    "renewal grace period",
    "the owner of this domain has not yet uploaded their website",
    "future home of something quite cool",

    # ── Porkbun ──
    "porkbun.com",

    # ── Google Domains ──
    "this site is hosted by google",

    # ── ParkingCrew ──
    "parkingcrew",

    # ── Bodis ──
    "bodis.com",

    # ── Above.com ──
    "above.com",

    # ── Cloudflare Placeholder ──
    "attention required! | cloudflare",
    "error 1000",
    "error 1001",
    "error 1003",
    "error 1004",
    "error 1005",
    "error 1006",
    "error 1007",
    "error 1008",
    "error 1010",
    "error 1012",
    "dns resolution error | cloudflare",
    "web server is returning an unknown error",
    "origin dns error | cloudflare",
    "cloudflare is unable to establish an ssl connection",
    "host error | cloudflare",

    # ── Netlify ──
    "page not found | netlify",
    "not found - netlify",
    "netlify | page not found",
    "site not found - netlify",

    # ── Vercel ──
    "404: this page could not be found",
    "this deployment cannot be found",
    "vercel 404",

    # ── GitHub Pages ──
    "site not found · github pages",
    "there isn't a github pages site here",
    "404 - file not found | github pages",

    # ── Azure ──
    "microsoft azure app service",
    "this web app is stopped",
    "hey, app service developers!",
    "your web app is running and waiting for your content",
    "azure web app - placeholder",

    # ── AWS S3 ──
    "nosuchbucket",
    "the specified bucket does not exist",
    "access denied - amazon s3",
    "code: nosuchbucket",

    # ── AWS CloudFront ──
    "error generating response. request could not be satisfied",

    # ── Google Sites ──
    "this google app is currently not available",
    "site not published",

    # ── Wix ──
    "wix.com - website builder",
    "looks like this site doesn't exist yet",
    "this domain is registered at wix",

    # ── Squarespace ──
    "squarespace - claim this domain",
    "this is a squarespace placeholder",

    # ── WordPress.com ──
    "doesn't seem to exist on wordpress.com",
    "this site is no longer available",

    # ── Shopify ──
    "only one step left!",
    "this store is unavailable",
    "sorry, this shop is currently unavailable",

    # ── Heroku ──
    "heroku | no such app",
    "no app was found at that url",
    "there is no app configured at that hostname",

    # ── Webflow ──
    "the page you are looking for doesn't exist or has been moved",

    # ── Fastly ──
    "fastly error: unknown domain",

    # ── Firebase Hosting ──
    "firebase hosting setup complete",
    "site not found",

    # ── Render ──
    "not found | render",

    # ── Fly.io ──
    "this fly.io app is not available",

    # ── Domain Seized by Law Enforcement ──
    "this website has been seized by the fbi",
    "this domain has been seized by",
    "seized by the united states",
    "seizure notice",
    "domain has been suspended by",
    "this website has been shut down",
    "this website has been taken down",
]


# ── Parking Domain Signatures ────────────────────────────────────────────────
# Final-URL hostname patterns that indicate parking redirects.

PARKING_DOMAINS: list[str] = [
    "sedoparking.com",
    "bodis.com",
    "hugedomains.com",
    "afternic.com",
    "dan.com",
    "undeveloped.com",
    "parkingcrew.net",
    "above.com",
    "godaddy.com/domain",
    "domains.google",
    "porkbun.com",
    "namecheap.com/parking",
]


def detect_expanded_parking(html: str, title: str, h1: str) -> str | None:
    """
    Detect if a page is a parked, placeholder, seized, or default page.
    
    Checks the expanded signature list (supplements the existing
    _PARKING_SIGNALS in fast_checker.py).
    
    Args:
        html: First ~5000 chars of page HTML (already lowercased by caller).
        title: Extracted <title> text.
        h1: Extracted <h1> text.
    
    Returns:
        Reason string if parking/placeholder detected, None otherwise.
    """
    text = f"{title} {h1} {html[:8000]}".lower()

    for signal in EXPANDED_PARKING_SIGNALS:
        if signal in text:
            return f"Placeholder/parking page ({signal[:50]})"

    return None

