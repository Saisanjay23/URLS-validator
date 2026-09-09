"""
Verdict Verification Layer — evidence gate for `active` / `taken_down`.

The per-platform checkers in fast_checker.py answer the question "did I find a
removal notice?". When they don't, they fall through to `active`. That default
is the single largest source of false positives: a page can return HTTP 200 with
a perfectly good <title> while the body says "This content isn't available", or
it can 302 a dead deep-link onto the site homepage, or ship an empty SPA shell
that only paints the 404 after JS runs.

This module does NOT replace any checker logic. It runs *after* a checker has
spoken and audits the verdict against the raw evidence actually collected during
the check (the "fetch tape"). Its contract:

    A URL is reported `active` only with positive proof of live content.
    A URL is reported `taken_down` only with positive proof of removal.
    Everything else is `uncertain` — honestly unproven, never guessed.

That is what makes the two decided buckets trustworthy without manual review:
uncertainty is routed to a third bucket instead of being absorbed into `active`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote

# ── Text normalisation ────────────────────────────────────────────────────────

# Platforms render typographic apostrophes ("isn’t"), non-breaking spaces, and
# zero-width joiners. Phrase matching against raw text misses all of them, which
# is why body-level removal notices slip through as `active`.
_PUNCT_MAP = str.maketrans({
    "‘": "'", "’": "'", "‛": "'", "ʼ": "'", "´": "'",
    "“": '"', "”": '"',
    "–": "-", "—": "-", "−": "-",
    " ": " ", "​": " ", "‌": " ", "‍": " ", "﻿": " ",
})


def normalize_text(text: str) -> str:
    """Lowercase, fold smart punctuation, and collapse whitespace."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.translate(_PUNCT_MAP).lower()).strip()


def visible_text(html: str) -> str:
    """
    Extract only what a human would read: strips script/style/template/noscript
    /head so JS bundle string literals and SEO metadata can't trigger matches.
    """
    if not html:
        return ""
    try:
        from selectolax.parser import HTMLParser
        tree = HTMLParser(html)
        for tag in ("script", "style", "template", "noscript", "head", "svg"):
            for element in tree.css(tag):
                element.decompose()
        raw = tree.body.text(separator=" ") if tree.body else tree.text(separator=" ")
    except Exception:
        raw = re.sub(
            r"<(script|style|template|noscript|head|svg)[^>]*>.*?</\1>",
            " ", html, flags=re.DOTALL | re.IGNORECASE,
        )
        raw = re.sub(r"<[^>]+>", " ", raw)
    return normalize_text(raw)


# ── Removal-phrase corpus ─────────────────────────────────────────────────────
# Split by strength. DECISIVE phrases are unambiguous removal notices — no live
# page shows them as its own message. SUPPORTING phrases are real signals that
# also appear in help-centre copy, error-handling docs, and UI boilerplate, so
# they only count when the page is small or the phrase sits in the title/heading.

_DECISIVE_PHRASES = [
    # Meta / Facebook / Instagram
    "this content isn't available right now",
    "this content isn't available at the moment",
    "this content isn't available",
    "sorry, this content isn't available",
    "this page isn't available",
    "sorry, this page isn't available",
    "the link you followed may be broken",
    "the page you're looking for isn't available",
    "this profile isn't available",
    "this account isn't available",
    "content not found",
    "content unavailable",
    "content is no longer available",
    "this content is no longer available",
    "content doesn't exist",
    "content does not exist",
    # X / Twitter
    "this account doesn't exist",
    "this account does not exist",
    "account suspended",
    "this account has been suspended",
    "hmm...this page doesn't exist",
    "this page doesn't exist",
    "this post is unavailable",
    "this post is from a suspended account",
    "sorry, that page doesn't exist",
    # YouTube
    "video unavailable",
    "this video has been removed",
    "this video is no longer available",
    "this video isn't available anymore",
    "this channel does not exist",
    "this channel doesn't exist",
    "this account has been terminated",
    "the uploader has not made this video available",
    # LinkedIn
    "this page doesn't exist or has been removed",
    "the page you're looking for doesn't exist",
    "profile not found",
    # Generic removal / takedown
    "page not found",
    "404 not found",
    "error 404",
    "410 gone",
    "no longer available",
    "no longer exists",
    "has been removed",
    "has been deleted",
    "has been suspended",
    "has been terminated",
    "account terminated",
    "account deleted",
    "this document has been removed",
    "removed for violating",
    "removed in response to a complaint",
    "removed due to a copyright claim",
    "unavailable for legal reasons",
    "removed at the request of",
    "this listing has been removed",
    "this item is no longer available",
    "this document is no longer available",
    "we can't find this document",
    "we couldn't find that page",
    "we can't find the page",
    "we cannot find the page",
    "the requested url was not found on this server",
    "the resource you are looking for has been removed",
    "sorry, we couldn't find that page",
    "oops! that page can't be found",
    "nothing found for",
    "this site can't be reached",
    "web page not available",
    "domain is not configured",
    "this store is unavailable",
    "this shop is currently unavailable",
    "user not found",
    "profile does not exist",
    "profile doesn't exist",
]

_SUPPORTING_PHRASES = [
    "not found",
    "page unavailable",
    "unavailable",
    "does not exist",
    "doesn't exist",
    "removed",
    "deleted",
    "suspended",
    "expired",
    "gone",
]
# Deliberately NOT supporting phrases: "something went wrong", "sorry", "oops",
# "we're sorry". These are transient-error and apology wording, not removal
# wording. X's SPA error shell ("Something went wrong. Try reloading.") appears
# whenever the platform rate-limits, and reading it as a possible removal cost
# 12 live accounts their `active` verdict on every loaded run. A genuinely
# removed page says so ("not found", "no longer exists"); those terms remain.

# Never treat these as removal even when a supporting word appears nearby — they
# are live-content states, not takedowns. Keeps private/login-walled pages out of
# the `taken_down` bucket (they belong in `uncertain`).
_AMBIGUITY_PHRASES = [
    "log in to continue",
    "log in or sign up",
    "sign in to continue",
    "please log in",
    "you must log in",
    "join linkedin",
    "create an account",
    "this account is private",
    "this profile is private",
    "follow to see",
    "enable javascript",
    "javascript is required",
    "javascript is disabled",
    "checking your browser",
    "just a moment",
    "verify you are human",
    "verifying you are human",
    "captcha",
    "cloudflare",
    "access denied",
    "rate limit",
    "too many requests",
    "temporarily unavailable",
    "try again later",
    "under maintenance",
    "scheduled maintenance",
    "age-restricted",
    "sign in to confirm your age",
    "not available in your country",
    "not available in your region",
    "geo-restricted",
    "video is private",
    "this video is private",
    "private video",
]

# Literal phrases can't cover every wording a site invents ("the content you
# requested does not exist"). These templates match the underlying grammar —
# a content noun followed shortly by a removal predicate — so novel phrasings
# are caught without loosening the corpus into false positives. The subject list
# is deliberately narrow: only nouns that name the requested resource.
_REMOVAL_SUBJECTS = (
    r"content|page|profile|account|video|document|post|tweet|user|channel|"
    r"listing|item|file|photo|image|album|story|group|event|product|link|url"
)
_REMOVAL_PREDICATES = (
    r"does not exist|doesn't exist|no longer exists|"
    r"is not available|isn't available|is no longer available|"
    r"was not found|were not found|can't be found|cannot be found|"
    r"has been removed|have been removed|has been deleted|has been taken down|"
    r"has been suspended|has been terminated|is unavailable"
)
# Up to 45 chars of qualifier between subject and predicate covers
# "the content you requested does not exist" without spanning sentences.
_DECISIVE_PATTERNS = [
    rf"\b(?:{_REMOVAL_SUBJECTS})\b[^.!?<]{{0,45}}?\b(?:{_REMOVAL_PREDICATES})\b",
]

_DECISIVE_RE = re.compile(
    "|".join([re.escape(p) for p in _DECISIVE_PHRASES] + _DECISIVE_PATTERNS)
)
_SUPPORTING_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in _SUPPORTING_PHRASES) + r")\b"
)
_AMBIGUITY_RE = re.compile("|".join(re.escape(p) for p in _AMBIGUITY_PHRASES))

# A HARD wall is a page that demonstrably withheld the content: a login form, a
# bot challenge, an explicit denial. Only these justify demoting an otherwise
# clean `active` to `uncertain`.
#
# The broader _AMBIGUITY_PHRASES list above must NOT be used for that: it
# deliberately includes soft boilerplate ("try again later", "temporarily
# unavailable") that live pages carry in hidden error templates — YouTube's
# watch page ships several — and demoting on those buries working URLs in the
# uncertain bucket. The broad list is used only in the opposite direction, to
# PROTECT live-but-gated content from being called dead.
_HARD_WALL_PHRASES = [
    "log in to continue",
    "log in or sign up",
    "sign in to continue",
    "please log in",
    "you must log in",
    # Wall wording platforms use as the page's own headline, e.g. Facebook's
    # "Log in to view this 18+ content" — distinct from chrome like "Log in or
    # sign up", which live pages carry alongside real content.
    "log in to view",
    "log in to see",
    "join linkedin",
    "enable javascript",
    "javascript is required",
    "javascript is disabled",
    "checking your browser",
    "just a moment",
    "verify you are human",
    "verifying you are human",
    "captcha",
    "access denied",
    "too many requests",
    # Cloudflare / WAF interstitials: the site is up, the content was withheld.
    "attention required",
    "you have been blocked",
    "unable to access",
    "ray id",
    "performance & security by cloudflare",
    "client challenge",
    "suspected phishing",
    "has been denied",
]
# NB: "create new account" deliberately does NOT belong here. Facebook renders it
# in the logged-out sidebar of perfectly live pages, so matching it in body text
# demotes real content. It is a wall only when it is the page's TITLE — handled
# in the Facebook checker's own generic-title test.
_HARD_WALL_RE = re.compile("|".join(re.escape(p) for p in _HARD_WALL_PHRASES))

# A geo-block is a country-level interstitial served in place of the resource.
# It must be told apart from a wildcard catch-all: both answer every path with
# the same page, but one is a notice about blocking (the resource's state is
# unknowable) and the other is the site's own content (the URL genuinely serves
# it). Without this split, either every geo-blocked account is certified live,
# or every wildcard domain is left unresolved.
_GEO_BLOCK_PHRASES = [
    "decided to block",
    "blocked in your country",
    "blocked in your region",
    "not available in your country",
    "not available in your region",
    "not available in your location",
    "restricted in your country",
    "restricted in your region",
    "unavailable in your country",
    "unavailable in your region",
    "access from your country",
    "access from your location",
    "this service is not available in",
    "content is not available in your",
    "due to local laws",
    "government of india",
    "govt. of india",
]
_GEO_BLOCK_RE = re.compile("|".join(re.escape(p) for p in _GEO_BLOCK_PHRASES))


def geo_blocked(text_norm: str) -> str:
    """Matched phrase if the page is a country-level block notice."""
    m = _GEO_BLOCK_RE.search(text_norm or "")
    return m.group(0) if m else ""

# An unrendered SPA shell (`<div id="root"></div>`) leaves essentially no text.
# This must stay brutally low: legitimately terse pages exist — example.com
# renders 127 visible chars — so anything higher demotes live pages.
EMPTY_SHELL_CHARS = 40
# Slightly more text than a shell, but still nothing a human could use. Only
# counts as dead-ish when the page ALSO has no title/heading of its own, since a
# short page that names itself is a real (if minimal) page.
THIN_TEXT_CHARS = 250
# Below this the page is small enough that any removal phrase in it IS the page's
# message rather than incidental prose in an article.
SMALL_PAGE_CHARS = 2500
# A removal phrase in the title/heading is the page announcing itself — but a
# real article *about* broken links can carry one in its headline too. What
# separates them is body volume: an error page renders nav + footer + a short
# notice, never paragraphs of unique content. Tuned above typical site chrome
# (~2-4KB of visible text) and below any substantive article.
ERROR_PAGE_MAX_TEXT = 8000


# ── Evidence container ────────────────────────────────────────────────────────

# Upper bound on HTML we will parse, purely as a pathological-input guard.
MAX_PARSE_CHARS = 5_000_000
# How much raw HTML to retain after extraction, for logging/debugging only.
HTML_EXCERPT_CHARS = 20_000


@dataclass
class FetchRecord:
    """
    One HTTP response observed while checking a URL.

    Text is extracted from the FULL html on construction, then the html is
    reduced to a short excerpt. Storing raw html instead and truncating it was a
    silent accuracy bug: YouTube ships ~2.3MB of markup whose first megabyte is
    one <script> blob, so any truncation left a document that stripped to zero
    visible text — and a live page then looked like an empty shell.
    Extract first, shrink second.
    """
    requested_url: str = ""
    final_url: str = ""
    status: int | None = None
    html: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    source: str = "http"  # http | curl | playwright
    text: str = ""        # visible text
    prominent: str = ""   # title + headings + og:*
    title: str = ""

    def __post_init__(self) -> None:
        if self.html and not self.text and not self.prominent:
            source_html = self.html[:MAX_PARSE_CHARS]
            self.text = visible_text(source_html)
            self.prominent = prominent_text(source_html)
            self.title = _extract_title(source_html)
            self.html = self.html[:HTML_EXCERPT_CHARS]


@dataclass
class Audit:
    """Outcome of auditing a checker verdict against collected evidence."""
    status: str
    reason: str
    confidence: int
    signals: list[str] = field(default_factory=list)
    escalate: bool = False  # worth a browser render before finalising


# ── Individual evidence probes ────────────────────────────────────────────────

def scan_removal(text_norm: str, prominent_norm: str, body_len: int) -> tuple[int, str]:
    """
    Score removal evidence by PROMINENCE, not page size.

    `prominent_norm` is the page's own voice — <title>, headings, og:title/
    og:description. `text_norm` is all visible text. Returns
    (weight, matched_phrase) where 3 = proof, 2 = strong, 0 = none.

    Size alone can't separate a 404 from a live page: real error pages ship the
    site's full nav and footer and routinely exceed 20KB. What separates them is
    where the phrase sits and how much unique content surrounds it. A removal
    notice in the page's own headline, on a page with no substantial body, is
    the page declaring itself dead. The same phrase buried in the prose of a
    long article is someone writing *about* broken links.
    """
    m = _DECISIVE_RE.search(prominent_norm)
    if m:
        # Headline match + no article-sized body => this is an error page.
        if body_len <= ERROR_PAGE_MAX_TEXT:
            return 3, m.group(0)
        return 2, m.group(0)

    m = _DECISIVE_RE.search(text_norm)
    if m:
        if body_len <= SMALL_PAGE_CHARS:
            return 3, m.group(0)
        # Buried in a large page: real signal, but it may be boilerplate on a
        # live page. Strong, not decisive — routed to `uncertain`.
        return 2, m.group(0)

    # Supporting words only count on a page too thin to be anything else.
    if body_len <= THIN_TEXT_CHARS:
        m = _SUPPORTING_RE.search(f"{prominent_norm} {text_norm}")
        if m:
            return 2, m.group(0)

    return 0, ""


def is_ambiguous(text_norm: str, title_norm: str) -> str:
    """
    Matched phrase if the page may be gated, private, geo-blocked, or in
    maintenance. Used to PROTECT such pages from a `taken_down` verdict.
    """
    m = _AMBIGUITY_RE.search(f"{title_norm} {text_norm[:4000]}")
    return m.group(0) if m else ""


def hard_wall(text_norm: str, title_norm: str) -> str:
    """Matched phrase if the page demonstrably withheld its content."""
    m = _HARD_WALL_RE.search(f"{title_norm} {text_norm[:4000]}")
    return m.group(0) if m else ""


def _path_of(url: str) -> str:
    try:
        return unquote(urlparse(url).path or "/").rstrip("/").lower()
    except Exception:
        return "/"


# Hosts whose whole purpose is to redirect somewhere unrelated. The generic
# "did the requested path survive?" rule cannot apply to them.
_SHORTENER_HOSTS = {
    "goo.gl", "maps.app.goo.gl", "share.google", "youtu.be", "vt.tiktok.com",
    "bit.ly", "t.co", "tinyurl.com", "lnkd.in", "fb.me", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "is.gd",
}
# Path prefixes that are opaque redirect tokens the site resolves itself
# (facebook.com/share/g/XXXX -> facebook.com/groups/NNN is a success, not drift).
_REDIRECTOR_PREFIXES = ("/share/", "/l/", "/go/", "/r/", "/redirect", "/s/", "/link/")


def redirect_drift(requested_url: str, final_url: str) -> str:
    """
    Detect a deep link that was silently redirected away from the resource it
    asked for. A dead profile bounced to the site homepage answers 200 with a
    healthy title — indistinguishable from success unless the path is compared.
    """
    if not requested_url or not final_url or requested_url == final_url:
        return ""

    req_path = _path_of(requested_url)
    fin_path = _path_of(final_url)
    if req_path == fin_path or not req_path or req_path == "/":
        return ""

    fin_low = final_url.lower()

    if any(seg in fin_low for seg in ("/login", "/signin", "/sign-in", "/authwall",
                                      "/checkpoint", "/challenge", "/accounts/login")):
        return "redirected to a login wall"
    if fin_path in ("", "/") or fin_path in ("/home", "/index", "/index.html"):
        return "deep link redirected to site homepage"
    if any(seg in fin_low for seg in ("/404", "/error", "/not-found", "/notfound",
                                      "/removed", "/deleted", "/expired")):
        return "redirected to an error page"
    if any(seg in fin_low for seg in ("/search?", "/search/", "?q=", "/explore")):
        return "redirected to search/browse"

    # Generic rule: the distinctive part of the requested path must survive the
    # redirect somewhere in the final URL. Enumerating known bad destinations
    # can't keep up — a geo-block is the case that exposed this, where every
    # tiktok.com/@handle (live or not) lands on tiktok.com/in/about and answers
    # 200 with a healthy page, so content-based probes see nothing wrong.
    if _host_of(requested_url) in _SHORTENER_HOSTS:
        return ""
    if req_path.startswith(_REDIRECTOR_PREFIXES):
        return ""

    segments = [s for s in req_path.split("/") if s]

    # When the path is a server entry point the identity lives in the query
    # string, and the site legitimately canonicalises the path away:
    # facebook.com/profile.php?id=4 -> facebook.com/zuck is a success, not drift.
    if segments and segments[-1].endswith((".php", ".asp", ".aspx", ".jsp", ".cgi", ".do")):
        return ""

    if segments:
        # The longest segment is the identifying one (handle, slug, id) — generic
        # wrappers like "in", "p", "watch" are short by nature.
        key = max(segments, key=len)
        if len(key) >= 4 and key not in fin_low:
            return f"redirected away from the requested resource ('{key}' absent from final URL)"
    return ""


# ── The gate ──────────────────────────────────────────────────────────────────

# Verdicts a checker produced from hard proof — the audit must not second-guess
# these, they already carry their own evidence (API confirmation, explicit 404).
_TRUSTED_MARKERS = (
    "graph api",
    "oembed",
    "dns not found",
    "domain/dns not found",
    "(404",
    "(410",
    "404)",
    "410)",
)


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().removeprefix("www.").removeprefix("m.")
    except Exception:
        return ""


def _targets_same_resource(record_url: str, checked_url: str) -> bool:
    """True when a tape record was fetched for the URL actually under test."""
    if not checked_url:
        return True
    return (
        _host_of(record_url) == _host_of(checked_url)
        and _path_of(record_url) == _path_of(checked_url)
    )


def _pick_primary(scored: list[tuple[FetchRecord, str]]) -> tuple[FetchRecord, str]:
    """
    Choose the most informative observation of the page.

    Checkers fan out across several engines (desktop/mobile/bot HTML, Graph API
    JSON, oEmbed, a browser render), so the LAST response on the tape is often an
    unrelated API call rather than the page itself. Prefer a browser render — it
    shows what a human sees — then whichever response carried the most readable
    text; an empty engine response must never outvote one that actually loaded.
    """
    rendered = [(r, b) for r, b in scored if r.source == "playwright" and b]
    if rendered:
        return max(rendered, key=lambda rb: len(rb[1]))

    # A response that actually delivered the page outranks one that was blocked,
    # regardless of length. Cloudflare's interstitial is wordier than Medium's
    # 404 page — ranking on volume alone picked the block page and certified a
    # dead profile as live.
    delivered = [(r, b) for r, b in scored if b and r.status and 200 <= r.status < 300]
    if delivered:
        return max(delivered, key=lambda rb: len(rb[1]))

    with_text = [(r, b) for r, b in scored if b]
    if with_text:
        return max(with_text, key=lambda rb: len(rb[1]))
    return scored[-1]


def audit_verdict(
    status: str,
    reason: str,
    http_code: int | None,
    records: list[FetchRecord],
    platform: str = "generic",
    url: str = "",
) -> Audit:
    """
    Audit a checker verdict against the fetch tape.

    Only `active` verdicts are audited for downgrade — `taken_down` already
    passes through temporal quorum confirmation upstream, and `uncertain` is
    already the safe bucket. The job here is to stop unproven `active`.
    """
    signals: list[str] = []

    if status != "active":
        return Audit(status=status, reason=reason, confidence=_confidence_for(status, reason), signals=signals)

    reason_low = (reason or "").lower()
    if any(marker in reason_low for marker in _TRUSTED_MARKERS):
        return Audit(status="active", reason=reason, confidence=95, signals=["verified_by_api"])

    if not records:
        # Checker said active but we captured no response body to corroborate it.
        return Audit(
            status="uncertain",
            reason=f"{reason} — unverified: no page content captured",
            confidence=40, signals=["no_evidence"], escalate=True,
        )

    # Restrict the evidence to responses actually fetched for THIS URL, so a
    # sibling engine's probe of a different path can't decide the verdict.
    on_target = [r for r in records if _targets_same_resource(r.requested_url, url)] or records
    scored = [(r, r.text) for r in on_target]

    rec, body = _pick_primary(scored)
    body_len = len(body)

    title_norm = normalize_text(rec.title)
    prominent = rec.prominent

    # ── 1. A 404/410 for this resource outranks any "active" claim ────────────
    for r in on_target:
        if r.status in (404, 410):
            return Audit(
                status="taken_down",
                reason=f"Removed — HTTP {r.status} observed on {_path_of(r.final_url or r.requested_url) or '/'}",
                confidence=97, signals=[f"http_{r.status}"],
            )

    # ── 2. Removal notice in the rendered page ────────────────────────────────
    blocker = is_ambiguous(body, title_norm)
    weight, phrase = scan_removal(body, prominent, body_len)

    if weight >= 3 and not blocker:
        return Audit(
            status="taken_down",
            reason=f"Removed — page states \"{phrase}\"",
            confidence=93, signals=["removal_phrase", f"phrase:{phrase}"],
        )
    if weight >= 3 and blocker:
        # Removal wording behind a login/challenge wall: real platforms show
        # "content isn't available" to logged-out users on live private content.
        return Audit(
            status="uncertain",
            reason=f"Removal wording present but page is gated ({blocker}) — needs confirmation",
            confidence=45, signals=["removal_phrase", "gated"], escalate=True,
        )
    if weight == 2:
        return Audit(
            status="uncertain",
            reason=f"Possible removal notice (\"{phrase}\") — not conclusive",
            confidence=45, signals=["weak_removal_phrase"], escalate=True,
        )

    # ── 3. Geo-block: we are being shown the network's opinion, not the page ──
    # Detected on the rendered text, because the HTTP response is often just a
    # JS shell ("please wait...") while the notice is painted afterwards. This
    # is a phrase check rather than a comparison, so it may use the richest
    # observation available even though similarity work must stay like-for-like.
    # Ordered ahead of redirect drift: a geo-block IS why the redirect happened,
    # and "blocked from this network, retry via proxy" is actionable where
    # "redirected away from the requested resource" is not.
    geo = geo_blocked(body)
    if geo:
        return Audit(
            status="uncertain",
            reason=(f"Geo-blocked from this network (\"{geo}\") — the block notice is served "
                    f"instead of the page, so existence cannot be determined; re-check via a proxy"),
            confidence=30, signals=["geo_blocked"],
        )

    # ── 4. Redirect drift away from the requested resource ────────────────────
    drift = redirect_drift(rec.requested_url, rec.final_url)
    if drift:
        return Audit(
            status="uncertain",
            reason=f"{reason} — but {drift}; original content not confirmed",
            confidence=40, signals=["redirect_drift"], escalate=True,
        )

    # ── 5. Empty shell: 200 OK with nothing a human could read ────────────────
    # A page that says nothing proves nothing — but "says nothing" must account
    # for metadata. Social platforms serve crawlers a JS shell with an empty body
    # and the real substance in og:* tags ("104M Followers, 96 Following, 4,882
    # Posts"), which is positive proof the resource exists. Requiring both the
    # body AND the page's own headline/meta to be empty keeps those verified,
    # while still catching a true unrendered shell (example.com's 127 visible
    # chars under a proper <title> also survive this).
    if (body_len < EMPTY_SHELL_CHARS and len(prominent) < 40) or (
        body_len < THIN_TEXT_CHARS and not prominent
    ):
        return Audit(
            status="uncertain",
            reason=f"{reason} — page rendered no readable content ({body_len} chars)",
            confidence=35, signals=["thin_content"], escalate=True,
        )

    # ── 6. Blocked/gated: server is up but proves nothing about the content ───
    # Judge the status of the response we actually analysed, not whatever the
    # checker last happened to see — those differ when engines fall back.
    effective_code = rec.status if rec.status is not None else http_code
    wall = hard_wall(body, title_norm)

    # A wall phrase only proves the content was withheld when the page has no
    # identity of its own. X prints "log in or sign up" in the chrome of live
    # profiles whose og:title still reads "Rotana Turdi (@FoodicsCS)" with a full
    # bio — that metadata IS proof the account exists, and demoting on the
    # surrounding chrome buried live accounts in the review queue. When the
    # identity text is itself wall language ("Log in to view this 18+ content"),
    # there is no identity and the demotion stands.
    if wall and len(prominent) >= 40 and not _HARD_WALL_RE.search(prominent):
        signals.append("identity_despite_wall")
        wall = ""

    if effective_code in (401, 403, 429) or wall:
        detail = wall or f"HTTP {effective_code}"
        return Audit(
            status="uncertain",
            reason=f"Server responded but content is gated ({detail}) — existence not confirmed",
            confidence=40, signals=["gated"], escalate=True,
        )

    # ── Passed every probe: real, readable, on-target content ─────────────────
    confidence = 90 if body_len > SMALL_PAGE_CHARS else 82
    signals.append("content_verified")
    return Audit(status="active", reason=reason, confidence=confidence, signals=signals)


def _confidence_for(status: str, reason: str) -> int:
    low = (reason or "").lower()
    if status == "taken_down":
        if any(m in low for m in ("404", "410", "graph api", "dns")):
            return 96
        if "confirmed down" in low:
            return 90
        return 80
    return 40


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]*)</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _strip_tags(fragment: str) -> str:
    return re.sub(r"<[^>]+>", " ", fragment)


def prominent_text(html: str) -> str:
    """
    The page speaking in its own voice: <title>, every h1-h3 heading, and the
    og:title / og:description a platform publishes about the resource.

    This is where an error page states its business ("Sorry, this page isn't
    available"), and it is the layer the old fast path only sampled partially —
    title and the *first* h1 — which is why body-level notices slipped through.
    """
    if not html:
        return ""
    parts = [_extract_title(html)]

    for level in ("h1", "h2", "h3"):
        for m in re.finditer(rf"<{level}[^>]*>(.*?)</{level}>", html, re.IGNORECASE | re.DOTALL):
            parts.append(_strip_tags(m.group(1)))

    for prop in ("title", "description"):
        for pattern in (
            rf'<meta\s+(?:property|name)=["\']og:{prop}["\']\s+content=["\']([^"\']*)["\']',
            rf'content=["\']([^"\']*?)["\']\s+(?:property|name)=["\']og:{prop}["\']',
        ):
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                parts.append(m.group(1))
                break

    return normalize_text(" ".join(p for p in parts if p))


# ── Baseline Calibration ──────────────────────────────────────────────────────
# The only way to know what a server's "this does not exist" response looks like
# is to ask it for something that cannot exist. Web fuzzers call this
# auto-calibration; it is the difference between guessing that a page looks like
# a 404 and measuring that it is byte-for-byte the server's own 404.
#
# Three observations are compared:
#   target   — the URL under test
#   control  — a sibling path with a random token, which cannot exist
#   root     — the site's homepage
#
#   control == target != root  ->  the target IS the server's not-found page
#   control != target          ->  the target carries content the 404 page lacks
#   control == target == root  ->  the server answers everything identically
#                                  (geo-block, wildcard, parking, WAF) and
#                                  nothing can be concluded
#
# That last case is why the root probe is not optional: without it, a geo-blocked
# platform (every TikTok handle redirects to the same notice page) looks exactly
# like a site whose 404 page matches — and every live account would be certified
# as removed.

# Jaccard similarity above this means "the same page template with the same
# content". Real content shares boilerplate (nav/footer) with the 404 page but
# adds a body of its own, which drops the score well below this.
SAME_PAGE_SIMILARITY = 0.90


# Below this much text there is nothing meaningful to compare, and a comparison
# of two near-empty pages always looks like a perfect match.
MIN_COMPARABLE_CHARS = 30


def text_fingerprint(text: str) -> frozenset:
    """
    Feature set used for page comparison; small dynamic diffs don't shift it.

    Must be script-agnostic. An ASCII-only token regex returns an EMPTY set for
    Thai, Khmer, Japanese, Arabic, or Chinese pages, and two empty sets compare
    as a perfect match — which would certify every non-Latin page as identical
    to its server's 404 page. Space-delimited scripts use word tokens; anything
    else falls back to character shingles, which need no word boundaries.
    """
    if not text:
        return frozenset()
    # Error pages routinely echo the requested URL ("you don't have permission to
    # access http://host/some/path"). Those path words differ between the target
    # and the control purely because the URLs differ, which drags the similarity
    # of two otherwise-identical pages down far enough to read as "different
    # content". Compare the prose, not the address.
    text = re.sub(r"https?://\S+|www\.\S+", " ", text)
    tokens = re.findall(r"\w{2,}", text, flags=re.UNICODE)
    if len(tokens) >= 20:
        return frozenset(tokens)
    compact = re.sub(r"\s+", "", text)
    shingles = frozenset(compact[i:i + 4] for i in range(len(compact) - 3))
    return shingles or frozenset(tokens)


def similarity(a: str, b: str) -> float:
    """Jaccard similarity of two pages' word sets (1.0 = identical wording)."""
    fa, fb = text_fingerprint(a), text_fingerprint(b)
    if not fa and not fb:
        return 1.0
    if not fa or not fb:
        return 0.0
    return len(fa & fb) / len(fa | fb)


def classify_against_baseline(
    target_text: str, control_text: str, root_text: str,
    target_status: int | None = None, control_status: int | None = None,
) -> tuple[str, str, int]:
    """
    Decide a verdict by comparing the target with the server's own not-found and
    homepage responses. Returns (status, reason, confidence).
    """
    # An honest server: it really does 404 for things that don't exist, so its
    # status code for the target can be taken at face value.
    if control_status in (404, 410) and target_status == 200:
        return ("active",
                f"Verified live — server returns {control_status} for nonexistent paths "
                f"but 200 with content for this one", 94)

    # A geo-block notice stands in place of the resource, so NOTHING can be
    # concluded — least of all removal. This must be checked before any
    # similarity work: the notice is served for every path, so it matches the
    # control perfectly while differing from the homepage, which reads as
    # "identical to the server's not-found page -> removed". That certified three
    # geo-blocked TikTok accounts as removed at 95% confidence. The all-paths-
    # equal branch below is not sufficient, because the homepage is sometimes
    # reachable while deep links are blocked.
    geo = geo_blocked(target_text)
    if geo:
        return ("uncertain",
                f"Geo-blocked from this network (\"{geo}\") — the block notice is served instead "
                f"of the page, so existence cannot be determined; re-check via a proxy", 30)

    # A target that is itself an error or block page cannot be certified live no
    # matter how much it differs from the 404 page — Cloudflare's "suspected
    # phishing" interstitial differs from a 404 too. Nor is it proof of removal:
    # a wall hides whether the content is there. Neither verdict is available.
    if (target_status is not None and target_status >= 400) or hard_wall(target_text, ""):
        return ("uncertain",
                f"Target returned a block or error page"
                f"{f' (HTTP {target_status})' if target_status else ''} — comparison "
                f"cannot establish whether the content exists", 35)

    # Two nearly-empty pages always look identical; that is not evidence.
    if len(target_text) < MIN_COMPARABLE_CHARS or len(control_text) < MIN_COMPARABLE_CHARS:
        return ("uncertain",
                "Not enough page content to compare against the server's not-found response", 35)

    sim_control = similarity(target_text, control_text)
    sim_root = similarity(target_text, root_text)

    # Every URL returns the same page. Two very different situations look like
    # this, and they must not share a verdict.
    if sim_control >= SAME_PAGE_SIMILARITY and sim_root >= SAME_PAGE_SIMILARITY:
        geo = geo_blocked(target_text)
        if geo:
            # A block notice stands in place of the resource: we are being shown
            # the network's opinion, not the page. Nothing can be concluded from
            # this vantage point — a proxy in another country can.
            return ("uncertain",
                    f"Geo-blocked from this network (\"{geo}\") — the same notice is served for "
                    f"every URL, so existence cannot be determined; re-check via a proxy", 30)
        if len(target_text) >= SMALL_PAGE_CHARS:
            # The site's own content on every path — a wildcard catch-all, often
            # a repurposed/hijacked domain. The URL does serve a live page, which
            # is the question a takedown check is asking.
            return ("active",
                    "Live — server serves its content on every path including this one "
                    "(wildcard catch-all; the URL resolves to a working page)", 85)
        return ("uncertain",
                "Server returns an identical page for every URL including the homepage "
                "(wildcard or parking) — existence cannot be determined", 30)

    if sim_control >= SAME_PAGE_SIMILARITY:
        return ("taken_down",
                f"Removed — response is identical to this server's not-found page "
                f"(similarity {sim_control:.0%} vs a URL that cannot exist)", 95)

    # Distinct from the known-missing response: the server produced something
    # specific to this URL, which a removed resource does not have.
    if sim_control < 0.60:
        return ("active",
                f"Verified live — content differs from this server's not-found page "
                f"(similarity {sim_control:.0%})", 92)

    return ("uncertain",
            f"Partially matches this server's not-found page (similarity {sim_control:.0%}) "
            f"— not conclusive", 45)


def primary_text(records: list[FetchRecord], url: str = "", sources: tuple = ()) -> str:
    """
    Visible text of the observation the audit would judge.

    `sources` restricts which fetch methods may be used. Baseline calibration
    passes ("http", "curl") because the control and root probes are plain HTTP:
    comparing a Playwright-rendered target against an unrendered control measures
    the renderer, not the page, and every SPA would read as "content differs".
    Compare like with like or not at all.
    """
    if not records:
        return ""
    pool = [r for r in records if not sources or r.source in sources]
    if not pool:
        return ""
    on_target = [r for r in pool if _targets_same_resource(r.requested_url, url)] or pool
    _rec, body = _pick_primary([(r, r.text) for r in on_target])
    return body
