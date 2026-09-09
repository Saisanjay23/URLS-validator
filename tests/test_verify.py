"""
Verdict-audit tests — the false-positive cases the fast path used to miss.

Each test is a page that the HTTP checkers classify as `active` (HTTP 200, real
<title>, no removal phrase in title/h1) but which a human would immediately see
is dead. The audit must catch every one of them, without flipping genuinely live
pages to dead.

Run:  python -m pytest tests/test_verify.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.verify import (  # noqa: E402
    FetchRecord, audit_verdict, redirect_drift, scan_removal,
    normalize_text, visible_text,
)

NAV = "<nav>" + ("<a href='/x'>Home</a><a href='/y'>About</a>" * 60) + "</nav>"
FOOTER = "<footer>" + ("<p>Copyright 2026 Example Inc. All rights reserved.</p>" * 60) + "</footer>"


def page(body: str, title: str = "Example Site", head_extra: str = "") -> str:
    """A realistically sized page: chrome + body, well over the old 5KB cutoff."""
    return f"<html><head><title>{title}</title>{head_extra}</head><body>{NAV}{body}{FOOTER}</body></html>"


def tape(html: str, url: str = "https://example.com/user/johndoe",
         final: str | None = None, status: int = 200) -> list[FetchRecord]:
    return [FetchRecord(requested_url=url, final_url=final or url, status=status, html=html)]


def audit(html, url="https://example.com/user/johndoe", final=None, status=200,
          reason="Page is accessible (Example Site)"):
    return audit_verdict("active", reason, status, tape(html, url, final, status))


# ── The core complaint: HTTP 200, big page, 404 message in the body ───────────

@pytest.mark.parametrize("phrase", [
    "This content isn't available right now",
    "This content isn’t available right now",          # typographic apostrophe
    "Sorry, this page isn't available.",
    "The content you requested does not exist.",
    "Content unavailable",
    "This account doesn't exist",
    "Video unavailable",
    "This document has been removed",
    "404 Not Found",
    "The requested URL was not found on this server.",
    "This page doesn't exist",
])
def test_soft_404_in_body_of_large_page(phrase):
    """A 20KB+ page returning 200 whose body carries a removal notice is dead."""
    html = page(f"<div class='main'><h2>{phrase}</h2></div>")
    assert len(html) > 5000, "fixture must exceed the old 5KB scan cutoff"
    result = audit(html)
    assert result.status == "taken_down", f"{phrase!r} -> {result.status}: {result.reason}"
    assert result.confidence >= 90


def test_error_headline_over_an_article_sized_body_is_uncertain_not_active():
    """
    A removal phrase in the title but paragraphs of real content beneath it is
    contradictory evidence (a 404 page with a full sitemap looks like this, and
    so does an article headlined "Page Not Found"). The engine must not certify
    it either way — but it must never call it `active`.
    """
    html = page("<article>" + ("Lorem ipsum dolor sit amet. " * 400) + "</article>",
                title="Page Not Found | Example")
    result = audit(html)
    assert result.status == "uncertain"


def test_error_headline_on_a_chrome_only_page_is_taken_down():
    """Same headline, no real content beneath it — that is an error page."""
    html = page("<p>Try the homepage instead.</p>", title="Page Not Found | Example")
    assert audit(html).status == "taken_down"


# ── Must NOT create new false positives ───────────────────────────────────────

def test_live_article_discussing_404s_stays_active():
    """A real article that merely mentions '404 not found' is not a takedown."""
    body = (
        "<article><h1>How to fix broken links on your website</h1>"
        + ("<p>When a server cannot locate a resource it returns 404 not found "
           "to the client, and the visitor sees an error page. Monitoring for "
           "these responses is a routine part of site maintenance. </p>" * 40)
        + "</article>"
    )
    result = audit(page(body, title="Fixing Broken Links — Example Blog"))
    assert result.status == "uncertain", (
        "an incidental mention in a long article must not convict, but it is "
        "also not clean enough to certify"
    )
    assert result.status != "taken_down"


def test_normal_live_page_is_active():
    body = "<h1>John Doe</h1>" + ("<p>Software engineer and writer based in Berlin. </p>" * 60)
    result = audit(page(body, title="John Doe — Profile"))
    assert result.status == "active"
    assert result.confidence >= 82


def test_private_profile_is_never_taken_down():
    """
    A private account is proof the account EXISTS — it is not a takedown. The
    page carries removal-adjacent wording ("private", "follow to see"), so the
    only requirement is that it never lands in taken_down.
    """
    body = "<h1>This account is private</h1><p>Follow to see their photos and videos.</p>"
    result = audit(page(body, title="Instagram"))
    assert result.status != "taken_down"


def test_soft_boilerplate_does_not_demote_a_live_page():
    """
    'try again later' / 'temporarily unavailable' ship inside hidden error
    templates on live pages (YouTube's watch page carries several). Treating
    them as walls buried working URLs in the uncertain bucket.
    """
    body = ("<h1>Rick Astley - Never Gonna Give You Up</h1>"
            + ("<p>Official music video. </p>" * 60)
            + "<div hidden>An error occurred. Please try again later.</div>")
    assert audit(page(body, title="Rick Astley - YouTube")).status == "active"


def test_platform_chrome_wall_does_not_bury_an_identified_profile():
    """
    X prints "Log in or sign up" in the chrome of LIVE profiles. When the page
    still names the resource (og:title + bio), that identity is proof it exists;
    demoting on the surrounding chrome buried live accounts in the review queue.
    """
    html = (
        "<html><head><title>Rotana Turdi (@FoodicsCS) / X</title>"
        "<meta property='og:title' content='Rotana Turdi (@FoodicsCS) / X'>"
        "<meta property='og:description' content='Customer support account for "
        "Foodics — the restaurant management platform. Reach us any time.'>"
        "</head><body><nav>Log in or sign up</nav>"
        "<div>" + ("Timeline content here. " * 40) + "</div></body></html>"
    )
    assert audit(html, url="https://x.com/FoodicsCS",
                 final="https://x.com/FoodicsCS").status == "active"


def test_wall_wording_as_the_identity_still_demotes():
    """"Log in to view this 18+ content" IS the page — no identity, so gated."""
    html = (
        "<html><head><title>Log in to view this 18+ content</title>"
        "<meta property='og:title' content='Log in to view this 18+ content on Facebook'>"
        "</head><body><h1>Log in to view this 18+ content</h1>"
        "<p>" + ("You must log in to continue. " * 30) + "</p></body></html>"
    )
    assert audit(html, url="https://www.facebook.com/x/posts/1",
                 final="https://www.facebook.com/x/posts/1").status == "uncertain"


def test_real_login_wall_still_demotes():
    body = "<h1>Sign in</h1><p>Please log in to continue.</p>" + ("<p>. </p>" * 80)
    assert audit(page(body, title="Login")).status == "uncertain"


# ── Redirect drift ────────────────────────────────────────────────────────────

def test_deep_link_redirected_to_homepage_is_not_active():
    html = page("<h1>Welcome to Example</h1>" + ("<p>Our products are great. </p>" * 60),
                title="Example — Home")
    result = audit(html, url="https://example.com/user/johndoe", final="https://example.com/")
    assert result.status == "uncertain"
    assert "homepage" in result.reason


def test_redirect_to_login_is_not_active():
    html = page("<h1>Sign in</h1>" + ("<p>Enter your credentials. </p>" * 60))
    result = audit(html, url="https://site.com/profile/abc", final="https://site.com/login")
    assert result.status == "uncertain"


@pytest.mark.parametrize("req,fin,expect_drift", [
    ("https://a.com/user/xxxx", "https://a.com/", True),
    ("https://a.com/user/xxxx", "https://a.com/user/xxxx", False),
    ("https://a.com/user/xxxx", "https://a.com/user/xxxx/", False),      # trailing slash
    ("https://a.com/user/xxxx", "https://a.com/user/xxxx?ref=1", False),  # query only
    ("https://a.com/user/xxxx", "https://a.com/404", True),
    ("https://a.com/", "https://a.com/home", False),                # root asked for nothing
    # Locale prefixes and canonicalisation keep the identifying segment
    ("https://a.com/user/johndoe", "https://a.com/en/user/johndoe", False),
    ("https://a.com/user/johndoe", "https://a.com/users/johndoe/", False),
    # Geo-block: every handle lands on the same notice page
    ("https://www.tiktok.com/@ewec", "https://www.tiktok.com/in/about", True),
    ("https://www.tiktok.com/@paragoncorp2", "https://www.tiktok.com/in/about", True),
    # Shorteners legitimately redirect somewhere unrelated
    ("https://youtu.be/fE3ngyWowro", "https://www.youtube.com/watch?v=fE3ngyWowro", False),
    ("https://maps.app.goo.gl/CCgwSVh1kQHvgDtx8", "https://www.google.com/maps/place/Foo", False),
    ("https://vt.tiktok.com/ZSyE4VAk3/", "https://www.tiktok.com/@someone/video/12345", False),
    # Facebook share tokens are resolved by the site — not drift
    ("https://www.facebook.com/share/g/1JnfZJaMXS/", "https://www.facebook.com/groups/998877", False),
    # Identity lives in the query string; the site canonicalises the path away
    ("https://www.facebook.com/profile.php?id=4", "https://www.facebook.com/zuck", False),
    ("https://site.com/view.aspx?id=99", "https://site.com/people/bob", False),
])
def test_redirect_drift_matrix(req, fin, expect_drift):
    assert bool(redirect_drift(req, fin)) is expect_drift


def test_geoblocked_platform_is_not_reported_active():
    """
    TikTok is blocked from Indian IPs: every handle — live, dead, or never
    existed — 302s to /in/about and answers 200 with a healthy page, so no
    content probe can tell them apart. The only honest verdict is uncertain.
    """
    notice = page("<h1>Watch now</h1><p>Dear users, on June 29, 2020 the govt. of India "
                  "decided to block 59 apps, including TikTok.</p>", title="TikTok")
    result = audit(notice, url="https://www.tiktok.com/@ewec",
                   final="https://www.tiktok.com/in/about")
    assert result.status == "uncertain"
    # Geo-block is reported ahead of the redirect it caused: "blocked from this
    # network, retry via proxy" is actionable, "redirected away" is not.
    assert "geo_blocked" in result.signals
    assert "proxy" in result.reason.lower()


# ── Structural leaks ──────────────────────────────────────────────────────────

def test_empty_spa_shell_is_uncertain():
    html = "<html><head><title>My App</title></head><body><div id='root'></div></body></html>"
    result = audit(html)
    assert result.status == "uncertain"
    assert "readable content" in result.reason


def test_terse_but_real_page_stays_active():
    """example.com renders 127 visible chars under a short title — still a page."""
    html = ("<html><head><title>Example Domain</title></head><body>"
            "<h1>Example Domain</h1><p>This domain is for use in illustrative examples "
            "in documents. You may use this domain without permission.</p></body></html>")
    assert audit(html, url="https://example.com/", final="https://example.com/").status == "active"


def test_js_shell_with_rich_og_metadata_is_active():
    """
    Instagram/Facebook serve crawlers an empty body with the real substance in
    og:* tags. That metadata is positive proof the resource exists — treating
    the empty body alone as an unrendered shell demoted live profiles.
    """
    html = (
        "<html><head><title>Instagram</title>"
        "<meta property='og:title' content='NASA (@nasa) • Instagram photos and videos'>"
        "<meta property='og:description' content='104M Followers, 96 Following, "
        "4,882 Posts - See Instagram photos and videos from NASA (@nasa)'>"
        "</head><body><div id='react-root'></div></body></html>"
    )
    assert audit(html, url="https://www.instagram.com/nasa/",
                 final="https://www.instagram.com/nasa/").status == "active"


def test_403_waf_is_not_reported_active():
    """The old fast path hard-coded 403 -> 'active (protected by WAF)'."""
    html = page("<h1>Access Denied</h1><p>You do not have permission.</p>")
    result = audit_verdict(
        "active", "Active (protected by WAF/firewall: 403)", 403,
        tape(html, status=403),
    )
    assert result.status == "uncertain"


def test_404_anywhere_in_the_tape_outranks_active():
    records = [
        FetchRecord(requested_url="https://x.com/a", final_url="https://x.com/a",
                    status=404, html="<html><body>nope</body></html>"),
        FetchRecord(requested_url="https://x.com/a", final_url="https://x.com/a",
                    status=200, html=page("<h1>Home</h1>" + "<p>content</p>" * 200)),
    ]
    result = audit_verdict("active", "Page is accessible", 200, records)
    assert result.status == "taken_down"
    assert result.confidence >= 95


def test_active_with_no_captured_body_is_uncertain():
    assert audit_verdict("active", "Page is accessible", 200, []).status == "uncertain"


def test_api_verified_verdicts_bypass_the_audit():
    """Graph-API / oEmbed confirmations are proof already — don't second-guess."""
    result = audit_verdict(
        "active", "Facebook active (Graph API verified, login wall on browser)",
        200, tape("<html><body></body></html>"),
    )
    assert result.status == "active"
    assert result.confidence >= 95


# ── Multi-engine tapes: pick the right observation ────────────────────────────

URL = "https://site.com/user/abc"


def test_unrelated_api_response_does_not_decide_the_verdict():
    """
    Checkers fan out (HTML engines + Graph/oEmbed APIs). The last response on
    the tape is often a JSON probe, not the page — it must not be treated as
    the page's content.
    """
    records = [
        FetchRecord(requested_url=URL, final_url=URL, status=200,
                    html=page("<h1>Abc</h1>" + "<p>Real profile content. </p>" * 80)),
        FetchRecord(requested_url="https://graph.site.com/v1/abc", status=200,
                    final_url="https://graph.site.com/v1/abc", html='{"id":"1"}'),
    ]
    result = audit_verdict("active", "Profile is live", 200, records, url=URL)
    assert result.status == "active"


def test_404_on_a_sibling_path_does_not_convict():
    """An engine probing a different path 404ing says nothing about this URL."""
    records = [
        FetchRecord(requested_url="https://site.com/mbasic/abc", status=404,
                    final_url="https://site.com/mbasic/abc", html="not found"),
        FetchRecord(requested_url=URL, final_url=URL, status=200,
                    html=page("<h1>Abc</h1>" + "<p>Real profile content. </p>" * 80)),
    ]
    assert audit_verdict("active", "Profile is live", 200, records, url=URL).status == "active"


def test_browser_render_outranks_an_empty_http_shell():
    """The rendered DOM is what a human sees — prefer it over a blank shell."""
    records = [
        FetchRecord(requested_url=URL, final_url=URL, status=200,
                    html="<html><head><title>Site</title></head><body></body></html>"),
        FetchRecord(requested_url=URL, final_url=URL, status=200, source="playwright",
                    html=page("<h1>Sorry, this page isn't available</h1>")),
    ]
    result = audit_verdict("active", "Page is accessible", 200, records, url=URL)
    assert result.status == "taken_down"


def test_waf_block_page_does_not_outvote_the_delivered_page():
    """
    Cloudflare's interstitial is wordier than a terse 404 page. Ranking records
    by text volume alone picked the block page and certified a dead profile as
    live — a delivered 2xx response must win over a blocked one.
    """
    waf = ("<html><head><title>Attention Required! | Cloudflare</title></head><body>"
           "<h1>Sorry, you have been blocked</h1><p>" + ("You are unable to access this site. " * 20)
           + "</p></body></html>")
    real404 = ("<html><head><title>Medium</title></head><body>"
               "<p>Page not found. 404 out of nothing, something.</p></body></html>")
    records = [
        FetchRecord(requested_url=URL, final_url=URL, status=403, html=waf),
        FetchRecord(requested_url=URL, final_url=URL, status=200, source="curl", html=real404),
    ]
    result = audit_verdict("active", "Page is accessible (Medium)", 200, records, url=URL)
    assert result.status == "taken_down", result.reason


def test_waf_block_alone_is_uncertain_not_active():
    waf = ("<html><head><title>Attention Required! | Cloudflare</title></head><body>"
           "<h1>Sorry, you have been blocked</h1><p>" + ("Unable to access. " * 40)
           + "</p></body></html>")
    records = [FetchRecord(requested_url=URL, final_url=URL, status=403, html=waf)]
    assert audit_verdict("active", "Active (WAF)", 200, records, url=URL).status == "uncertain"


def test_empty_engine_response_does_not_outvote_a_loaded_one():
    records = [
        FetchRecord(requested_url=URL, final_url=URL, status=200,
                    html=page("<h1>Abc</h1>" + "<p>Real profile content. </p>" * 80)),
        FetchRecord(requested_url=URL, final_url=URL, status=200, html=""),
    ]
    assert audit_verdict("active", "Profile is live", 200, records, url=URL).status == "active"


# ── Non-active verdicts pass through untouched ────────────────────────────────

@pytest.mark.parametrize("status", ["taken_down", "uncertain"])
def test_audit_does_not_rewrite_non_active_verdicts(status):
    result = audit_verdict(status, "some reason", 404, tape(page("<p>x</p>")))
    assert result.status == status


# ── Huge script-heavy documents (YouTube/Facebook shape) ──────────────────────

def test_text_is_extracted_from_beyond_any_truncation_point():
    """
    YouTube ships ~2.3MB of markup whose first megabyte is a single <script>
    blob, with the real content after it. Truncating the HTML before extracting
    text left zero visible text, so a live page looked like an empty shell and
    was demoted. Extraction must see the whole document.
    """
    blob = "var ytInitialData = {" + ("x" * 1_200_000) + "};"
    html = (
        "<html><head><title>NASA - YouTube</title></head><body>"
        f"<script>{blob}</script>"
        "<div><h1>NASA</h1><p>" + ("Official NASA channel content. " * 60) + "</p></div>"
        "</body></html>"
    )
    rec = FetchRecord(requested_url="https://youtube.com/@NASA",
                      final_url="https://youtube.com/@NASA", status=200, html=html)
    assert len(html) > 1_000_000
    assert len(rec.text) > 500, "visible text must survive the script blob"
    assert "official nasa channel content." in rec.text
    assert "ytinitialdata" not in rec.text, "script contents must not leak into text"

    result = audit_verdict("active", "Page is accessible", 200, [rec],
                           url="https://youtube.com/@NASA")
    assert result.status == "active"


def test_record_releases_the_large_html_after_extraction():
    """Text is kept in full; the raw markup is not, so batches stay bounded."""
    html = "<html><body><p>" + ("content " * 50_000) + "</p></body></html>"
    rec = FetchRecord(requested_url="https://a.com/x", status=200, html=html)
    assert len(rec.html) <= 20_000 < len(html)
    assert len(rec.text) > 100_000


# ── Helpers ───────────────────────────────────────────────────────────────────

def test_visible_text_ignores_scripts_and_meta():
    html = (
        "<html><head><title>ok</title>"
        "<meta name='description' content='this content isnt available'></head>"
        "<body><script>var msg = \"page not found\";</script>"
        "<p>Real live content here.</p></body></html>"
    )
    text = visible_text(html)
    assert "page not found" not in text
    assert "real live content here." in text


def test_normalize_folds_smart_punctuation():
    assert normalize_text("This  content isn’t\navailable") == "this content isn't available"


def test_scan_removal_weights():
    # (visible_text, prominent_text, body_len)
    assert scan_removal("", "page not found", 50)[0] == 3        # headline, no body
    assert scan_removal("", "page not found", 90000)[0] == 2     # headline over an article
    assert scan_removal("page not found", "", 100)[0] == 3       # tiny page, body match
    assert scan_removal("page not found", "", 90000)[0] == 2     # buried in a big page
    assert scan_removal("all good here", "", 90000)[0] == 0


@pytest.mark.parametrize("text", [
    "the content you requested does not exist",
    "the page you asked for is no longer available",
    "this document has been taken down",
    "the video you requested was not found",
])
def test_novel_phrasings_are_caught_by_grammar_templates(text):
    """Wordings absent from the literal corpus still match the removal grammar."""
    assert scan_removal(text, "", 100)[0] == 3


@pytest.mark.parametrize("text", [
    "our content team is available monday to friday",
    "every page was found to load quickly in our tests",
    "the account manager will contact you shortly",
])
def test_benign_sentences_do_not_match(text):
    assert scan_removal(text, "", 100)[0] == 0


def test_geo_block_notice_in_rendered_page_is_uncertain_and_tagged():
    """
    The HTTP response for a geo-blocked platform is often a bare JS shell
    ("please wait..."), with the block notice painted only after rendering.
    Detect it on the rendered text and label it so the operator knows a proxy
    — not a code change — is what resolves it.
    """
    html = page(
        "<h1>Watch now</h1><p>Dear users, on June 29, 2020 the govt. of India "
        "decided to block 59 apps, including this service.</p>",
        title="TikTok",
    )
    result = audit(html, url="https://www.tiktok.com/@someone",
                   final="https://www.tiktok.com/@someone")
    assert result.status == "uncertain"
    assert "geo_blocked" in result.signals
    assert "proxy" in result.reason.lower()


def test_empty_render_is_never_a_takedown():
    """
    An empty page is absence of evidence, not evidence of removal — a bot wall,
    a blocked request, or a failed script all render empty. Softonic answers 406
    with a blank body (a "client challenge" sits behind it) and four of its URLs
    were reported as removed on that basis alone.
    """
    empty = "<html><head></head><body></body></html>"
    result = audit_verdict("uncertain", "Page rendered no content", 406,
                           tape(empty, "https://x.softonic.com/android/download"),
                           url="https://x.softonic.com/android/download")
    assert result.status != "taken_down"


def test_transient_platform_error_is_not_a_removal_signal():
    """
    X's SPA shell says "Something went wrong. Try reloading." whenever it
    rate-limits. Treated as a possible removal notice, it demoted 12 live
    accounts to uncertain on every loaded run. Apology/transient wording is not
    removal wording.
    """
    html = (
        "<html><head><title>Spark Minda (@sparkminda9434) / X</title>"
        "<meta property='og:title' content='Spark Minda (@sparkminda9434) / X'>"
        "<meta property='og:description' content='Official account of Spark Minda, "
        "an automotive component manufacturer serving global OEMs.'>"
        "</head><body><div>Something went wrong. Try reloading.</div></body></html>"
    )
    result = audit(html, url="https://x.com/SparkMinda9434",
                   final="https://x.com/SparkMinda9434")
    assert result.status != "taken_down"
    assert "removal notice" not in result.reason.lower()
