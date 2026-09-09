"""
Baseline-calibration tests.

Reasoning about a page in isolation cannot settle a soft-404: a server that
answers HTTP 200 with a tidy error page is indistinguishable from one serving
real content. Calibration asks the server what a URL that CANNOT exist returns,
and compares. These tests pin the three outcomes — including the one that keeps
a geo-blocked site from being read as a site full of removed pages.

Run:  python -m pytest tests/test_baseline.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.verify import (  # noqa: E402
    classify_against_baseline, similarity, text_fingerprint,
)

CHROME = "home about contact careers privacy terms copyright example inc all rights reserved "
NOT_FOUND = CHROME + "sorry we could not find the page you requested try the homepage"
REAL = CHROME + "john doe senior engineer berlin portfolio projects publications talks contact me"
HOMEPAGE = CHROME + "welcome to example we build tools for teams pricing customers request a demo"
GEO_BLOCK = "watch now dear users the government decided to block this service in your region"


def test_target_identical_to_not_found_page_is_removed():
    st, why, conf = classify_against_baseline(NOT_FOUND, NOT_FOUND, HOMEPAGE)
    assert st == "taken_down"
    assert conf >= 90
    assert "not-found page" in why


def test_target_unlike_not_found_page_is_live():
    st, _why, conf = classify_against_baseline(REAL, NOT_FOUND, HOMEPAGE)
    assert st == "active"
    assert conf >= 90


def test_every_url_identical_including_homepage_is_uncertain():
    """
    A geo-block/wildcard/parking server returns the same page for everything.
    Without the homepage probe this looks like "matches the 404 page, therefore
    removed" — and every live account on a blocked platform gets certified dead.
    """
    st, why, conf = classify_against_baseline(GEO_BLOCK, GEO_BLOCK, GEO_BLOCK)
    assert st == "uncertain"
    assert conf <= 40
    # Recognised as a geo-block specifically (checked ahead of similarity), which
    # is more actionable than the generic "same page everywhere" finding.
    assert "geo-blocked" in why.lower() or "every url" in why.lower()


def test_honest_404_server_confirms_live_without_comparison():
    st, why, conf = classify_against_baseline(
        REAL, "not found", HOMEPAGE, target_status=200, control_status=404
    )
    assert st == "active"
    assert "404" in why and conf >= 90


def test_partial_match_stays_uncertain():
    """Between 60% and 90% similar is genuinely ambiguous — do not decide."""
    partial = CHROME + "sorry we could not find the page you requested plus a little extra text here"
    st, _why, conf = classify_against_baseline(partial, NOT_FOUND, HOMEPAGE)
    assert st in ("uncertain", "taken_down")
    if st == "uncertain":
        assert conf < 70


def test_similarity_bounds():
    assert similarity("alpha beta gamma", "alpha beta gamma") == 1.0
    assert similarity("alpha beta gamma", "delta epsilon zeta") == 0.0
    assert similarity("alpha beta", "") == 0.0


def test_non_latin_pages_are_comparable():
    """
    An ASCII-only fingerprint returns an empty set for Thai/Khmer/Japanese/
    Arabic/Chinese pages, and two empty sets compare as a perfect match — which
    would certify every non-Latin page as identical to its server's 404 page.
    """
    thai_live = "สุขาภิบาลอาหาร รุ่นที่ 3 ยินดีต้อนรับเข้าสู่กลุ่มเปิด กรุณาอ่านกฎก่อนเข้าร่วมสนทนา"
    thai_404 = "ขออภัย ไม่พบหน้าที่คุณต้องการ กรุณากลับไปยังหน้าแรกของเว็บไซต์นี้เพื่อดำเนินการต่อ"
    japanese = "大和コネクト証券 株式取引 口座開設 手数料無料 スマホで簡単に始められます"
    for page in (thai_live, thai_404, japanese):
        assert len(text_fingerprint(page)) > 10, "non-Latin text must produce features"
    assert similarity(thai_live, thai_404) < 0.2
    assert similarity(thai_live, thai_live) == 1.0
    assert classify_against_baseline(thai_live, thai_404, japanese)[0] == "active"


def test_near_empty_pages_are_never_declared_identical():
    """Two blank pages match perfectly — that is absence of evidence, not proof."""
    st, why, _c = classify_against_baseline("tiny", "tiny", "home page content here")
    assert st == "uncertain"
    assert "not enough" in why.lower()


# ── Block pages must never be certified live ──────────────────────────────────

def test_block_page_is_never_certified_live():
    """
    Cloudflare's "suspected phishing" interstitial differs from a 404 page, so a
    pure difference test called it live content. A wall is not content — and it
    is not proof of removal either, so neither verdict is available.
    """
    block = "warning suspected phishing this website has been reported for potential phishing"
    st, why, _c = classify_against_baseline(block, NOT_FOUND, HOMEPAGE, target_status=403)
    assert st == "uncertain"
    assert "block or error page" in why


def test_block_page_detected_by_wording_without_a_status():
    denied = "access denied you do not have permission to access this resource on this server"
    st, _why, _c = classify_against_baseline(denied, NOT_FOUND, HOMEPAGE, target_status=200)
    assert st == "uncertain"


def test_echoed_url_does_not_make_identical_pages_look_different():
    """
    Error pages echo the requested URL. Those path words differ between target
    and control purely because the URLs differ — which dragged two identical
    "Access denied" pages down to 57% similarity and read as "different content".
    """
    tgt = 'you do not have permission to access "http://site.com/announcement/tender-25000-cctv" on this server'
    ctl = 'you do not have permission to access "http://site.com/zqabcdefgh12345" on this server'
    assert similarity(tgt, ctl) > 0.95


# ── Geo-block vs wildcard catch-all ───────────────────────────────────────────
# Both answer every URL with the same page. One is a notice standing in place of
# the resource; the other is the site's own content actually being served.

GEO_NOTICE = ("watch now dear users on june 29 2020 the govt. of india decided to block "
              "59 apps including this service we are complying with the directive")
WILDCARD = ("wama88 taruhan slot judi online terpercaya daftar sekarang bonus new member "
            "deposit pulsa tanpa potongan link alternatif resmi live casino sportsbook "
            "poker online promo harian withdraw cepat layanan pelanggan 24 jam " * 16)


def test_geo_block_notice_stays_uncertain():
    st, why, _c = classify_against_baseline(GEO_NOTICE, GEO_NOTICE, GEO_NOTICE)
    assert st == "uncertain"
    assert "geo-blocked" in why.lower()
    assert "proxy" in why.lower(), "must tell the operator how to resolve it"


def test_wildcard_catch_all_serving_real_content_is_live():
    """A hijacked domain answering every path with its own page IS serving a live page."""
    assert len(WILDCARD) >= 2500, "fixture must carry a real page's worth of content"
    st, why, conf = classify_against_baseline(WILDCARD, WILDCARD, WILDCARD)
    assert st == "active"
    assert "wildcard" in why.lower()
    assert conf >= 80


def test_wildcard_with_no_real_content_stays_uncertain():
    thin = "welcome " * 12
    st, _why, _c = classify_against_baseline(thin, thin, thin)
    assert st == "uncertain"


def test_geo_notice_beats_wildcard_even_with_lots_of_text():
    """Padding must not turn a block notice into a live verdict."""
    padded = GEO_NOTICE + " " + ("additional filler copy about the service " * 60)
    st, why, _c = classify_against_baseline(padded, padded, padded)
    assert st == "uncertain"
    assert "geo-blocked" in why.lower()


def test_geo_notice_matching_control_is_never_a_takedown():
    """
    The regression that certified three geo-blocked TikTok accounts as removed
    at 95%: the block notice is served for every path, so it matches the control
    exactly while differing from a reachable homepage — which reads as
    "identical to the not-found page". Geo-block must be checked before any
    similarity work, not only when all three probes agree.
    """
    homepage = "tiktok trending discover upload log in sign up for you following explore " * 8
    st, why, _c = classify_against_baseline(GEO_NOTICE, GEO_NOTICE, homepage)
    assert st == "uncertain", f"got {st}: {why}"
    assert "geo-blocked" in why.lower()
