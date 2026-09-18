"""
URL normalisation tests.

Normalisation bugs are the most dangerous class of false positive in this tool:
a mangled URL fetches a genuinely different page, so the engine reports a real
404 with full confidence and no signal that anything went wrong.

Run:  python -m pytest tests/test_url_utils.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.url_utils import (  # noqa: E402
    normalize_url, detect_platform, deduplicate_urls, is_email,
    normalize_email, detect_email_provider
)


# ── Balanced brackets must survive ────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://en.wikipedia.org/wiki/Python_(programming_language)",
    "https://en.wikipedia.org/wiki/Alien_(film)",
    "https://en.wikipedia.org/wiki/Mercury_(planet)",
    "https://example.com/path_(with)_(two)_groups",
    "https://example.com/a[0]",
])
def test_balanced_brackets_are_preserved(url):
    """Truncating these fetches a different page — a guaranteed false 404."""
    assert normalize_url(url) == url


@pytest.mark.parametrize("raw,expected", [
    # Unbalanced trailing bracket really is copy-paste noise
    ("https://example.com/page)", "https://example.com/page"),
    ("https://example.com/page]", "https://example.com/page"),
    ("(see https://example.com/page)", "https://example.com/page"),
    # Ordinary trailing punctuation
    ("https://example.com/page,", "https://example.com/page"),
    ("https://example.com/page;", "https://example.com/page"),
    ('"https://example.com/page"', "https://example.com/page"),
    ("https://example.com/page>", "https://example.com/page"),
    # Mixed noise after a balanced group
    ("https://en.wikipedia.org/wiki/Alien_(film),",
     "https://en.wikipedia.org/wiki/Alien_(film)"),
])
def test_trailing_noise_is_stripped(raw, expected):
    assert normalize_url(raw) == expected


# ── Existing normalisation behaviour must not regress ─────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com"),
    ("  https://example.com  ", "https://example.com"),
    ("https ://example.com", "https://example.com"),
    ("http://https://example.com", "https://example.com"),
    ("https://example.com/page extra words here", "https://example.com/page"),
])
def test_normalisation_basics(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", None, "notaurl"])
def test_garbage_input_returns_none(raw):
    assert normalize_url(raw) is None


def test_query_strings_survive():
    url = "https://example.com/watch?v=abc123&t=10s"
    assert normalize_url(url) == url


# ── Platform detection ────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,platform", [
    ("https://www.facebook.com/someone", "facebook"),
    ("https://twitter.com/someone", "x"),
    ("https://x.com/someone", "x"),
    ("https://t.me/channel", "telegram"),
    ("https://youtu.be/abc", "youtube"),
    ("https://example.com/anything", "generic"),
])
def test_detect_platform(url, platform):
    assert detect_platform(url) == platform


def test_deduplicate_preserves_order():
    urls = ["https://b.com", "https://a.com", "https://b.com"]
    assert deduplicate_urls(urls) == ["https://b.com", "https://a.com"]


# ── Email detection & rejection ───────────────────────────────────────────────

@pytest.mark.parametrize("email", [
    "trace@gmail.com",
    "seatowninternationaladmin@gmail.com",
    "user.name+tag@example.com",
    "admin@sub.domain.org",
    "mailto:user@example.com",
])
def test_email_addresses_are_detected_and_rejected(email):
    """Email addresses are not web URLs and must not be prepended with https://."""
    assert is_email(email) is True
    assert normalize_url(email) is None


@pytest.mark.parametrize("url", [
    "https://www.youtube.com/@username",
    "youtube.com/@username",
    "https://medium.com/@author",
    "https://t.me/rytbank",
    "https://example.com/path",
])
def test_urls_with_at_in_path_are_not_emails(url):
    """URLs that contain '@' in the path (e.g. YouTube handles) must normalize normally."""
    assert is_email(url) is False
    assert normalize_url(url) is not None


@pytest.mark.asyncio
async def test_process_urls_stream_handles_mixed_inputs():
    """Verify that separate inputs (URLs, bare handles, emails) are never merged."""
    from backend.fast_checker import process_urls_stream

    raw_inputs = [
        "https://t.me/rytbank",
        "boostpayflexbackup",
        "trace@gmail.com",
        "seatowninternationaladmin@gmail.com",
    ]
    results = []
    summary = None
    async for event in process_urls_stream(raw_inputs):
        if event.get("type") == "result":
            results.append(event)
        if event.get("done"):
            summary = event.get("summary")

    assert len(results) == 4
    assert summary["total"] == 4
    urls = [r["url"] for r in results]
    assert "https://t.me/rytbank" in urls
    assert "boostpayflexbackup" in urls
    assert "trace@gmail.com" in urls
    assert "seatowninternationaladmin@gmail.com" in urls
    assert not any("rytbankboostpayflex" in u for u in urls)


# ── Email normalization & platform tests ─────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("user@example.com", "user@example.com"),
    ("  User@Example.COM  ", "user@example.com"),
    ("mailto:support@google.com", "support@google.com"),
    ("<info@cyfirma.com>", "info@cyfirma.com"),
    ("contact@domain.co.uk,", "contact@domain.co.uk"),
    ("invalid-email", None),
    ("@nodomain.com", None),
    ("noat.com", None),
    ("", None),
])
def test_normalize_email(raw, expected):
    assert normalize_email(raw) == expected


@pytest.mark.parametrize("email,expected_provider", [
    ("test@gmail.com", "gmail"),
    ("user@googlemail.com", "gmail"),
    ("person@outlook.com", "outlook"),
    ("person@hotmail.com", "outlook"),
    ("person@live.com", "outlook"),
    ("user@yahoo.com", "yahoo"),
    ("user@ymail.com", "yahoo"),
    ("user@icloud.com", "icloud"),
    ("sec@proton.me", "proton"),
    ("custom@company.org", "email"),
])
def test_detect_email_provider(email, expected_provider):
    assert detect_email_provider(email) == expected_provider
    assert detect_platform(email) == expected_provider


