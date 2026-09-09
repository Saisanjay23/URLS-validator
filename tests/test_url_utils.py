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

from backend.url_utils import normalize_url, detect_platform, deduplicate_urls  # noqa: E402


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
