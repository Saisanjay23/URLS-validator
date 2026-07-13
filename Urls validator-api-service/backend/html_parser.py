"""
HTML Parser with Fallback Chain — Enterprise URL Validation Engine.

Parsing priority:
  1. selectolax (CSS selectors, ~30x faster than BeautifulSoup)
  2. Existing regex (always available as final fallback)

All functions return the same types as the original regex functions
in fast_checker.py to maintain full compatibility.
"""

from __future__ import annotations

import json
import re
from typing import Any

from backend.config import ENABLE_SELECTOLAX, ENABLE_STRUCTURED_METADATA

# ── Try importing selectolax ──────────────────────────────────────────────────

_HAS_SELECTOLAX = False
try:
    if ENABLE_SELECTOLAX:
        from selectolax.parser import HTMLParser as SelectolaxParser
        _HAS_SELECTOLAX = True
except ImportError:
    pass


# ── Regex Fallbacks (preserved from original fast_checker.py) ─────────────────

def _regex_title(html: str) -> str:
    """Extract <title> text via regex."""
    m = re.search(r"<title[^>]*>([^<]*)</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _regex_h1(html: str) -> str:
    """Extract first <h1> text via regex."""
    m = re.search(r"<h1[^>]*>([^<]*)</h1>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _regex_og(html: str, prop: str) -> str:
    """Extract OpenGraph property via regex."""
    for pattern in (
        rf'<meta\s+(?:property|name)=["\']og:{prop}["\']\s+content=["\']([^"\']*)["\']',
        rf'content=["\']([^"\']*?)["\'](?:\s+(?:property|name)=["\']og:{prop}["\'])',
    ):
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _regex_canonical(html: str) -> str:
    """Extract <link rel='canonical'> href via regex."""
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if not m:
        m = re.search(r'<link[^>]+href=["\']([^"\']*)["\'][^>]+rel=["\']canonical["\']', html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _regex_meta_robots(html: str) -> str:
    """Extract <meta name='robots'> content via regex."""
    m = re.search(r'<meta\s+name=["\']robots["\']\s+content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    return m.group(1).strip().lower() if m else ""


# ── Selectolax-Based Extraction ───────────────────────────────────────────────

def _selectolax_title(tree: Any) -> str:
    """Extract <title> using selectolax."""
    node = tree.css_first("title")
    return node.text(strip=True) if node else ""


def _selectolax_h1(tree: Any) -> str:
    """Extract first <h1> using selectolax."""
    node = tree.css_first("h1")
    return node.text(strip=True) if node else ""


def _selectolax_og(tree: Any, prop: str) -> str:
    """Extract OpenGraph property using selectolax."""
    for selector in (
        f'meta[property="og:{prop}"]',
        f'meta[name="og:{prop}"]',
    ):
        node = tree.css_first(selector)
        if node:
            val = node.attributes.get("content", "")
            if val:
                return val.strip()
    return ""


def _selectolax_canonical(tree: Any) -> str:
    """Extract canonical URL using selectolax."""
    node = tree.css_first('link[rel="canonical"]')
    if node:
        return (node.attributes.get("href", "") or "").strip()
    return ""


def _selectolax_meta_robots(tree: Any) -> str:
    """Extract robots meta using selectolax."""
    node = tree.css_first('meta[name="robots"]')
    if node:
        return (node.attributes.get("content", "") or "").strip().lower()
    return ""


def _selectolax_twitter_card(tree: Any) -> dict[str, str]:
    """Extract Twitter Card metadata using selectolax."""
    card: dict[str, str] = {}
    for node in tree.css('meta[name^="twitter:"]'):
        name = node.attributes.get("name", "")
        content = node.attributes.get("content", "")
        if name and content:
            key = name.replace("twitter:", "")
            card[key] = content.strip()
    return card


def _selectolax_json_ld(tree: Any) -> list[dict]:
    """Extract JSON-LD structured data using selectolax."""
    results: list[dict] = []
    for node in tree.css('script[type="application/ld+json"]'):
        text = node.text(strip=True)
        if text:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    results.extend(data)
                elif isinstance(data, dict):
                    results.append(data)
            except (json.JSONDecodeError, ValueError):
                pass
    return results


def _selectolax_og_image(tree: Any) -> str:
    """Extract og:image using selectolax."""
    return _selectolax_og(tree, "image")


# ── Regex-Based Structured Metadata ──────────────────────────────────────────

def _regex_twitter_card(html: str) -> dict[str, str]:
    """Extract Twitter Card metadata via regex."""
    card: dict[str, str] = {}
    for m in re.finditer(
        r'<meta\s+name=["\']twitter:(\w+)["\']\s+content=["\']([^"\']*)["\']',
        html, re.IGNORECASE,
    ):
        card[m.group(1)] = m.group(2).strip()
    return card


def _regex_json_ld(html: str) -> list[dict]:
    """Extract JSON-LD structured data via regex."""
    results: list[dict] = []
    for m in re.finditer(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        text = m.group(1).strip()
        if text:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    results.extend(data)
                elif isinstance(data, dict):
                    results.append(data)
            except (json.JSONDecodeError, ValueError):
                pass
    return results


# ── Unified API ───────────────────────────────────────────────────────────────

class ParsedHTML:
    """
    Unified parsed HTML result.
    
    Provides all extracted data via properties, regardless of which
    parser backend was used. All fields match the original regex
    function return types.
    """

    def __init__(self, html: str):
        self._html = html
        self._tree = None

        if _HAS_SELECTOLAX and html:
            try:
                self._tree = SelectolaxParser(html)
            except Exception:
                self._tree = None

    @property
    def title(self) -> str:
        if self._tree:
            val = _selectolax_title(self._tree)
            if val:
                return val
        return _regex_title(self._html)

    @property
    def h1(self) -> str:
        if self._tree:
            val = _selectolax_h1(self._tree)
            if val:
                return val
        return _regex_h1(self._html)

    @property
    def og_title(self) -> str:
        if self._tree:
            val = _selectolax_og(self._tree, "title")
            if val:
                return val
        return _regex_og(self._html, "title")

    @property
    def og_description(self) -> str:
        if self._tree:
            val = _selectolax_og(self._tree, "description")
            if val:
                return val
        return _regex_og(self._html, "description")

    @property
    def og_url(self) -> str:
        if self._tree:
            val = _selectolax_og(self._tree, "url")
            if val:
                return val
        return _regex_og(self._html, "url")

    @property
    def og_image(self) -> str:
        if self._tree:
            val = _selectolax_og(self._tree, "image")
            if val:
                return val
        return _regex_og(self._html, "image")

    @property
    def canonical(self) -> str:
        if self._tree:
            val = _selectolax_canonical(self._tree)
            if val:
                return val
        return _regex_canonical(self._html)

    @property
    def meta_robots(self) -> str:
        if self._tree:
            val = _selectolax_meta_robots(self._tree)
            if val:
                return val
        return _regex_meta_robots(self._html)

    @property
    def twitter_card(self) -> dict[str, str]:
        if not ENABLE_STRUCTURED_METADATA:
            return {}
        if self._tree:
            val = _selectolax_twitter_card(self._tree)
            if val:
                return val
        return _regex_twitter_card(self._html)

    @property
    def json_ld(self) -> list[dict]:
        if not ENABLE_STRUCTURED_METADATA:
            return []
        if self._tree:
            val = _selectolax_json_ld(self._tree)
            if val:
                return val
        return _regex_json_ld(self._html)

    @property
    def schema_types(self) -> list[str]:
        """Extract @type values from JSON-LD data."""
        types: list[str] = []
        for ld in self.json_ld:
            if isinstance(ld, dict):
                t = ld.get("@type")
                if isinstance(t, str):
                    types.append(t)
                elif isinstance(t, list):
                    types.extend(t)
        return types


def parse_html(html: str) -> ParsedHTML:
    """
    Parse HTML using the best available parser.
    
    Returns a ParsedHTML object with all extracted data accessible
    via properties. Falls back automatically if selectolax is unavailable.
    """
    return ParsedHTML(html)
