"""
Evidence Collection Layer — Enterprise URL Validation Engine.

Structured dataclass that collects every available signal BEFORE
any decision is made. Platform checkers populate this object,
and the decision engine evaluates it holistically.

This is metadata-only — it never changes existing status decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    """
    Container for all signals collected during a URL check.

    Every field is optional — checkers populate what they can.
    The confidence engine and decision engine read from this.
    """

    # ── DNS / HTTP ─────────────────────────────────────────────────────────
    dns_resolved: bool | None = None
    http_status: int | None = None

    # ── Redirects ──────────────────────────────────────────────────────────
    redirect_count: int = 0
    redirect_classifications: list[str] = field(default_factory=list)  # per-hop classification
    cross_domain: bool = False

    # ── Content — extracted from HTML ──────────────────────────────────────
    title: str = ""
    og_title: str = ""
    og_description: str = ""
    canonical: str = ""
    content_length: int = 0

    # ── Structured Metadata ────────────────────────────────────────────────
    json_ld: list[dict] = field(default_factory=list)
    twitter_card: dict[str, str] = field(default_factory=dict)
    schema_types: list[str] = field(default_factory=list)  # e.g. ["WebPage", "Organization"]

    # ── Infrastructure Detection ───────────────────────────────────────────
    server_type: str = ""                    # nginx, Apache, cloudflare, etc.
    cdn_provider: str | None = None          # Cloudflare, CloudFront, Fastly, etc.
    waf_detected: str | None = None          # Cloudflare, Imperva, etc.
    hosting_provider: str | None = None      # GitHub Pages, Netlify, Vercel, etc.

    # ── Platform-Specific Signals ──────────────────────────────────────────
    platform_signals: dict[str, Any] = field(default_factory=dict)
    # Examples:
    #   Facebook:  {"page_id": "123", "graph_api_exists": True}
    #   Instagram: {"username": "zuck", "followers": "1M"}

    # ── Parking / Seized ──────────────────────────────────────────────────
    parking_detected: bool = False
    parking_provider: str | None = None      # GoDaddy, Sedo, Namecheap, etc.

    # ── Error Classification ──────────────────────────────────────────────
    error_type: str | None = None
    # Values: DNS_ERROR, SSL_ERROR, TLS_HANDSHAKE, TIMEOUT, RATE_LIMITED,
    #         CLOUDFLARE_CHALLENGE, BOT_BLOCK, GEO_BLOCK, FIREWALL, WAF,
    #         CONNECTION_RESET, PROXY_BLOCK

    # ── Timing ────────────────────────────────────────────────────────────
    dns_time_ms: float = 0.0
    connect_time_ms: float = 0.0
    ttfb_ms: float = 0.0
    total_latency_ms: float = 0.0

    # ── Signals (for confidence scoring) ───────────────────────────────────
    _positive_signals: list[str] = field(default_factory=list)
    _negative_signals: list[str] = field(default_factory=list)

    def add_signal(self, name: str, positive: bool = True) -> None:
        """Record a signal for confidence scoring."""
        if positive:
            if name not in self._positive_signals:
                self._positive_signals.append(name)
        else:
            if name not in self._negative_signals:
                self._negative_signals.append(name)

    def to_metadata_dict(self) -> dict[str, Any]:
        """
        Export a compact metadata dict for the API response.
        Only includes fields that have non-default values.
        """
        meta: dict[str, Any] = {}

        # Timing
        if self.total_latency_ms > 0:
            meta["total_latency_ms"] = round(self.total_latency_ms, 1)
        if self.dns_time_ms > 0:
            meta["dns_latency_ms"] = round(self.dns_time_ms, 1)
        if self.ttfb_ms > 0:
            meta["ttfb_ms"] = round(self.ttfb_ms, 1)

        # Infrastructure
        if self.cdn_provider:
            meta["cdn"] = self.cdn_provider
        if self.waf_detected:
            meta["waf"] = self.waf_detected
        if self.hosting_provider:
            meta["hosting"] = self.hosting_provider
        if self.server_type:
            meta["server"] = self.server_type

        # Redirects
        if self.redirect_count > 0:
            meta["redirect_hops"] = self.redirect_count
        if self.cross_domain:
            meta["cross_domain_redirect"] = True
        if self.redirect_classifications:
            meta["redirect_types"] = self.redirect_classifications

        # Content
        if self.content_length > 0:
            meta["content_length"] = self.content_length

        # Parking
        if self.parking_detected:
            meta["parking_detected"] = True
            if self.parking_provider:
                meta["parking_provider"] = self.parking_provider

        # Error
        if self.error_type:
            meta["error_type"] = self.error_type

        # Platform
        if self.platform_signals:
            meta["platform"] = self.platform_signals

        # Structured metadata
        if self.json_ld:
            meta["json_ld_types"] = self.schema_types or [
                ld.get("@type", "unknown") for ld in self.json_ld if isinstance(ld, dict)
            ]

        return meta

    def to_log_dict(self) -> dict[str, Any]:
        """Export a dict optimized for structured logging."""
        d: dict[str, Any] = {}
        if self.dns_resolved is not None:
            d["dns_resolved"] = self.dns_resolved
        if self.dns_time_ms > 0:
            d["dns_ms"] = round(self.dns_time_ms, 1)
        if self.http_status is not None:
            d["http_status"] = self.http_status
        if self.connect_time_ms > 0:
            d["connect_ms"] = round(self.connect_time_ms, 1)
        if self.ttfb_ms > 0:
            d["ttfb_ms"] = round(self.ttfb_ms, 1)
        if self.total_latency_ms > 0:
            d["total_ms"] = round(self.total_latency_ms, 1)
        if self.redirect_count > 0:
            d["redirects"] = self.redirect_count
        if self.cdn_provider:
            d["cdn"] = self.cdn_provider
        if self.error_type:
            d["error_type"] = self.error_type
        if self.parking_detected:
            d["parked"] = True
        d["signals"] = len(self._positive_signals)
        d["neg_signals"] = len(self._negative_signals)
        return d
