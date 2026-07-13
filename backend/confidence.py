"""
Confidence Scoring Engine — Enterprise URL Validation Engine.

Computes a 0-100 confidence score based on collected evidence signals.
NEVER overrides existing status decisions — confidence is metadata only.

Scoring Philosophy:
  - Each signal contributes independently
  - Positive signals increase confidence
  - Negative signals decrease confidence
  - Score is clamped to [0, 100]
  - Platform-specific bonuses for strong platform signals
"""

from __future__ import annotations

from backend.evidence import Evidence


# ── Scoring Weights ───────────────────────────────────────────────────────────
# Positive factors (evidence that content exists or is active)

_POSITIVE_WEIGHTS: dict[str, int] = {
    "dns_resolved":            15,
    "http_200":                20,
    "og_metadata":             20,
    "canonical_url":           10,
    "json_ld_present":         10,
    "twitter_card":             5,
    "redirect_consistent":     10,
    "real_title":               5,
    "content_substantial":      5,  # > 2KB
    "known_cdn":                5,
    "structured_data":          5,
    "platform_verified":       15,  # platform-specific strong signal
    "oembed_verified":         15,
    "graph_api_verified":      15,
    "multi_engine_verified":   10,
}

# Negative factors (evidence that content is gone)

_NEGATIVE_WEIGHTS: dict[str, int] = {
    "http_404":                80,
    "http_410":                90,
    "http_451":                85,
    "dns_failure":            100,
    "parking_detected":        60,
    "redirect_to_parking":     70,
    "takedown_signal":         75,
    "empty_page":              40,
    "generic_title":           20,
    "login_wall":              15,
    "bot_blocked":             10,
    "cloudflare_challenge":    10,
    "timeout":                 15,
    "connection_reset":        20,
    "suspended_account":       90,
}


def compute_confidence(evidence: Evidence) -> tuple[int, list[str]]:
    """
    Compute a confidence score from collected evidence.

    Returns:
        (score, signals) where:
        - score: 0-100 integer. Higher = more confident in the determination.
        - signals: List of signal names that contributed to the score.

    The score reflects how confident we are in the STATUS (whether active or taken_down).
    A high score on an "active" result means "very likely truly active".
    A high score on a "taken_down" result means "very likely truly removed".
    """
    positive_score = 0
    negative_score = 0
    signals: list[str] = []

    # ── Evaluate positive signals ─────────────────────────────────────────

    if evidence.dns_resolved is True:
        positive_score += _POSITIVE_WEIGHTS["dns_resolved"]
        signals.append("dns_resolved")
        evidence.add_signal("dns_resolved", positive=True)

    if evidence.http_status == 200:
        positive_score += _POSITIVE_WEIGHTS["http_200"]
        signals.append("http_200")
        evidence.add_signal("http_200", positive=True)

    if evidence.og_title or evidence.og_description:
        positive_score += _POSITIVE_WEIGHTS["og_metadata"]
        signals.append("og_metadata")
        evidence.add_signal("og_metadata", positive=True)

    if evidence.canonical:
        positive_score += _POSITIVE_WEIGHTS["canonical_url"]
        signals.append("canonical_url")
        evidence.add_signal("canonical_url", positive=True)

    if evidence.json_ld:
        positive_score += _POSITIVE_WEIGHTS["json_ld_present"]
        signals.append("json_ld_present")
        evidence.add_signal("json_ld_present", positive=True)

    if evidence.twitter_card:
        positive_score += _POSITIVE_WEIGHTS["twitter_card"]
        signals.append("twitter_card")
        evidence.add_signal("twitter_card", positive=True)

    if not evidence.cross_domain and evidence.redirect_count <= 3:
        positive_score += _POSITIVE_WEIGHTS["redirect_consistent"]
        signals.append("redirect_consistent")
        evidence.add_signal("redirect_consistent", positive=True)

    if evidence.title and evidence.title.lower() not in ("", "untitled", "error"):
        positive_score += _POSITIVE_WEIGHTS["real_title"]
        signals.append("real_title")
        evidence.add_signal("real_title", positive=True)

    if evidence.content_length > 2048:
        positive_score += _POSITIVE_WEIGHTS["content_substantial"]
        signals.append("content_substantial")
        evidence.add_signal("content_substantial", positive=True)

    if evidence.cdn_provider:
        positive_score += _POSITIVE_WEIGHTS["known_cdn"]
        signals.append("known_cdn")
        evidence.add_signal("known_cdn", positive=True)

    # Platform-specific strong signals
    ps = evidence.platform_signals
    if ps.get("platform_verified"):
        positive_score += _POSITIVE_WEIGHTS["platform_verified"]
        signals.append("platform_verified")
        evidence.add_signal("platform_verified", positive=True)

    if ps.get("oembed_verified"):
        positive_score += _POSITIVE_WEIGHTS["oembed_verified"]
        signals.append("oembed_verified")
        evidence.add_signal("oembed_verified", positive=True)

    if ps.get("graph_api_verified"):
        positive_score += _POSITIVE_WEIGHTS["graph_api_verified"]
        signals.append("graph_api_verified")
        evidence.add_signal("graph_api_verified", positive=True)

    if ps.get("multi_engine_verified"):
        positive_score += _POSITIVE_WEIGHTS["multi_engine_verified"]
        signals.append("multi_engine_verified")
        evidence.add_signal("multi_engine_verified", positive=True)

    # ── Evaluate negative signals ─────────────────────────────────────────

    if evidence.http_status == 404:
        negative_score += _NEGATIVE_WEIGHTS["http_404"]
        signals.append("-http_404")
        evidence.add_signal("http_404", positive=False)

    if evidence.http_status == 410:
        negative_score += _NEGATIVE_WEIGHTS["http_410"]
        signals.append("-http_410")
        evidence.add_signal("http_410", positive=False)

    if evidence.http_status == 451:
        negative_score += _NEGATIVE_WEIGHTS["http_451"]
        signals.append("-http_451")
        evidence.add_signal("http_451", positive=False)

    if evidence.dns_resolved is False:
        negative_score += _NEGATIVE_WEIGHTS["dns_failure"]
        signals.append("-dns_failure")
        evidence.add_signal("dns_failure", positive=False)

    if evidence.parking_detected:
        weight_key = "redirect_to_parking" if evidence.cross_domain else "parking_detected"
        negative_score += _NEGATIVE_WEIGHTS[weight_key]
        signals.append(f"-{weight_key}")
        evidence.add_signal(weight_key, positive=False)

    if evidence.error_type == "TIMEOUT":
        negative_score += _NEGATIVE_WEIGHTS["timeout"]
        signals.append("-timeout")
        evidence.add_signal("timeout", positive=False)

    if evidence.error_type == "CONNECTION_RESET":
        negative_score += _NEGATIVE_WEIGHTS["connection_reset"]
        signals.append("-connection_reset")
        evidence.add_signal("connection_reset", positive=False)

    if evidence.error_type in ("BOT_BLOCK", "RATE_LIMITED"):
        negative_score += _NEGATIVE_WEIGHTS["bot_blocked"]
        signals.append("-bot_blocked")
        evidence.add_signal("bot_blocked", positive=False)

    if evidence.error_type == "CLOUDFLARE_CHALLENGE":
        negative_score += _NEGATIVE_WEIGHTS["cloudflare_challenge"]
        signals.append("-cloudflare_challenge")
        evidence.add_signal("cloudflare_challenge", positive=False)

    # ── Compute final score ───────────────────────────────────────────────
    # For "active" results: confidence = positive_score (capped at 100)
    # For "taken_down" results: confidence = negative_score (capped at 100)
    # For "uncertain": confidence = max(positive, negative) but lower overall
    #
    # We return the raw magnitude — the caller (fast_checker) applies
    # direction based on the existing status decision.

    raw_score = max(positive_score, negative_score)
    score = min(100, max(0, raw_score))

    return score, signals
