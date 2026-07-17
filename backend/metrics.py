"""
Performance Metrics Collector — Enterprise URL Validation Engine.

Thread-safe metrics collection for performance monitoring.
Collects per-check timing breakdowns and aggregated statistics.

Exposed via /api/metrics endpoint.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class CheckMetric:
    """Timing breakdown for a single URL check."""
    url: str = ""
    platform: str = ""
    status: str = ""
    dns_ms: float = 0.0
    connect_ms: float = 0.0
    ttfb_ms: float = 0.0
    total_ms: float = 0.0
    error_type: str | None = None


class MetricsCollector:
    """
    Thread-safe metrics collector.

    Stores the last N check metrics and computes aggregated statistics.
    Uses a circular buffer to bound memory usage.
    """

    def __init__(self, max_history: int = 10000):
        self._max_history = max_history
        self._metrics: list[CheckMetric] = []
        self._lock = asyncio.Lock()

        # Counters
        self._total_checks = 0
        self._status_counts: dict[str, int] = defaultdict(int)
        self._platform_counts: dict[str, int] = defaultdict(int)
        self._error_counts: dict[str, int] = defaultdict(int)

        # Timing accumulators (for computing averages)
        self._total_dns_ms = 0.0
        self._total_connect_ms = 0.0
        self._total_ttfb_ms = 0.0
        self._total_check_ms = 0.0

        # Start time
        self._start_time = time.time()

    async def record(self, metric: CheckMetric) -> None:
        """Record a single check metric."""
        async with self._lock:
            self._metrics.append(metric)
            if len(self._metrics) > self._max_history:
                self._metrics = self._metrics[-self._max_history:]

            self._total_checks += 1
            self._status_counts[metric.status] += 1
            self._platform_counts[metric.platform] += 1

            if metric.error_type:
                self._error_counts[metric.error_type] += 1

            self._total_dns_ms += metric.dns_ms
            self._total_connect_ms += metric.connect_ms
            self._total_ttfb_ms += metric.ttfb_ms
            self._total_check_ms += metric.total_ms

    def get_summary(self) -> dict[str, Any]:
        """
        Return aggregated metrics summary.

        Includes:
          - Total checks, uptime, throughput
          - Status breakdown
          - Platform breakdown
          - Timing averages and percentiles
          - Error breakdown
        """
        uptime_s = time.time() - self._start_time
        n = self._total_checks or 1

        summary: dict[str, Any] = {
            "uptime_seconds": round(uptime_s, 1),
            "total_checks": self._total_checks,
            "throughput_per_minute": round(self._total_checks / max(uptime_s / 60, 1), 1),
            "status_breakdown": dict(self._status_counts),
            "platform_breakdown": dict(self._platform_counts),
            "timing": {
                "avg_dns_ms": round(self._total_dns_ms / n, 1),
                "avg_connect_ms": round(self._total_connect_ms / n, 1),
                "avg_ttfb_ms": round(self._total_ttfb_ms / n, 1),
                "avg_total_ms": round(self._total_check_ms / n, 1),
            },
        }

        # Compute percentiles from recent history
        if self._metrics:
            recent = self._metrics[-min(1000, len(self._metrics)):]
            total_times = sorted(m.total_ms for m in recent)
            n_recent = len(total_times)
            summary["timing"]["p50_total_ms"] = round(total_times[n_recent // 2], 1)
            summary["timing"]["p95_total_ms"] = round(total_times[int(n_recent * 0.95)], 1)
            summary["timing"]["p99_total_ms"] = round(total_times[int(n_recent * 0.99)], 1)

        if self._error_counts:
            summary["error_breakdown"] = dict(self._error_counts)

        return summary


# ── Global Instance ───────────────────────────────────────────────────────────

metrics_collector = MetricsCollector()
