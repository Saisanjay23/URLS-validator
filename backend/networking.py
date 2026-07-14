"""
Networking Infrastructure — Enterprise URL Validation Engine.

Contains:
  1. Circuit Breaker — Per-host failure tracking with auto-recovery
  2. Adaptive Rate Limiter — Per-host concurrency semaphores
  3. Enhanced Retry Engine — Retries only transient failures
  4. Enhanced DNS Resolver — Better error classification

All components are independently feature-flagged.
"""

from __future__ import annotations

import asyncio
import random
import socket
import time
from typing import Any

import aiohttp

from backend.config import (
    CIRCUIT_BREAKER_COOLDOWN,
    CIRCUIT_BREAKER_THRESHOLD,
    ENABLE_CIRCUIT_BREAKER,
    HOST_CONCURRENCY,
    RETRY_BASE_DELAY,
    RETRY_MAX_ATTEMPTS,
    RETRY_MAX_DELAY,
    RETRY_STATUS_CODES,
    NO_RETRY_STATUS_CODES,
)
from backend.logger import get_logger

logger = get_logger()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════════════════

class CircuitBreaker:
    """
    Per-host circuit breaker to prevent hammering failing hosts.

    States:
      CLOSED   — Normal operation. Requests pass through.
      OPEN     — Host is failing. Requests are rejected.
      HALF_OPEN — Cooldown expired. One test request is allowed.

    Thread-safe via asyncio Lock.
    """

    def __init__(self, threshold: int = CIRCUIT_BREAKER_THRESHOLD,
                 cooldown: float = CIRCUIT_BREAKER_COOLDOWN):
        self._threshold = threshold
        self._cooldown = cooldown
        self._failures: dict[str, int] = {}
        self._open_since: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def is_open(self, host: str) -> bool:
        """Check if the circuit is open (host should be skipped)."""
        if not ENABLE_CIRCUIT_BREAKER:
            return False

        # Exclude social media platforms from circuit breaker tripping
        normalized = host.lower().removeprefix("www.").removeprefix("m.")
        if normalized in {
            "instagram.com", "facebook.com", "linkedin.com", "x.com", 
            "twitter.com", "youtube.com", "youtu.be", "t.me", "telegram.me"
        }:
            return False

        async with self._lock:
            if host not in self._open_since:
                return False

            elapsed = time.monotonic() - self._open_since[host]
            if elapsed >= self._cooldown:
                # Transition to HALF_OPEN — allow one request
                del self._open_since[host]
                self._failures[host] = self._threshold - 1  # One more failure re-opens
                logger.info(f"[CIRCUIT_BREAKER] {host} → HALF_OPEN (cooldown expired)")
                return False

            return True

    async def record_success(self, host: str) -> None:
        """Record a successful request — reset failure counter."""
        if not ENABLE_CIRCUIT_BREAKER:
            return

        async with self._lock:
            self._failures.pop(host, None)
            self._open_since.pop(host, None)

    async def record_failure(self, host: str) -> None:
        """Record a failed request — may trip the circuit."""
        if not ENABLE_CIRCUIT_BREAKER:
            return

        # Exclude social media platforms from recording circuit breaker failures
        normalized = host.lower().removeprefix("www.").removeprefix("m.")
        if normalized in {
            "instagram.com", "facebook.com", "linkedin.com", "x.com", 
            "twitter.com", "youtube.com", "youtu.be", "t.me", "telegram.me"
        }:
            return

        async with self._lock:
            self._failures[host] = self._failures.get(host, 0) + 1
            if self._failures[host] >= self._threshold:
                self._open_since[host] = time.monotonic()
                logger.warning(
                    f"[CIRCUIT_BREAKER] {host} → OPEN "
                    f"({self._failures[host]} consecutive failures, "
                    f"cooldown={self._cooldown}s)"
                )

    def get_status(self) -> dict[str, str]:
        """Return current circuit state for all tracked hosts."""
        now = time.monotonic()
        status: dict[str, str] = {}
        for host in set(list(self._failures.keys()) + list(self._open_since.keys())):
            if host in self._open_since:
                elapsed = now - self._open_since[host]
                if elapsed >= self._cooldown:
                    status[host] = "half_open"
                else:
                    status[host] = f"open ({int(self._cooldown - elapsed)}s remaining)"
            elif self._failures.get(host, 0) > 0:
                status[host] = f"closed ({self._failures[host]} failures)"
            else:
                status[host] = "closed"
        return status


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ADAPTIVE RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveRateLimiter:
    """
    Per-host concurrency limiter using asyncio Semaphores.

    Each host gets an independent semaphore with a configurable limit,
    preventing any single platform from starving others.
    """

    def __init__(self, host_limits: dict[str, int] | None = None):
        self._limits = host_limits or HOST_CONCURRENCY
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        """Acquire a concurrency slot for the given host."""
        sem = await self._get_semaphore(host)
        await sem.acquire()

    def release(self, host: str) -> None:
        """Release a concurrency slot for the given host."""
        sem = self._semaphores.get(host) or self._semaphores.get("_default")
        if sem:
            sem.release()

    async def _get_semaphore(self, host: str) -> asyncio.Semaphore:
        """Get or create a semaphore for the given host."""
        # Normalize host
        normalized = host.lower().removeprefix("www.").removeprefix("m.")

        async with self._lock:
            if normalized not in self._semaphores:
                limit = self._limits.get(normalized, self._limits.get("_default", 10))
                self._semaphores[normalized] = asyncio.Semaphore(limit)
            return self._semaphores[normalized]

    def get_config(self) -> dict[str, int]:
        """Return per-host concurrency configuration."""
        return dict(self._limits)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ENHANCED RETRY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def should_retry(status_code: int | None = None,
                 error: Exception | None = None) -> bool:
    """
    Determine if a request should be retried.

    Retries ONLY transient failures:
      - HTTP 429, 500, 502, 503, 504
      - Timeout errors
      - Connection reset
      - SSL handshake failures

    NEVER retries:
      - HTTP 404, 410, 451 (permanent)
      - DNS failures (NXDOMAIN)
      - Content-based decisions
    """
    if status_code is not None:
        if status_code in NO_RETRY_STATUS_CODES:
            return False
        if status_code in RETRY_STATUS_CODES:
            return True

    if error is not None:
        error_type = type(error).__name__
        error_msg = str(error).lower()

        # Timeout — always retry
        if "timeout" in error_type.lower() or "timeout" in error_msg:
            return True

        # Connection reset — retry
        if "reset" in error_msg or "broken pipe" in error_msg:
            return True

        # SSL handshake — retry once
        if "ssl" in error_msg and "handshake" in error_msg:
            return True

        # DNS NXDOMAIN — never retry (permanent)
        if "getaddrinfo" in error_msg or "nodename" in error_msg:
            return False

        # Generic connection error — retry
        if isinstance(error, aiohttp.ClientConnectorError):
            # But not DNS errors
            if "getaddrinfo" not in error_msg:
                return True

    return False


def compute_backoff_delay(attempt: int) -> float:
    """
    Compute exponential backoff delay with jitter.

    Formula: min(max_delay, base_delay * 2^attempt + random_jitter)
    """
    delay = min(
        RETRY_MAX_DELAY,
        RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5),
    )
    return delay


# ═══════════════════════════════════════════════════════════════════════════════
# 4. ENHANCED DNS RESOLVER
# ═══════════════════════════════════════════════════════════════════════════════

async def resolve_dns(hostname: str) -> dict[str, Any]:
    """
    Enhanced async DNS resolution using socket.getaddrinfo.

    Returns a dict with:
      resolved: bool
      latency_ms: float
      error_type: str | None  (NXDOMAIN, SERVFAIL, TIMEOUT, MISCONFIGURED)
      addresses: list[str]    (resolved IP addresses)
      has_ipv6: bool

    Uses the existing socket.getaddrinfo approach with better error
    classification (no aiodns dependency).
    """
    result: dict[str, Any] = {
        "resolved": False,
        "latency_ms": 0.0,
        "error_type": None,
        "addresses": [],
        "has_ipv6": False,
    }

    loop = asyncio.get_event_loop()
    start = time.monotonic()

    try:
        # Resolve IPv4 (A records)
        addrs = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, hostname, 443),
            timeout=5.0,
        )

        elapsed = (time.monotonic() - start) * 1000
        result["latency_ms"] = round(elapsed, 1)
        result["resolved"] = True

        # Collect unique addresses
        seen_addrs: set[str] = set()
        for family, _, _, _, sockaddr in addrs:
            addr = sockaddr[0]
            if addr not in seen_addrs:
                seen_addrs.add(addr)
                result["addresses"].append(addr)
                if family == socket.AF_INET6:
                    result["has_ipv6"] = True

    except asyncio.TimeoutError:
        result["latency_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error_type"] = "TIMEOUT"

    except socket.gaierror as e:
        result["latency_ms"] = round((time.monotonic() - start) * 1000, 1)
        error_code = getattr(e, "errno", None)
        error_msg = str(e).lower()

        if "name or service not known" in error_msg or "nodename nor servname" in error_msg:
            result["error_type"] = "NXDOMAIN"
        elif "temporary failure" in error_msg:
            result["error_type"] = "SERVFAIL"
        elif "no address" in error_msg:
            result["error_type"] = "NO_ADDRESS"
        else:
            result["error_type"] = "DNS_ERROR"

    except Exception as e:
        result["latency_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error_type"] = "DNS_ERROR"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 5. GLOBAL INSTANCES
# ═══════════════════════════════════════════════════════════════════════════════
# Singleton instances shared across the application lifecycle.

circuit_breaker = CircuitBreaker()
rate_limiter = AdaptiveRateLimiter()
