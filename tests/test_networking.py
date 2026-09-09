"""Per-host concurrency limiter tests."""
import asyncio, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.networking import AdaptiveRateLimiter  # noqa: E402


def test_acquire_release_is_symmetric_across_host_spellings():
    """
    acquire() normalises the host but release() used to look up the raw string,
    so the permit was never returned: after `limit` URLs on a host every later
    one blocked forever. Any spelling must release the slot it took.
    """
    async def run():
        rl = AdaptiveRateLimiter({"facebook.com": 2, "_default": 5})
        for host in ("www.facebook.com", "m.facebook.com", "facebook.com"):
            await rl.acquire(host)
            rl.release(host)
        # All permits returned: two more acquisitions must not block.
        await asyncio.wait_for(rl.acquire("www.facebook.com"), timeout=1)
        await asyncio.wait_for(rl.acquire("facebook.com"), timeout=1)
        rl.release("facebook.com"); rl.release("facebook.com")
    asyncio.run(run())


def test_limit_is_actually_enforced():
    async def run():
        rl = AdaptiveRateLimiter({"example.com": 2, "_default": 5})
        await rl.acquire("example.com")
        await rl.acquire("example.com")
        try:
            await asyncio.wait_for(rl.acquire("example.com"), timeout=0.25)
            raise AssertionError("third acquisition should have blocked at limit 2")
        except asyncio.TimeoutError:
            pass
        rl.release("example.com"); rl.release("example.com")
    asyncio.run(run())
