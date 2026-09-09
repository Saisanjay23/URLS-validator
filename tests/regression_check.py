"""
Accuracy regression harness.

Runs every labeled URL in ``regression_urls.json`` through the real platform
checkers and compares the verdict to the known ground truth. Prints a per-platform
pass-rate table and lists every mismatch, so accuracy drift (a platform changing
its HTML/API) is caught early and pinpointed to the platform that broke.

Usage:
    python tests/regression_check.py                 # run the whole set
    python tests/regression_check.py facebook x      # only these platforms

Outcome buckets per URL:
    PASS  — verdict matched the label exactly.
    SOFT  — verdict was "uncertain" (honest fallback, not a wrong answer).
    FAIL  — verdict was the WRONG direction (dead reported active, or vice versa).
            These are the alarming ones; the process exits non-zero if any occur,
            so this can gate a scheduled/CI run.

Temporal confirmation is disabled during the run (each URL is observed once) —
we are testing the decision logic, not the confirmation window.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections import defaultdict

# Make the project root importable when run as `python tests/regression_check.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure standard async loop on Windows to allow subprocesses (needed by Playwright)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import aiohttp

from backend import config
config.ENABLE_TEMPORAL_CONFIRMATION = False  # observe each URL once for a clean signal

from backend.fast_checker import _check_single  # noqa: E402
from backend.url_utils import detect_platform     # noqa: E402

DATASET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "regression_urls.json")
CONCURRENCY = 5  # modest — high concurrency can itself trigger bot walls and skew results


def _load_cases(only: list[str]) -> list[tuple[str, str, str]]:
    """Return (platform, url, expected_status) tuples from the dataset."""
    with open(DATASET, encoding="utf-8") as f:
        data = json.load(f)
    cases: list[tuple[str, str, str]] = []
    for platform, buckets in data.items():
        if platform.startswith("_"):
            continue
        if only and platform not in only:
            continue
        for expected in ("active", "taken_down"):
            for url in buckets.get(expected, []):
                cases.append((platform, url, expected))
    return cases


async def _run_case(sem, session, platform, url, expected):
    async with sem:
        t0 = time.monotonic()
        try:
            # Trust the dataset's platform label, but fall back to detection if absent.
            plat = platform if platform != "generic" else detect_platform(url)
            res = await _check_single(session, url, plat)
            got = res.get("status", "error")
            reason = res.get("reason", "")
        except Exception as e:
            got, reason = "error", f"exception: {str(e)[:80]}"
        dt = time.monotonic() - t0

        if got == expected:
            bucket = "PASS"
        elif got == "uncertain":
            bucket = "SOFT"
        else:
            bucket = "FAIL"
        return platform, url, expected, got, bucket, reason, dt


async def main(only: list[str]):
    cases = _load_cases(only)
    if not cases:
        print("No cases to run (check platform filter / dataset).")
        return 0

    print(f"Running {len(cases)} labeled URLs "
          f"(temporal_confirmation=off, concurrency={CONCURRENCY})\n")

    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        results = await asyncio.gather(
            *(_run_case(sem, session, p, u, e) for p, u, e in cases)
        )

    # Per-platform tally
    tally: dict[str, dict[str, int]] = defaultdict(lambda: {"PASS": 0, "SOFT": 0, "FAIL": 0})
    failures = []
    softs = []
    for platform, url, expected, got, bucket, reason, dt in results:
        tally[platform][bucket] += 1
        if bucket == "FAIL":
            failures.append((platform, url, expected, got, reason))
        elif bucket == "SOFT":
            softs.append((platform, url, expected, reason))

    # Report
    print(f"{'platform':<12} {'total':>5} {'pass':>5} {'soft':>5} {'fail':>5}   pass-rate")
    print("-" * 56)
    tot = {"PASS": 0, "SOFT": 0, "FAIL": 0}
    for platform in sorted(tally):
        t = tally[platform]
        n = t["PASS"] + t["SOFT"] + t["FAIL"]
        for k in tot:
            tot[k] += t[k]
        rate = 100.0 * t["PASS"] / n if n else 0.0
        print(f"{platform:<12} {n:>5} {t['PASS']:>5} {t['SOFT']:>5} {t['FAIL']:>5}   {rate:5.0f}%")
    N = tot["PASS"] + tot["SOFT"] + tot["FAIL"]
    print("-" * 56)
    print(f"{'TOTAL':<12} {N:>5} {tot['PASS']:>5} {tot['SOFT']:>5} {tot['FAIL']:>5}   "
          f"{100.0 * tot['PASS'] / N:5.0f}%")

    if softs:
        print(f"\nSOFT ({len(softs)}) — returned 'uncertain' (not wrong, but couldn't confirm):")
        for platform, url, expected, reason in softs:
            print(f"  [{platform}] expected={expected}  {url}")
            print(f"      {reason[:100]}")

    if failures:
        print(f"\nFAIL ({len(failures)}) — WRONG DIRECTION, investigate:")
        for platform, url, expected, got, reason in failures:
            print(f"  [{platform}] expected={expected} got={got}  {url}")
            print(f"      {reason[:100]}")
        print("\n==> Hard failures present. A platform's signals likely drifted.")
        return 1

    print("\n==> No hard failures.")
    return 0


if __name__ == "__main__":
    only = [a.lower() for a in sys.argv[1:]]
    raise SystemExit(asyncio.run(main(only)))
