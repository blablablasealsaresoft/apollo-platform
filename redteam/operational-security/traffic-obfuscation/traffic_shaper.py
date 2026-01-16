#!/usr/bin/env python3
"""Proxy HTTP traffic with randomized timing and headers."""
from __future__ import annotations

import argparse
import random
import time

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1)",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6)",
]


def jitter_sleep(base: float = 1.5) -> None:
    jitter = random.uniform(-0.5, 0.8)
    time.sleep(max(0.2, base + jitter))


def proxy_request(url: str) -> tuple[int, float]:
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    start = time.perf_counter()
    with httpx.Client(timeout=10.0, headers=headers) as client:
        resp = client.get(url)
    duration = time.perf_counter() - start
    return resp.status_code, duration


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--count", type=int, default=5)
    args = parser.parse_args()

    for _ in range(args.count):
        status, duration = proxy_request(args.url)
        print(f"[traffic] status={status} duration={duration:.2f}s")
        jitter_sleep()


if __name__ == "__main__":
    main()
