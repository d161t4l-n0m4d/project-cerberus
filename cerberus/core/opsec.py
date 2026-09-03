"""OPSEC / stealth helpers shared across plugins and C2."""

from __future__ import annotations

import asyncio
import random
from typing import Any


STEALTH_PROFILES = {
    "noisy": {
        "nmap_timing": "-T4",
        "threads": 40,
        "delay_ms": 0,
        "jitter_pct": 0.1,
        "user_agent": "Mozilla/5.0 (compatible; Nmap)",
        "max_parallel": 8,
        "block_dangerous": False,
    },
    "balanced": {
        "nmap_timing": "-T3",
        "threads": 15,
        "delay_ms": 50,
        "jitter_pct": 0.3,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "max_parallel": 4,
        "block_dangerous": False,
    },
    "ninja": {
        "nmap_timing": "-T2",
        "threads": 3,
        "delay_ms": 300,
        "jitter_pct": 0.6,
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "max_parallel": 1,
        "block_dangerous": True,
    },
}


def profile(stealth: str) -> dict[str, Any]:
    return STEALTH_PROFILES.get(stealth, STEALTH_PROFILES["balanced"]).copy()


async def human_delay(stealth: str, base_ms: int | None = None) -> None:
    """Sleep with jitter according to stealth profile."""
    p = profile(stealth)
    base = base_ms if base_ms is not None else int(p["delay_ms"])
    if base <= 0:
        return
    jitter = int(base * float(p["jitter_pct"]))
    ms = base + random.randint(-jitter, jitter) if jitter else base
    ms = max(0, ms)
    await asyncio.sleep(ms / 1000.0)


def allow_opsec(stealth: str, level: str) -> bool:
    """Return False if ninja profile should block dangerous actions."""
    p = profile(stealth)
    if p.get("block_dangerous") and level in ("dangerous", "high"):
        return False
    return True


# Rotating UA pool for web probes
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


def random_ua() -> str:
    return random.choice(USER_AGENTS)
