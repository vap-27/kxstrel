"""In-memory sliding-window rate limiter (per key, e.g. client IP).

Single-process, dependency-free. Render runs this service with one worker,
so in-memory state is sufficient; limits are a safety net, not a billing
control.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._hits: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        window = 60.0
        async with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= self.per_minute:
                retry_after = window - (now - bucket[0])
                return False, max(0.0, retry_after)
            bucket.append(now)
            # Opportunistic cleanup to bound memory.
            if len(self._hits) > 10000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < window}
            return True, 0.0
