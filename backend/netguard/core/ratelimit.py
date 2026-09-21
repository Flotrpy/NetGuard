"""Sliding-window in-process rate limiter.

State is per-process. Behind multiple API replicas each replica enforces its own budget, which
is a documented limitation; put a shared limiter (e.g. at the reverse proxy) in front for strict
global limits.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[key]
            cutoff = now - self.window
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                retry = int(max(1, hits[0] + self.window - now))
                return False, retry
            hits.append(now)
            if len(self._hits) > 50_000:  # bound memory under key-spraying
                self._evict(cutoff)
            return True, 0

    def _evict(self, cutoff: float) -> None:
        for k in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
