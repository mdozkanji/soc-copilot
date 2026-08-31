"""
Two separate concerns, deliberately kept as two separate classes:

- RateLimiter: a short-timescale sliding window (e.g. VirusTotal's free
  tier: 4 requests/minute). Enforced in-process, resets naturally, doesn't
  need to survive a restart.
- DailyQuota: a long-timescale budget (e.g. VirusTotal's free tier: 500
  requests/day; AbuseIPDB: 1000/day). This DOES need to survive a restart —
  if the process crashes and restarts, we must not forget we already used
  480 of today's 500 VT calls — so it's persisted via the same SqliteCache
  used for response caching, under a namespaced key.

Both take injectable time/sleep functions so tests can run instantly
instead of actually sleeping or waiting for a day to roll over.
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

from soc_copilot.enrich.cache import SqliteCache


class RateLimiter:
    """At most `max_calls` calls within any rolling `period_seconds` window."""

    def __init__(
        self,
        max_calls: int,
        period_seconds: float,
        time_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self._max_calls = max_calls
        self._period = period_seconds
        self._time_fn = time_fn
        self._sleep_fn = sleep_fn
        self._call_times: deque[float] = deque()

    def acquire(self) -> None:
        self._evict_old()
        if len(self._call_times) >= self._max_calls:
            wait = self._period - (self._time_fn() - self._call_times[0])
            if wait > 0:
                self._sleep_fn(wait)
            self._evict_old()
        self._call_times.append(self._time_fn())

    def _evict_old(self) -> None:
        now = self._time_fn()
        while self._call_times and now - self._call_times[0] >= self._period:
            self._call_times.popleft()


class DailyQuotaExceeded(RuntimeError):
    pass


class DailyQuota:
    """Persisted per-source, per-UTC-day call budget."""

    def __init__(
        self,
        cache: SqliteCache,
        source: str,
        max_per_day: int,
        now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._cache = cache
        self._source = source
        self._max_per_day = max_per_day
        self._now_fn = now_fn

    def _key(self) -> str:
        today = self._now_fn().date().isoformat()
        return f"quota:{self._source}:{today}"

    def _seconds_until_midnight_utc(self) -> int:
        now = self._now_fn()
        end_of_day = now.replace(hour=23, minute=59, second=59, microsecond=999_999)
        return max(1, int((end_of_day - now).total_seconds()) + 1)

    def remaining(self) -> int:
        record = self._cache.get(self._key()) or {"count": 0}
        return max(0, self._max_per_day - record["count"])

    def consume(self) -> None:
        key = self._key()
        record = self._cache.get(key) or {"count": 0}
        if record["count"] >= self._max_per_day:
            raise DailyQuotaExceeded(
                f"{self._source}: daily quota of {self._max_per_day} requests exhausted for {self._now_fn().date()}"
            )
        record["count"] += 1
        self._cache.set(key, record, ttl_seconds=self._seconds_until_midnight_utc())
