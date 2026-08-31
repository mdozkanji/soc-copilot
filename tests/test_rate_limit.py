from datetime import datetime, timezone

import pytest

from soc_copilot.enrich.cache import SqliteCache
from soc_copilot.enrich.rate_limit import DailyQuota, DailyQuotaExceeded, RateLimiter


class FakeClock:
    """Controllable time source so rate-limit tests run instantly instead
    of actually sleeping."""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_rate_limiter_allows_calls_under_the_limit():
    clock = FakeClock()
    limiter = RateLimiter(max_calls=3, period_seconds=10, time_fn=clock.time, sleep_fn=clock.sleep)
    for _ in range(3):
        limiter.acquire()
    assert clock.sleeps == []  # never had to wait


def test_rate_limiter_blocks_and_waits_once_limit_is_hit():
    clock = FakeClock()
    limiter = RateLimiter(max_calls=2, period_seconds=10, time_fn=clock.time, sleep_fn=clock.sleep)
    limiter.acquire()
    limiter.acquire()
    limiter.acquire()  # 3rd call within the window should force a wait
    assert clock.sleeps == [10.0]


def test_rate_limiter_does_not_wait_once_window_has_rolled_over():
    clock = FakeClock()
    limiter = RateLimiter(max_calls=1, period_seconds=10, time_fn=clock.time, sleep_fn=clock.sleep)
    limiter.acquire()
    clock.now += 11  # window has fully elapsed
    limiter.acquire()
    assert clock.sleeps == []


def test_daily_quota_allows_up_to_max_then_raises(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    fixed_now = lambda: datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    quota = DailyQuota(cache, source="testsource", max_per_day=3, now_fn=fixed_now)

    quota.consume()
    quota.consume()
    quota.consume()
    with pytest.raises(DailyQuotaExceeded, match="testsource"):
        quota.consume()


def test_daily_quota_remaining_reflects_consumption(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    fixed_now = lambda: datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    quota = DailyQuota(cache, source="testsource", max_per_day=5, now_fn=fixed_now)

    assert quota.remaining() == 5
    quota.consume()
    quota.consume()
    assert quota.remaining() == 3


def test_daily_quota_resets_on_a_new_utc_day(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    day1 = lambda: datetime(2026, 8, 30, 23, 59, 0, tzinfo=timezone.utc)
    day2 = lambda: datetime(2026, 8, 31, 0, 1, 0, tzinfo=timezone.utc)

    quota_day1 = DailyQuota(cache, source="testsource", max_per_day=1, now_fn=day1)
    quota_day1.consume()
    with pytest.raises(DailyQuotaExceeded):
        quota_day1.consume()

    # same source, same cache, but a new day -- budget should be fresh
    quota_day2 = DailyQuota(cache, source="testsource", max_per_day=1, now_fn=day2)
    quota_day2.consume()  # should not raise


def test_daily_quota_is_per_source(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    fixed_now = lambda: datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    vt_quota = DailyQuota(cache, source="virustotal", max_per_day=1, now_fn=fixed_now)
    abuse_quota = DailyQuota(cache, source="abuseipdb", max_per_day=1, now_fn=fixed_now)

    vt_quota.consume()
    with pytest.raises(DailyQuotaExceeded):
        vt_quota.consume()

    abuse_quota.consume()  # separate budget, should not raise
