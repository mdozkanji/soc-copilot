"""
AbuseIPDB API v2 client.

Free-tier limit: 1000 requests/day, no documented strict per-minute cap —
we still pass a conservative RateLimiter in from service.py rather than
firing requests as fast as Python allows, out of courtesy to a free service.

AbuseIPDB's /check endpoint returns HTTP 422 for a private/reserved/loopback
address rather than a normal result — one more reason the private-IP guard
lives in service.py *before* any client is called at all: it's not just
about saving quota, a private IP genuinely isn't a valid query for either
of these two APIs.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Optional

import httpx

from soc_copilot.enrich.cache import SqliteCache
from soc_copilot.enrich.models import IPReputation
from soc_copilot.enrich.rate_limit import DailyQuota, RateLimiter

BASE_URL = "https://api.abuseipdb.com/api/v2"

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_BACKOFF_BASE_SECONDS = 1.0


class AbuseIPDBError(RuntimeError):
    pass


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str,
        cache: SqliteCache,
        rate_limiter: RateLimiter,
        quota: DailyQuota,
        http_client: Optional[httpx.Client] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        cache_ttl_seconds: int = 24 * 60 * 60,
    ):
        self._cache = cache
        self._rate_limiter = rate_limiter
        self._quota = quota
        self._sleep_fn = sleep_fn
        self._cache_ttl_seconds = cache_ttl_seconds
        # See the matching comment in virustotal.py: sent per-request, not
        # as a client-level default, so it survives an injected http_client.
        self._api_key = api_key
        self._client = http_client or httpx.Client(base_url=BASE_URL, timeout=10.0)

    def get_ip_reputation(self, ip: str, max_age_days: int = 90) -> IPReputation:
        cache_key = f"abuseipdb:ip:{ip}:{max_age_days}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return IPReputation.model_validate(cached)

        response_json = self._get_checked(ip, max_age_days)
        data = response_json["data"]
        result = IPReputation(
            ip=ip,
            source="abuseipdb",
            found=True,  # AbuseIPDB always returns a record (score 0 for unknown-but-valid IPs)
            abuse_confidence_score=data.get("abuseConfidenceScore"),
            total_reports=data.get("totalReports"),
            is_tor=data.get("isTor"),
            country=data.get("countryCode"),
            last_seen=_parse_iso(data.get("lastReportedAt")),
            raw=response_json,
        )

        self._cache.set(cache_key, result.model_dump(mode="json"), ttl_seconds=self._cache_ttl_seconds)
        return result

    def _get_checked(self, ip: str, max_age_days: int) -> dict:
        last_exc: Optional[Exception] = None

        for attempt in range(_MAX_RETRIES):
            self._rate_limiter.acquire()
            self._quota.consume()
            try:
                resp = self._client.get(
                    "/check",
                    params={"ipAddress": ip, "maxAgeInDays": max_age_days},
                    headers={"Key": self._api_key, "Accept": "application/json"},
                )
            except httpx.TransportError as e:
                last_exc = e
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 422:
                # Malformed or non-routable-per-AbuseIPDB IP. service.py's
                # private-IP guard should normally prevent this, but a
                # client can be called directly (e.g. from a script or a
                # future tool), so we still fail with a clear message
                # rather than a raw stack trace from a KeyError below.
                raise AbuseIPDBError(f"AbuseIPDB rejected {ip!r} as invalid/non-routable: {resp.text[:300]}")
            if resp.status_code in _RETRYABLE_STATUS_CODES:
                last_exc = AbuseIPDBError(f"AbuseIPDB returned {resp.status_code} for {ip}")
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            raise AbuseIPDBError(f"AbuseIPDB returned {resp.status_code} for {ip}: {resp.text[:300]}")

        raise AbuseIPDBError(f"AbuseIPDB request for {ip} failed after {_MAX_RETRIES} attempts") from last_exc


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    return datetime.fromisoformat(value)
