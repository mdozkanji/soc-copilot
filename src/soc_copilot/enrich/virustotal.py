"""
VirusTotal API v3 client.

Free-tier limits as documented by VirusTotal: 4 requests/minute, 500
requests/day. This client is built assuming those limits — the rate
limiter and quota values are wired up in service.py's factory function,
not hardcoded here, so a paid-tier key can raise them without touching
this file.

The `http_client` parameter exists specifically so tests can inject an
httpx.MockTransport instead of hitting the real network — see
tests/test_virustotal.py. Nothing in this file assumes it's talking to the
real VirusTotal service.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable, Optional

import httpx

from soc_copilot.enrich.cache import SqliteCache
from soc_copilot.enrich.models import FileReputation, IPReputation
from soc_copilot.enrich.rate_limit import DailyQuota, RateLimiter

BASE_URL = "https://www.virustotal.com/api/v3"

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_BACKOFF_BASE_SECONDS = 1.0


class VirusTotalError(RuntimeError):
    pass


class VirusTotalClient:
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
        # The API key is sent explicitly per-request (not set as a
        # client-level default header) so it's never silently lost when a
        # caller injects their own httpx.Client -- which every test in this
        # project does. This was in fact caught as a real bug during Week 2
        # testing: the original version set headers only in the branch that
        # constructs its own client, so every mock-transport test silently
        # sent no API key at all. See the Week 2 devlog.
        self._api_key = api_key
        self._client = http_client or httpx.Client(base_url=BASE_URL, timeout=10.0)

    # ----------------------------------------------------------------
    # public API
    # ----------------------------------------------------------------

    def get_ip_reputation(self, ip: str) -> IPReputation:
        cache_key = f"virustotal:ip:{ip}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return IPReputation.model_validate(cached)

        response_json, found = self._get(f"/ip_addresses/{ip}")
        if not found:
            result = IPReputation(ip=ip, source="virustotal", found=False)
        else:
            attrs = response_json["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            # NOTE: VirusTotal's raw response also has a top-level key
            # literally called "total_votes" -- that's an unrelated field
            # (community up/down votes from VT users), not an AV-engine
            # count. Our IPReputation.total_votes is our own sum of
            # last_analysis_stats below; don't confuse the two if you're
            # ever reading response_json directly. Confirmed as a real,
            # easy-to-misread field collision during Week 2's live test.
            result = IPReputation(
                ip=ip,
                source="virustotal",
                found=True,
                malicious_votes=stats.get("malicious"),
                total_votes=sum(stats.values()) if stats else None,
                country=attrs.get("country"),
                last_seen=_epoch_to_datetime(attrs.get("last_analysis_date")),
                raw=response_json,
            )

        self._cache.set(cache_key, result.model_dump(mode="json"), ttl_seconds=self._cache_ttl_seconds)
        return result

    def get_file_reputation(self, sha256: str) -> FileReputation:
        cache_key = f"virustotal:hash:{sha256}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return FileReputation.model_validate(cached)

        response_json, found = self._get(f"/files/{sha256}")
        if not found:
            result = FileReputation(sha256=sha256, found=False)
        else:
            attrs = response_json["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            detection_names = [
                res["result"]
                for res in attrs.get("last_analysis_results", {}).values()
                if res.get("category") == "malicious" and res.get("result")
            ]
            result = FileReputation(
                sha256=sha256,
                found=True,
                malicious_detections=stats.get("malicious"),
                total_engines=sum(stats.values()) if stats else None,
                detection_names=sorted(set(detection_names))[:10],  # cap: this is context, not a full report
                first_submission_date=_epoch_to_datetime(attrs.get("first_submission_date")),
                raw=response_json,
            )

        self._cache.set(cache_key, result.model_dump(mode="json"), ttl_seconds=self._cache_ttl_seconds)
        return result

    # ----------------------------------------------------------------
    # internals
    # ----------------------------------------------------------------

    def _get(self, path: str) -> tuple[dict, bool]:
        """Returns (response_json, found). `found=False` means a clean 404
        (VirusTotal has no record of this entity) — a legitimate, useful
        answer, not an error. Anything else non-2xx after retries raises."""
        last_exc: Optional[Exception] = None

        for attempt in range(_MAX_RETRIES):
            self._rate_limiter.acquire()
            self._quota.consume()
            try:
                resp = self._client.get(path, headers={"x-apikey": self._api_key})
            except httpx.TransportError as e:
                last_exc = e
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            if resp.status_code == 200:
                return resp.json(), True
            if resp.status_code == 404:
                return {}, False
            if resp.status_code in _RETRYABLE_STATUS_CODES:
                last_exc = VirusTotalError(f"VirusTotal returned {resp.status_code} for {path}")
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            # Non-retryable client error (401 bad key, 400 malformed request, etc).
            raise VirusTotalError(f"VirusTotal returned {resp.status_code} for {path}: {resp.text[:300]}")

        raise VirusTotalError(f"VirusTotal request to {path} failed after {_MAX_RETRIES} attempts") from last_exc


def _epoch_to_datetime(epoch_seconds: Optional[int]) -> Optional[datetime]:
    if epoch_seconds is None:
        return None
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
