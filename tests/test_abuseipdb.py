import httpx
import pytest

from soc_copilot.enrich.abuseipdb import BASE_URL, AbuseIPDBClient, AbuseIPDBError
from soc_copilot.enrich.cache import SqliteCache
from soc_copilot.enrich.rate_limit import DailyQuota, RateLimiter

MALICIOUS_RESPONSE = {
    "data": {
        "ipAddress": "185.220.101.47",
        "isPublic": True,
        "abuseConfidenceScore": 100,
        "countryCode": "DE",
        "totalReports": 543,
        "isTor": True,
        "lastReportedAt": "2026-08-20T10:00:00+00:00",
    }
}

CLEAN_RESPONSE = {
    "data": {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "totalReports": 0,
        "isTor": False,
        "lastReportedAt": None,
    }
}


def _client_with_handler(handler, tmp_path, **kwargs):
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(base_url=BASE_URL, transport=transport)
    cache = kwargs.pop("cache", None) or SqliteCache(tmp_path / "cache.sqlite3")
    rate_limiter = kwargs.pop("rate_limiter", None) or RateLimiter(max_calls=100, period_seconds=1)
    quota = kwargs.pop("quota", None) or DailyQuota(cache, source="abuseipdb", max_per_day=1000)
    return AbuseIPDBClient(
        api_key="test-key",
        cache=cache,
        rate_limiter=rate_limiter,
        quota=quota,
        http_client=http_client,
        sleep_fn=lambda s: None,
        **kwargs,
    )


def test_get_ip_reputation_parses_malicious_response(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/check"
        assert request.url.params["ipAddress"] == "185.220.101.47"
        assert request.headers["Key"] == "test-key"
        return httpx.Response(200, json=MALICIOUS_RESPONSE)

    client = _client_with_handler(handler, tmp_path)
    result = client.get_ip_reputation("185.220.101.47")

    assert result.abuse_confidence_score == 100
    assert result.total_reports == 543
    assert result.is_tor is True
    assert result.country == "DE"


def test_get_ip_reputation_parses_clean_response(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=CLEAN_RESPONSE)

    client = _client_with_handler(handler, tmp_path)
    result = client.get_ip_reputation("8.8.8.8")

    assert result.abuse_confidence_score == 0
    assert result.found is True  # AbuseIPDB always returns a record, unlike VT's 404 case
    assert result.last_seen is None


def test_get_ip_reputation_raises_clear_error_on_422(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"errors": [{"detail": "not routable"}]})

    client = _client_with_handler(handler, tmp_path)
    with pytest.raises(AbuseIPDBError, match="rejected"):
        client.get_ip_reputation("10.0.0.1")


def test_uses_cache_on_second_call(tmp_path):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json=MALICIOUS_RESPONSE)

    client = _client_with_handler(handler, tmp_path)
    client.get_ip_reputation("185.220.101.47")
    client.get_ip_reputation("185.220.101.47")
    assert call_count["n"] == 1


def test_retries_on_429_then_succeeds(tmp_path):
    responses = iter([httpx.Response(429, text="rate limited"), httpx.Response(200, json=MALICIOUS_RESPONSE)])

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    client = _client_with_handler(handler, tmp_path)
    result = client.get_ip_reputation("185.220.101.47")
    assert result.abuse_confidence_score == 100
