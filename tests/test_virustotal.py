import httpx
import pytest

from soc_copilot.enrich.cache import SqliteCache
from soc_copilot.enrich.rate_limit import DailyQuota, DailyQuotaExceeded, RateLimiter
from soc_copilot.enrich.virustotal import BASE_URL, VirusTotalClient, VirusTotalError

MALICIOUS_IP_RESPONSE = {
    "data": {
        "id": "185.220.101.47",
        "type": "ip_address",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 70,
                "malicious": 12,
                "suspicious": 2,
                "undetected": 5,
                "timeout": 0,
            },
            "country": "DE",
            "last_analysis_date": 1755000000,
        },
    }
}

MALICIOUS_FILE_RESPONSE = {
    "data": {
        "id": "a" * 64,
        "type": "file",
        "attributes": {
            "last_analysis_stats": {"malicious": 55, "suspicious": 1, "undetected": 10, "harmless": 0, "timeout": 0},
            "last_analysis_results": {
                "EngineA": {"category": "malicious", "result": "Trojan.Generic"},
                "EngineB": {"category": "malicious", "result": "Trojan.Generic"},  # duplicate name, should dedupe
                "EngineC": {"category": "malicious", "result": "Win32.Bad"},
                "EngineD": {"category": "undetected", "result": None},
            },
            "first_submission_date": 1650000000,
        },
    }
}


def _client_with_handler(handler, **kwargs):
    """Build a VirusTotalClient whose httpx.Client routes through `handler`
    instead of the real network."""
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(base_url=BASE_URL, transport=transport)
    tmp_path = kwargs.pop("tmp_path")  # always consumed, regardless of whether cache is also overridden below
    cache = kwargs.pop("cache", None) or SqliteCache(tmp_path / "cache.sqlite3")
    rate_limiter = kwargs.pop("rate_limiter", None) or RateLimiter(max_calls=100, period_seconds=1)
    quota = kwargs.pop("quota", None) or DailyQuota(cache, source="virustotal", max_per_day=1000)
    return VirusTotalClient(
        api_key="test-key",
        cache=cache,
        rate_limiter=rate_limiter,
        quota=quota,
        http_client=http_client,
        sleep_fn=lambda s: None,  # don't actually sleep in tests
        **kwargs,
    )


def test_get_ip_reputation_parses_malicious_response(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/ip_addresses/185.220.101.47"
        assert request.headers["x-apikey"] == "test-key"
        return httpx.Response(200, json=MALICIOUS_IP_RESPONSE)

    client = _client_with_handler(handler, tmp_path=tmp_path)
    result = client.get_ip_reputation("185.220.101.47")

    assert result.found is True
    assert result.malicious_votes == 12
    assert result.total_votes == 89  # sum of all stats
    assert result.country == "DE"
    assert result.raw == MALICIOUS_IP_RESPONSE


def test_get_ip_reputation_handles_404_as_not_found(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    client = _client_with_handler(handler, tmp_path=tmp_path)
    result = client.get_ip_reputation("1.2.3.4")

    assert result.found is False
    assert result.malicious_votes is None


def test_get_ip_reputation_uses_cache_on_second_call(tmp_path):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json=MALICIOUS_IP_RESPONSE)

    client = _client_with_handler(handler, tmp_path=tmp_path)
    client.get_ip_reputation("185.220.101.47")
    client.get_ip_reputation("185.220.101.47")

    assert call_count["n"] == 1  # second call served from cache, no HTTP request made


def test_get_file_reputation_parses_and_dedupes_detection_names(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/v3/files/{'a' * 64}"
        return httpx.Response(200, json=MALICIOUS_FILE_RESPONSE)

    client = _client_with_handler(handler, tmp_path=tmp_path)
    result = client.get_file_reputation("a" * 64)

    assert result.malicious_detections == 55
    assert result.total_engines == 66
    assert sorted(result.detection_names) == ["Trojan.Generic", "Win32.Bad"]  # deduped


def test_retries_on_5xx_then_succeeds(tmp_path):
    responses = iter([httpx.Response(503, text="temporarily unavailable"), httpx.Response(200, json=MALICIOUS_IP_RESPONSE)])

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    client = _client_with_handler(handler, tmp_path=tmp_path)
    result = client.get_ip_reputation("185.220.101.47")
    assert result.found is True


def test_raises_after_exhausting_retries_on_persistent_5xx(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="down")

    client = _client_with_handler(handler, tmp_path=tmp_path)
    with pytest.raises(VirusTotalError):
        client.get_ip_reputation("185.220.101.47")


def test_does_not_retry_on_401_unauthorized(tmp_path):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(401, text="bad api key")

    client = _client_with_handler(handler, tmp_path=tmp_path)
    with pytest.raises(VirusTotalError):
        client.get_ip_reputation("185.220.101.47")
    assert call_count["n"] == 1  # no retries wasted on a non-retryable error


def test_respects_daily_quota(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=MALICIOUS_IP_RESPONSE)

    cache = SqliteCache(tmp_path / "cache.sqlite3")
    quota = DailyQuota(cache, source="virustotal", max_per_day=1)
    client = _client_with_handler(handler, tmp_path=tmp_path, cache=cache, quota=quota)

    client.get_ip_reputation("1.1.1.1")
    with pytest.raises(DailyQuotaExceeded):
        client.get_ip_reputation("2.2.2.2")  # different IP -> not a cache hit, must consume quota
