import pytest

from soc_copilot.enrich.models import IPReputation
from soc_copilot.enrich.service import EnrichmentService, _non_routable_reason


# --------------------------------------------------------------------------
# private/non-routable IP guard
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip",
    [
        "10.20.4.55",       # RFC1918
        "172.16.0.1",       # RFC1918
        "192.168.1.1",      # RFC1918
        "127.0.0.1",        # loopback
        "169.254.1.1",      # link-local
        "224.0.0.1",        # multicast
    ],
)
def test_non_routable_reason_flags_internal_addresses(ip):
    assert _non_routable_reason(ip) is not None


@pytest.mark.parametrize("ip", ["8.8.8.8", "185.220.101.47", "1.1.1.1"])
def test_non_routable_reason_allows_public_addresses(ip):
    assert _non_routable_reason(ip) is None


def test_non_routable_reason_flags_garbage_input():
    assert _non_routable_reason("not-an-ip") is not None


def test_enrich_ip_skips_private_ip_without_calling_any_source():
    calls = {"n": 0}

    class ExplodingClient:
        def get_ip_reputation(self, ip):
            calls["n"] += 1
            raise AssertionError("should never be called for a private IP")

    service = EnrichmentService(virustotal=ExplodingClient(), abuseipdb=ExplodingClient())
    result = service.enrich_ip("10.20.4.55")

    assert result.skipped is True
    assert "private" in result.skip_reason
    assert calls["n"] == 0


# --------------------------------------------------------------------------
# multi-source aggregation + graceful degradation
# --------------------------------------------------------------------------

class StubClient:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def get_ip_reputation(self, ip):
        if self._error:
            raise self._error
        return self._result


def test_enrich_ip_merges_both_sources_when_both_succeed():
    vt_result = IPReputation(ip="1.2.3.4", source="virustotal", found=True, malicious_votes=12, total_votes=89)
    abuse_result = IPReputation(ip="1.2.3.4", source="abuseipdb", found=True, abuse_confidence_score=90)

    service = EnrichmentService(virustotal=StubClient(vt_result), abuseipdb=StubClient(abuse_result))
    result = service.enrich_ip("1.2.3.4")

    assert len(result.sources) == 2
    assert result.source_errors == {}
    assert result.likely_malicious_heuristic is True


def test_enrich_ip_degrades_gracefully_when_one_source_fails():
    vt_result = IPReputation(ip="1.2.3.4", source="virustotal", found=True, malicious_votes=0, total_votes=89)

    service = EnrichmentService(
        virustotal=StubClient(vt_result),
        abuseipdb=StubClient(error=RuntimeError("AbuseIPDB is down")),
    )
    result = service.enrich_ip("1.2.3.4")

    assert len(result.sources) == 1
    assert result.sources[0].source == "virustotal"
    assert "abuseipdb" in result.source_errors
    assert "AbuseIPDB is down" in result.source_errors["abuseipdb"]


def test_enrich_ip_returns_none_heuristic_when_no_sources_configured():
    service = EnrichmentService()  # neither client configured
    result = service.enrich_ip("1.2.3.4")
    assert result.sources == []
    assert result.likely_malicious_heuristic is None


def test_enrich_ip_heuristic_false_when_checked_and_clean():
    clean = IPReputation(ip="8.8.8.8", source="virustotal", found=True, malicious_votes=0, total_votes=89)
    service = EnrichmentService(virustotal=StubClient(clean))
    result = service.enrich_ip("8.8.8.8")
    assert result.likely_malicious_heuristic is False  # "checked, looks clean" != "unknown"


def test_enrich_ip_heuristic_none_when_source_found_no_data():
    not_found = IPReputation(ip="203.0.113.5", source="virustotal", found=False)
    service = EnrichmentService(virustotal=StubClient(not_found))
    result = service.enrich_ip("203.0.113.5")
    assert result.likely_malicious_heuristic is None  # genuinely unknown, not "confirmed clean"


def test_enrich_hash_requires_virustotal():
    service = EnrichmentService(virustotal=None)
    with pytest.raises(RuntimeError, match="VT_API_KEY"):
        service.enrich_hash("a" * 64)
