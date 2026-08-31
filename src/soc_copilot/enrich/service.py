"""
The enrichment service is the only thing the rest of the codebase (and
later, the agent's tools) should talk to -- never the VirusTotal/AbuseIPDB
clients directly. It's responsible for three things neither client should
have to know about:

1. Refusing to query external threat intel about internal/private
   addresses. Roughly half of this project's own sample alerts have
   RFC1918 IPs (10.x, the corp network) as their destination -- querying
   VirusTotal or AbuseIPDB about 10.20.4.90 is meaningless (they have no
   data on your internal network) and, for AbuseIPDB specifically, the API
   will actively reject it with a 422. Context about an internal IP has to
   come from an asset inventory instead -- that's the get_asset_context tool
   planned for Week 4, not this module.
2. Querying multiple sources for the same IP and merging the results into
   one IPEnrichment, without letting one source's failure (rate limit,
   network error, bad key) take down the whole lookup.
3. Producing a first-pass, clearly-labeled-as-naive "likely malicious"
   heuristic. This is intentionally crude (fixed thresholds, no learning)
   -- its only job is to give the Week 4 agent something structured to
   reason over and potentially override, not to be the actual triage
   decision. Treat any change to these thresholds as a product decision to
   revisit once Week 7's analyst-override log gives us real signal on
   whether they're too sensitive or not sensitive enough.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Optional

from soc_copilot.enrich.abuseipdb import AbuseIPDBClient
from soc_copilot.enrich.cache import SqliteCache
from soc_copilot.enrich.models import FileReputation, IPEnrichment
from soc_copilot.enrich.rate_limit import DailyQuota, RateLimiter
from soc_copilot.enrich.virustotal import VirusTotalClient

_VT_RATE_LIMIT = (4, 60.0)
_VT_DAILY_QUOTA = 500
_ABUSEIPDB_RATE_LIMIT = (30, 60.0)
_ABUSEIPDB_DAILY_QUOTA = 1000

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CACHE_PATH = REPO_ROOT / "data" / "enrichment_cache.sqlite3"


class EnrichmentService:
    def __init__(
        self,
        virustotal: Optional[VirusTotalClient] = None,
        abuseipdb: Optional[AbuseIPDBClient] = None,
    ):
        self._vt = virustotal
        self._abuseipdb = abuseipdb

    @classmethod
    def from_env(cls, cache_path: Path = DEFAULT_CACHE_PATH) -> "EnrichmentService":
        cache = SqliteCache(cache_path)

        vt_key = os.environ.get("VT_API_KEY")
        vt = None
        if vt_key:
            vt = VirusTotalClient(
                api_key=vt_key,
                cache=cache,
                rate_limiter=RateLimiter(*_VT_RATE_LIMIT),
                quota=DailyQuota(cache, source="virustotal", max_per_day=_VT_DAILY_QUOTA),
            )

        abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
        abuseipdb = None
        if abuseipdb_key:
            abuseipdb = AbuseIPDBClient(
                api_key=abuseipdb_key,
                cache=cache,
                rate_limiter=RateLimiter(*_ABUSEIPDB_RATE_LIMIT),
                quota=DailyQuota(cache, source="abuseipdb", max_per_day=_ABUSEIPDB_DAILY_QUOTA),
            )

        if vt is None and abuseipdb is None:
            raise RuntimeError(
                "Neither VT_API_KEY nor ABUSEIPDB_API_KEY is set. "
                "Set at least one (see .env.example) before running live enrichment."
            )
        return cls(virustotal=vt, abuseipdb=abuseipdb)

    def enrich_ip(self, ip: str) -> IPEnrichment:
        skip_reason = _non_routable_reason(ip)
        if skip_reason is not None:
            return IPEnrichment(ip=ip, skipped=True, skip_reason=skip_reason)

        sources = []
        errors: dict[str, str] = {}

        if self._vt is not None:
            try:
                sources.append(self._vt.get_ip_reputation(ip))
            except Exception as e:  # noqa: BLE001
                errors["virustotal"] = str(e)

        if self._abuseipdb is not None:
            try:
                sources.append(self._abuseipdb.get_ip_reputation(ip))
            except Exception as e:  # noqa: BLE001
                errors["abuseipdb"] = str(e)

        return IPEnrichment(
            ip=ip,
            sources=sources,
            source_errors=errors,
            likely_malicious_heuristic=_naive_malicious_heuristic(sources),
        )

    def enrich_hash(self, sha256: str) -> FileReputation:
        if self._vt is None:
            raise RuntimeError("No VirusTotal client configured; file-hash enrichment requires VT_API_KEY.")
        return self._vt.get_file_reputation(sha256)


def _non_routable_reason(ip: str) -> Optional[str]:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return f"'{ip}' is not a valid IP address"

    if parsed.is_private:
        return "private (RFC1918/RFC4193) address -- internal network, not queryable against external threat intel"
    if parsed.is_loopback:
        return "loopback address"
    if parsed.is_link_local:
        return "link-local address"
    if parsed.is_reserved:
        return "reserved address range"
    if parsed.is_multicast:
        return "multicast address"
    return None


def _naive_malicious_heuristic(sources: list) -> Optional[bool]:
    if not sources:
        return None

    for s in sources:
        if s.source == "virustotal" and s.found:
            if s.total_votes and s.malicious_votes is not None and s.total_votes > 0:
                if s.malicious_votes / s.total_votes > 0.05 or s.malicious_votes >= 3:
                    return True
        if s.source == "abuseipdb" and s.found:
            if (s.abuse_confidence_score or 0) >= 50:
                return True

    if any(s.found for s in sources):
        return False
    return None
