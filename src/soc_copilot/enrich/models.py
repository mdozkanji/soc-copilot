"""
Normalized enrichment results.

The agent (Week 4 onward) should never have to know that VirusTotal calls
its detection breakdown "last_analysis_stats" or that AbuseIPDB calls its
score "abuseConfidenceScore". Every client in this package translates the
vendor's raw response into one of these models. `raw` is always kept
alongside, same principle as Alert.raw in Week 1 — nothing is thrown away,
it's just not what downstream code is expected to read.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class IPReputation(BaseModel):
    """One source's opinion about one IP address."""

    ip: str
    source: str  # "virustotal" | "abuseipdb"
    found: bool  # False = source has no data on this IP (not the same as "confirmed clean")

    # VirusTotal-flavored fields (None if source != virustotal or not found)
    malicious_votes: Optional[int] = None
    total_votes: Optional[int] = None

    # AbuseIPDB-flavored fields (None if source != abuseipdb or not found)
    abuse_confidence_score: Optional[int] = None  # 0-100
    total_reports: Optional[int] = None
    is_tor: Optional[bool] = None

    country: Optional[str] = None
    last_seen: Optional[datetime] = None

    raw: dict[str, Any] = Field(default_factory=dict)


class FileReputation(BaseModel):
    """VirusTotal's opinion about one file hash. AbuseIPDB has no file-hash
    lookup, so this is always a virustotal-sourced result — kept as its own
    model rather than folded into IPReputation because the two entity types
    share almost no fields and forcing them into one model would just mean
    a pile of always-None fields either way."""

    sha256: str
    source: str = "virustotal"
    found: bool

    malicious_detections: Optional[int] = None
    total_engines: Optional[int] = None
    detection_names: list[str] = Field(default_factory=list)
    first_submission_date: Optional[datetime] = None

    raw: dict[str, Any] = Field(default_factory=dict)


class IPEnrichment(BaseModel):
    """The aggregated view across every source we queried for one IP —
    this, not IPReputation, is what the enrichment service and (later) the
    agent's enrich_ip tool actually return."""

    ip: str
    skipped: bool = False
    skip_reason: Optional[str] = None

    sources: list[IPReputation] = Field(default_factory=list)
    source_errors: dict[str, str] = Field(default_factory=dict)

    # Deliberately naive placeholder — see service.py docstring. This
    # exists so the agent has *something* structured to reason over in
    # Week 4, not because a fixed threshold is a good final triage rule.
    likely_malicious_heuristic: Optional[bool] = None
