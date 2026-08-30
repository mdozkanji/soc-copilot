"""
Per-source normalizers.

This is the deliberately unglamorous, load-bearing part of the pipeline:
every upstream tool names and shapes its fields differently (a "level"
string vs. a numeric "severity_score", "user" vs. "username", nested vs.
flat network fields...). Every later stage of this project — correlation,
enrichment, the agent — depends on these functions being correct, because
they're the only place that ever looks at a raw vendor format again.

Adding a new source means adding one function here (plus tests) and a new
AlertSource enum value in schema.py. Nothing else in the codebase should
ever need to know that a source-specific field was called "severity_score"
instead of "level".
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from soc_copilot.ingest.schema import Alert, AlertSource, Severity

# --------------------------------------------------------------------------
# sigma_synthetic: a generic SIEM-style alert export
# --------------------------------------------------------------------------

_SIGMA_LEVEL_MAP: dict[str, Severity] = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def normalize_sigma_synthetic(raw: dict[str, Any]) -> Alert:
    """Normalize one raw record from the sigma_synthetic sample source."""
    level = raw.get("level")
    if level not in _SIGMA_LEVEL_MAP:
        raise ValueError(f"Unknown sigma_synthetic level: {level!r} (record id={raw.get('id')})")

    return Alert(
        source=AlertSource.SIGMA_SYNTHETIC,
        source_alert_id=raw["id"],
        rule_name=raw["rule"],
        occurred_at=_parse_time(raw["time"]),
        severity=_SIGMA_LEVEL_MAP[level],
        description=raw["message"],
        src_ip=raw.get("src_ip"),
        dst_ip=raw.get("dst_ip"),
        dst_port=raw.get("dest_port"),
        user=_strip_domain(raw.get("user")),
        host=raw.get("computer"),
        mitre_technique_hint=raw.get("mitre"),
        raw=raw,
    )


# --------------------------------------------------------------------------
# edr_synthetic: an EDR-style process/network detection export
# --------------------------------------------------------------------------


def _edr_score_to_severity(score: int) -> Severity:
    """EDR tools frequently report a numeric severity instead of a level
    string. The exact cutoffs are a judgment call — document them here so
    they can be revisited once we have real triage feedback data (Week 7)
    instead of leaving the mapping implicit and unexplained."""
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 5:
        return Severity.MEDIUM
    if score >= 3:
        return Severity.LOW
    return Severity.INFORMATIONAL


def normalize_edr_synthetic(raw: dict[str, Any]) -> Alert:
    """Normalize one raw record from the edr_synthetic sample source."""
    network = raw.get("network") or {}

    return Alert(
        source=AlertSource.EDR_SYNTHETIC,
        source_alert_id=raw["event_id"],
        rule_name=raw["detection_name"],
        occurred_at=_parse_time(raw["timestamp"]),
        severity=_edr_score_to_severity(raw["severity_score"]),
        description=raw["summary"],
        dst_ip=network.get("remote_ip"),
        dst_port=network.get("remote_port"),
        user=raw.get("username"),
        host=raw.get("endpoint"),
        process_name=raw.get("process"),
        command_line=raw.get("cmdline"),
        file_hash_sha256=raw.get("sha256"),
        raw=raw,
    )


# --------------------------------------------------------------------------
# dispatch + shared helpers
# --------------------------------------------------------------------------

_NORMALIZERS = {
    AlertSource.SIGMA_SYNTHETIC: normalize_sigma_synthetic,
    AlertSource.EDR_SYNTHETIC: normalize_edr_synthetic,
}


def normalize(raw: dict[str, Any], source: AlertSource) -> Alert:
    """Dispatch to the right per-source normalizer."""
    try:
        fn = _NORMALIZERS[source]
    except KeyError as e:
        raise NotImplementedError(f"No normalizer registered for source={source!r}") from e
    return fn(raw)


def _parse_time(value: str) -> datetime:
    # Sample data uses Zulu-suffixed ISO 8601 ("...Z"); Python's fromisoformat
    # doesn't accept a bare "Z" before 3.11, so normalize it explicitly
    # rather than assuming every future source will format timestamps the
    # same way.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _strip_domain(user: str | None) -> str | None:
    """"CORP\\jsmith" -> "jsmith". Real IdPs vary wildly here (UPN vs
    down-level logon name vs bare username) — keeping this as an explicit,
    single-purpose helper makes it obvious where to extend when a second
    identity format shows up."""
    if user is None:
        return None
    return user.split("\\")[-1]
