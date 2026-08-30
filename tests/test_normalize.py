import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from soc_copilot.ingest.load_samples import RAW_DIR, load_all
from soc_copilot.ingest.normalize import normalize, normalize_edr_synthetic, normalize_sigma_synthetic
from soc_copilot.ingest.schema import Alert, AlertSource, Severity


# --------------------------------------------------------------------------
# sigma_synthetic normalizer
# --------------------------------------------------------------------------

def test_normalize_sigma_synthetic_maps_core_fields():
    raw = {
        "id": "sig-9999",
        "rule": "Test Rule",
        "time": "2026-08-20T14:03:11Z",
        "level": "high",
        "message": "A test alert.",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dest_port": 443,
        "user": "CORP\\jsmith",
        "computer": "WKS-01",
        "mitre": "T1059.001",
    }
    alert = normalize_sigma_synthetic(raw)

    assert alert.source == AlertSource.SIGMA_SYNTHETIC
    assert alert.source_alert_id == "sig-9999"
    assert alert.severity == Severity.HIGH
    assert alert.user == "jsmith"  # domain prefix stripped
    assert alert.host == "WKS-01"
    assert alert.mitre_technique_hint == "T1059.001"
    assert alert.raw == raw  # original record preserved untouched


def test_normalize_sigma_synthetic_rejects_unknown_level():
    raw = {
        "id": "sig-bad",
        "rule": "Test Rule",
        "time": "2026-08-20T14:03:11Z",
        "level": "extremely-bad",  # not a real level
        "message": "A test alert.",
    }
    with pytest.raises(ValueError, match="Unknown sigma_synthetic level"):
        normalize_sigma_synthetic(raw)


def test_normalize_sigma_synthetic_handles_missing_optional_fields():
    raw = {
        "id": "sig-minimal",
        "rule": "Minimal Rule",
        "time": "2026-08-20T14:03:11Z",
        "level": "informational",
        "message": "Minimal alert with no entities.",
    }
    alert = normalize_sigma_synthetic(raw)
    assert alert.src_ip is None
    assert alert.user is None
    assert alert.host is None


# --------------------------------------------------------------------------
# edr_synthetic normalizer
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected",
    [
        (10, Severity.CRITICAL),
        (9, Severity.CRITICAL),
        (8, Severity.HIGH),
        (7, Severity.HIGH),
        (6, Severity.MEDIUM),
        (5, Severity.MEDIUM),
        (4, Severity.LOW),
        (3, Severity.LOW),
        (2, Severity.INFORMATIONAL),
        (0, Severity.INFORMATIONAL),
    ],
)
def test_edr_severity_score_mapping(score, expected):
    raw = {
        "event_id": "edr-test",
        "detection_name": "Test Detection",
        "timestamp": "2026-08-20T14:03:11Z",
        "severity_score": score,
        "summary": "A test detection.",
        "endpoint": "WKS-01",
        "username": "jsmith",
        "process": "test.exe",
        "cmdline": "test.exe",
        "sha256": "a" * 64,
        "network": {"remote_ip": None, "remote_port": None},
    }
    alert = normalize_edr_synthetic(raw)
    assert alert.severity == expected


def test_normalize_edr_synthetic_flattens_nested_network_field():
    raw = {
        "event_id": "edr-net",
        "detection_name": "Test Detection",
        "timestamp": "2026-08-20T14:03:11Z",
        "severity_score": 9,
        "summary": "A test detection.",
        "endpoint": "WKS-01",
        "username": "jsmith",
        "process": "test.exe",
        "cmdline": "test.exe",
        "sha256": "a" * 64,
        "network": {"remote_ip": "1.2.3.4", "remote_port": 4444},
    }
    alert = normalize_edr_synthetic(raw)
    assert alert.dst_ip == "1.2.3.4"
    assert alert.dst_port == 4444


def test_normalize_edr_synthetic_handles_missing_network_block():
    raw = {
        "event_id": "edr-no-net",
        "detection_name": "Test Detection",
        "timestamp": "2026-08-20T14:03:11Z",
        "severity_score": 5,
        "summary": "A test detection.",
        "endpoint": "WKS-01",
        "username": "jsmith",
        "process": "test.exe",
        "cmdline": "test.exe",
        "sha256": "a" * 64,
        # no "network" key at all
    }
    alert = normalize_edr_synthetic(raw)
    assert alert.dst_ip is None
    assert alert.dst_port is None


# --------------------------------------------------------------------------
# schema validation
# --------------------------------------------------------------------------

def test_schema_rejects_malformed_sha256():
    with pytest.raises(ValidationError):
        Alert(
            source=AlertSource.EDR_SYNTHETIC,
            source_alert_id="x",
            rule_name="x",
            occurred_at="2026-08-20T14:03:11Z",
            severity=Severity.LOW,
            description="x",
            file_hash_sha256="not-a-real-hash",
        )


def test_schema_rejects_malformed_ip():
    with pytest.raises(ValidationError):
        Alert(
            source=AlertSource.EDR_SYNTHETIC,
            source_alert_id="x",
            rule_name="x",
            occurred_at="2026-08-20T14:03:11Z",
            severity=Severity.LOW,
            description="x",
            src_ip="not-an-ip",
        )


def test_dispatch_normalize_raises_for_unregistered_source():
    # AlertSource.MORDOR_SIGMA is reserved for a later week and has no
    # normalizer yet -- confirm the dispatcher fails loudly rather than
    # silently no-op'ing.
    with pytest.raises(NotImplementedError):
        normalize({}, AlertSource.MORDOR_SIGMA)


# --------------------------------------------------------------------------
# end-to-end over the real sample data
# --------------------------------------------------------------------------

def test_load_all_normalizes_every_sample_alert_without_error():
    alerts = load_all()

    expected_count = sum(
        len(json.loads((RAW_DIR / f).read_text())) for f in ("sigma_synthetic.json", "edr_synthetic.json")
    )
    assert len(alerts) == expected_count
    assert all(isinstance(a, Alert) for a in alerts)
    # sorted by occurred_at
    assert alerts == sorted(alerts, key=lambda a: a.occurred_at)


def test_every_sample_alert_has_ground_truth_label():
    """Guards against the sample dataset and eval/labels.json drifting apart
    silently -- every alert we ship must be labeled, or Week 8's eval
    numbers would be quietly computed over an incomplete set."""
    labels_path = Path(__file__).resolve().parents[1] / "eval" / "labels.json"
    labels = json.loads(labels_path.read_text())

    alerts = load_all()
    missing = [a.source_alert_id for a in alerts if a.source_alert_id not in labels]
    assert not missing, f"Alerts missing ground-truth labels: {missing}"
