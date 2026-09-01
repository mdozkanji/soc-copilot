import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from soc_copilot.correlate.cluster import NOISY_ENTITY_VALUES, correlate
from soc_copilot.ingest.load_samples import load_all
from soc_copilot.ingest.schema import Alert, AlertSource, Severity

REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        source=AlertSource.SIGMA_SYNTHETIC,
        source_alert_id=f"test-{uuid4().hex[:8]}",
        rule_name="Test Rule",
        occurred_at=datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc),
        severity=Severity.MEDIUM,
        description="Test alert.",
    )
    defaults.update(overrides)
    return Alert(**defaults)


# --------------------------------------------------------------------------
# synthetic scenarios
# --------------------------------------------------------------------------

def test_two_alerts_sharing_host_within_window_merge():
    a = _make_alert(host="WKS-01", occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc))
    b = _make_alert(host="WKS-01", occurred_at=datetime(2026, 8, 20, 12, 30, tzinfo=timezone.utc))
    cases = correlate([a, b])
    assert len(cases) == 1
    assert cases[0].alert_count == 2


def test_two_alerts_sharing_host_outside_window_stay_separate():
    a = _make_alert(host="WKS-01", occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc))
    b = _make_alert(host="WKS-01", occurred_at=datetime(2026, 8, 20, 20, 0, tzinfo=timezone.utc))  # 8h later
    cases = correlate([a, b], max_gap=timedelta(hours=2))
    assert len(cases) == 2
    assert all(c.alert_count == 1 for c in cases)


def test_alerts_sharing_only_a_noisy_ip_do_not_merge():
    noisy_ip = next(iter(NOISY_ENTITY_VALUES))
    a = _make_alert(dst_ip=noisy_ip, occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc))
    b = _make_alert(dst_ip=noisy_ip, occurred_at=datetime(2026, 8, 20, 12, 5, tzinfo=timezone.utc))
    cases = correlate([a, b])
    assert len(cases) == 2  # NOT merged, despite sharing an IP and being close in time


def test_alerts_sharing_a_non_noisy_ip_do_merge_as_a_control():
    a = _make_alert(dst_ip="185.220.101.47", occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc))
    b = _make_alert(dst_ip="185.220.101.47", occurred_at=datetime(2026, 8, 20, 12, 5, tzinfo=timezone.utc))
    cases = correlate([a, b])
    assert len(cases) == 1  # same scenario as above, minus the noisy-IP exclusion -> merges


def test_shared_file_hash_links_alerts_with_no_other_common_entity():
    shared_hash = "a" * 64
    a = _make_alert(host="WKS-01", file_hash_sha256=shared_hash, occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc))
    b = _make_alert(host="WKS-02", file_hash_sha256=shared_hash, occurred_at=datetime(2026, 8, 20, 12, 10, tzinfo=timezone.utc))
    cases = correlate([a, b])
    assert len(cases) == 1
    assert "file_hash" in cases[0].link_reasons[0]


def test_transitive_chain_links_alerts_that_never_directly_share_an_entity():
    # A and C share nothing directly, but A-B share a host and B-C share a
    # user -- connected components should still merge all three, which is
    # exactly the "rolling window via chaining" behavior the module
    # docstring describes.
    a = _make_alert(host="WKS-01", occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc))
    b = _make_alert(host="WKS-01", user="jsmith", occurred_at=datetime(2026, 8, 20, 12, 5, tzinfo=timezone.utc))
    c = _make_alert(user="jsmith", occurred_at=datetime(2026, 8, 20, 12, 10, tzinfo=timezone.utc))
    cases = correlate([a, b, c])
    assert len(cases) == 1
    assert cases[0].alert_count == 3


def test_alert_with_no_shareable_entities_becomes_its_own_singleton_case():
    lone = _make_alert()  # no host/user/ip/hash at all
    cases = correlate([lone])
    assert len(cases) == 1
    assert cases[0].alert_count == 1
    assert cases[0].link_reasons == []


def test_every_input_alert_appears_in_exactly_one_output_case():
    alerts = [_make_alert(host=f"WKS-{i}") for i in range(5)]
    cases = correlate(alerts)
    all_case_alert_ids = {aid for c in cases for aid in c.alert_ids}
    assert all_case_alert_ids == {a.alert_id for a in alerts}


# --------------------------------------------------------------------------
# real dataset: purity check against eval/labels.json ground truth
# --------------------------------------------------------------------------

def _load_labels() -> dict:
    labels = json.loads((REPO_ROOT / "eval" / "labels.json").read_text())
    return {k: v for k, v in labels.items() if k != "_readme"}


def test_case_001_alerts_all_cluster_together_and_only_with_each_other():
    """The 8-alert intrusion chain should end up as one produced case,
    containing exactly those 8 alerts -- no more, no fewer. This is the
    scenario the whole correlation design (rolling-window chaining via
    connected components) exists to get right."""
    alerts = load_all()
    labels = _load_labels()
    cases = correlate(alerts)

    expected_source_ids = {sid for sid, info in labels.items() if info.get("case_id") == "case-001"}
    assert len(expected_source_ids) == 8  # sanity check on the fixture itself

    matching_cases = [c for c in cases if set(c.source_alert_ids) & expected_source_ids]
    assert len(matching_cases) == 1, "case-001 alerts ended up split across multiple produced cases"
    assert set(matching_cases[0].source_alert_ids) == expected_source_ids, (
        "produced case either merged extra alerts into case-001, or is missing some -- "
        f"got {sorted(matching_cases[0].source_alert_ids)}"
    )


def test_case_002_and_case_003_stay_separate_despite_shared_attacker_ip():
    """Regression test locking in the documented judgment call: case-002
    and case-003 share an external IP (45.146.164.12) ~2h45m apart. At the
    default 2-hour window they must NOT merge. If this ever starts failing
    after a max_gap change, that change needs the same explicit
    documentation this behavior already has in cluster.py."""
    alerts = load_all()
    labels = _load_labels()
    cases = correlate(alerts)

    case_002_id = next(sid for sid, info in labels.items() if info.get("case_id") == "case-002")
    case_003_id = next(sid for sid, info in labels.items() if info.get("case_id") == "case-003")

    case_of = {sid: c.case_id for c in cases for sid in c.source_alert_ids}
    assert case_of[case_002_id] != case_of[case_003_id]


def test_no_benign_alert_ends_up_in_the_same_case_as_a_malicious_one():
    """Cluster purity across the whole labeled set: every produced case
    should be internally consistent -- either every alert in it is
    malicious (same or no case_id) or every alert in it is benign, never a
    mix. A case is allowed to contain multiple *benign* alerts (e.g. two
    routine update check-ins on the same host close in time) -- that's a
    legitimate, harmless grouping, not a labeling failure."""
    alerts = load_all()
    labels = _load_labels()
    cases = correlate(alerts)

    for case in cases:
        truths = {labels[sid]["ground_truth"] for sid in case.source_alert_ids}
        assert len(truths) == 1, f"{case.case_id} mixes benign and malicious alerts: {case.source_alert_ids}"


def test_correlation_over_full_sample_set_is_deterministic():
    alerts = load_all()
    cases_1 = correlate(alerts)
    cases_2 = correlate(alerts)
    assert [sorted(c.source_alert_ids) for c in cases_1] == [sorted(c.source_alert_ids) for c in cases_2]
