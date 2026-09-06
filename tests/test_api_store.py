from datetime import datetime, timezone

from soc_copilot.agent.models import AgentResult, RecommendedAction, Verdict
from soc_copilot.api.store import AgentResultStore, FeedbackStore
from soc_copilot.correlate.models import Case
from soc_copilot.ingest.schema import Severity


def _case() -> Case:
    return Case(
        case_id="test-case",
        alert_ids=[],
        source_alert_ids=["sig-0001"],
        first_seen=datetime(2026, 8, 20, tzinfo=timezone.utc),
        last_seen=datetime(2026, 8, 20, tzinfo=timezone.utc),
        hosts=["WKS-01"],
    )


def _result() -> AgentResult:
    verdict = Verdict(
        severity=Severity.HIGH,
        confidence=80,
        evidence_sufficient=True,
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_ANALYST,
        reasoning="x",
    )
    return AgentResult(case_id="test-case", verdict=verdict, trace=[], iterations=1)


# --------------------------------------------------------------------------
# AgentResultStore
# --------------------------------------------------------------------------

def test_save_then_load_roundtrips(tmp_path):
    store = AgentResultStore(results_dir=tmp_path)
    store.save(_case(), _result())

    loaded = store.load("test-case")
    assert loaded is not None
    case, result = loaded
    assert case.case_id == "test-case"
    assert result.verdict.confidence == 80


def test_load_missing_case_returns_none(tmp_path):
    store = AgentResultStore(results_dir=tmp_path)
    assert store.load("does-not-exist") is None


def test_all_case_ids_reflects_saved_cases(tmp_path):
    store = AgentResultStore(results_dir=tmp_path)
    assert store.all_case_ids() == set()
    store.save(_case(), _result())
    assert store.all_case_ids() == {"test-case"}


def test_save_overwrites_existing_case(tmp_path):
    store = AgentResultStore(results_dir=tmp_path)
    store.save(_case(), _result())

    new_verdict = Verdict(
        severity=Severity.LOW,
        confidence=10,
        evidence_sufficient=False,
        recommended_action=RecommendedAction.RECOMMEND_MONITOR,
        reasoning="updated",
    )
    new_result = AgentResult(case_id="test-case", verdict=new_verdict, trace=[], iterations=1)
    store.save(_case(), new_result)

    _, loaded_result = store.load("test-case")
    assert loaded_result.verdict.confidence == 10


# --------------------------------------------------------------------------
# FeedbackStore
# --------------------------------------------------------------------------

def test_append_then_read_all(tmp_path):
    store = FeedbackStore(path=tmp_path / "feedback.jsonl")
    store.append(case_id="test-case", decision="accept", verdict_snapshot={"confidence": 80})

    entries = store.read_all()
    assert len(entries) == 1
    assert entries[0]["case_id"] == "test-case"
    assert entries[0]["decision"] == "accept"
    assert "reviewed_at" in entries[0]


def test_read_all_on_missing_file_returns_empty_list(tmp_path):
    store = FeedbackStore(path=tmp_path / "does-not-exist.jsonl")
    assert store.read_all() == []


def test_append_is_additive_not_overwriting(tmp_path):
    store = FeedbackStore(path=tmp_path / "feedback.jsonl")
    store.append(case_id="case-1", decision="accept", verdict_snapshot={})
    store.append(case_id="case-2", decision="override", verdict_snapshot={}, reason="wrong severity")

    entries = store.read_all()
    assert len(entries) == 2
    assert [e["case_id"] for e in entries] == ["case-1", "case-2"]


def test_override_entry_records_reason_and_corrections(tmp_path):
    store = FeedbackStore(path=tmp_path / "feedback.jsonl")
    store.append(
        case_id="case-1",
        decision="override",
        verdict_snapshot={"severity": "high"},
        reason="Confirmed benign after manual review",
        corrected_severity="informational",
        corrected_action="recommend_close_benign",
    )
    entry = store.read_all()[0]
    assert entry["reason"] == "Confirmed benign after manual review"
    assert entry["corrected_severity"] == "informational"
    assert entry["corrected_action"] == "recommend_close_benign"


def test_latest_decision_for_returns_the_most_recent_matching_entry(tmp_path):
    store = FeedbackStore(path=tmp_path / "feedback.jsonl")
    store.append(case_id="case-1", decision="accept", verdict_snapshot={})
    store.append(case_id="case-1", decision="override", verdict_snapshot={}, reason="changed my mind")

    latest = store.latest_decision_for("case-1")
    assert latest["decision"] == "override"


def test_latest_decision_for_returns_none_when_no_entries_match(tmp_path):
    store = FeedbackStore(path=tmp_path / "feedback.jsonl")
    store.append(case_id="case-1", decision="accept", verdict_snapshot={})
    assert store.latest_decision_for("case-2") is None
