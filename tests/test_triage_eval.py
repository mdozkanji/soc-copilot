import pytest

from soc_copilot.agent.models import RecommendedAction, Verdict
from soc_copilot.ingest.schema import Severity
from eval.triage_eval import EvalOutcome, TriageEvalReport, _true_label_for_case, classify_verdict, compute_report


def _verdict(action: RecommendedAction, evidence_sufficient: bool = True, confidence: int = 80) -> Verdict:
    return Verdict(
        severity=Severity.MEDIUM,
        confidence=confidence if evidence_sufficient else min(confidence, 30),
        evidence_sufficient=evidence_sufficient,
        recommended_action=action,
        reasoning="x",
    )


# --------------------------------------------------------------------------
# classify_verdict
# --------------------------------------------------------------------------

def test_predicted_malicious_and_actually_malicious_is_true_positive():
    v = _verdict(RecommendedAction.RECOMMEND_ESCALATE_URGENT)
    assert classify_verdict(v, true_malicious=True) == EvalOutcome.TRUE_POSITIVE


def test_predicted_malicious_but_actually_benign_is_false_positive():
    v = _verdict(RecommendedAction.RECOMMEND_ESCALATE_ANALYST)
    assert classify_verdict(v, true_malicious=False) == EvalOutcome.FALSE_POSITIVE


def test_predicted_benign_but_actually_malicious_is_false_negative():
    v = _verdict(RecommendedAction.RECOMMEND_CLOSE_BENIGN)
    assert classify_verdict(v, true_malicious=True) == EvalOutcome.FALSE_NEGATIVE


def test_predicted_benign_and_actually_benign_is_true_negative():
    v = _verdict(RecommendedAction.RECOMMEND_MONITOR)
    assert classify_verdict(v, true_malicious=False) == EvalOutcome.TRUE_NEGATIVE


@pytest.mark.parametrize("true_malicious", [True, False])
def test_insufficient_evidence_is_always_abstained_regardless_of_ground_truth(true_malicious):
    v = _verdict(RecommendedAction.RECOMMEND_ESCALATE_ANALYST, evidence_sufficient=False)
    assert classify_verdict(v, true_malicious=true_malicious) == EvalOutcome.ABSTAINED


def test_monitor_counts_as_predicted_benign_not_malicious():
    """A real methodology choice, tested explicitly rather than left
    implicit: recommend_monitor is scored as 'nothing needs to happen
    right now', the same operational bucket as close_benign."""
    v = _verdict(RecommendedAction.RECOMMEND_MONITOR)
    assert classify_verdict(v, true_malicious=True) == EvalOutcome.FALSE_NEGATIVE


# --------------------------------------------------------------------------
# compute_report
# --------------------------------------------------------------------------

def test_compute_report_basic_counts_and_rates():
    outcomes = [
        EvalOutcome.TRUE_POSITIVE,
        EvalOutcome.TRUE_POSITIVE,
        EvalOutcome.FALSE_POSITIVE,
        EvalOutcome.FALSE_NEGATIVE,
        EvalOutcome.TRUE_NEGATIVE,
        EvalOutcome.ABSTAINED,
    ]
    report = compute_report(outcomes)
    assert report.total == 6
    assert report.outcome_counts["true_positive"] == 2
    assert report.precision == pytest.approx(2 / 3)  # 2 TP / (2 TP + 1 FP)
    assert report.recall == pytest.approx(2 / 3)  # 2 TP / (2 TP + 1 FN)
    assert report.false_negative_rate == pytest.approx(1 / 3)  # 1 FN / (1 FN + 2 TP)
    assert report.abstention_rate == pytest.approx(1 / 6)


def test_compute_report_handles_no_positive_predictions_without_dividing_by_zero():
    outcomes = [EvalOutcome.TRUE_NEGATIVE, EvalOutcome.FALSE_NEGATIVE]
    report = compute_report(outcomes)
    assert report.precision is None  # no TP+FP at all -- precision is undefined, not 0


def test_compute_report_handles_all_abstained():
    outcomes = [EvalOutcome.ABSTAINED, EvalOutcome.ABSTAINED]
    report = compute_report(outcomes)
    assert report.abstention_rate == 1.0
    assert report.precision is None
    assert report.recall is None
    assert report.false_negative_rate is None


def test_compute_report_empty_input():
    report = compute_report([])
    assert report.total == 0
    assert report.abstention_rate == 0.0


# --------------------------------------------------------------------------
# _true_label_for_case
# --------------------------------------------------------------------------

def test_true_label_for_case_agrees_across_alerts():
    labels = {"a": {"ground_truth": "malicious"}, "b": {"ground_truth": "malicious"}}
    assert _true_label_for_case(["a", "b"], labels) is True


def test_true_label_for_case_benign():
    labels = {"a": {"ground_truth": "benign"}}
    assert _true_label_for_case(["a"], labels) is False


def test_true_label_for_case_raises_on_disagreement():
    """Guards a real invariant this harness depends on: Week 3's
    cluster-purity tests guarantee no case mixes benign and malicious
    alerts. If this ever fires, that guarantee has been broken somewhere,
    and the harness should say so loudly rather than silently pick one."""
    labels = {"a": {"ground_truth": "malicious"}, "b": {"ground_truth": "benign"}}
    with pytest.raises(ValueError, match="disagree"):
        _true_label_for_case(["a", "b"], labels)


def test_true_label_for_case_raises_when_no_labels_found():
    with pytest.raises(ValueError, match="No labeled alerts"):
        _true_label_for_case(["unknown-id"], {})
