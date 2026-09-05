import pytest
from pydantic import ValidationError

from soc_copilot.agent.models import MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT, RecommendedAction, Verdict
from soc_copilot.ingest.schema import Severity

BASE_FIELDS = dict(
    severity=Severity.INFORMATIONAL,
    mitre_techniques=[],
    reasoning="Some reasoning.",
    key_evidence=[],
)


def test_evidence_sufficient_true_allows_any_confidence_and_action():
    v = Verdict(
        **BASE_FIELDS,
        confidence=95,
        evidence_sufficient=True,
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_URGENT,
    )
    assert v.confidence == 95


def test_evidence_sufficient_false_rejects_high_confidence():
    with pytest.raises(ValidationError, match="confidence"):
        Verdict(
            **BASE_FIELDS,
            confidence=MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT + 1,
            evidence_sufficient=False,
            recommended_action=RecommendedAction.RECOMMEND_ESCALATE_ANALYST,
        )


def test_evidence_sufficient_false_allows_confidence_at_the_boundary():
    v = Verdict(
        **BASE_FIELDS,
        confidence=MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT,
        evidence_sufficient=False,
        recommended_action=RecommendedAction.RECOMMEND_MONITOR,
    )
    assert v.confidence == MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT


@pytest.mark.parametrize(
    "action",
    [RecommendedAction.RECOMMEND_CLOSE_BENIGN, RecommendedAction.RECOMMEND_ESCALATE_URGENT],
)
def test_evidence_sufficient_false_rejects_actions_implying_certainty(action):
    with pytest.raises(ValidationError, match="recommended_action"):
        Verdict(**BASE_FIELDS, confidence=20, evidence_sufficient=False, recommended_action=action)


@pytest.mark.parametrize(
    "action",
    [RecommendedAction.RECOMMEND_MONITOR, RecommendedAction.RECOMMEND_ESCALATE_ANALYST],
)
def test_evidence_sufficient_false_allows_coherent_actions(action):
    v = Verdict(**BASE_FIELDS, confidence=20, evidence_sufficient=False, recommended_action=action)
    assert v.recommended_action == action


def test_evidence_sufficient_is_required():
    with pytest.raises(ValidationError, match="evidence_sufficient"):
        Verdict(
            **BASE_FIELDS,
            confidence=50,
            recommended_action=RecommendedAction.RECOMMEND_MONITOR,
        )
