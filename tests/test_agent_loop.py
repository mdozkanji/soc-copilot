from datetime import datetime, timezone

import pytest

from soc_copilot.agent.assets import make_asset_lookup
from soc_copilot.agent.llm_types import LLMResponse, ToolCall
from soc_copilot.agent.loop import AgentDidNotConverge, SocAnalystAgent
from soc_copilot.agent.models import RecommendedAction
from soc_copilot.correlate.models import Case
from soc_copilot.enrich.service import EnrichmentService
from soc_copilot.ingest.schema import Alert, AlertSource, Severity


class FakeLLMClient:
    """Returns scripted LLMResponse objects in order; records every call
    for inspection. Working against the normalized llm_types interface
    (rather than any provider's raw wire format) means these tests exercise
    the loop's actual logic, not a specific vendor's JSON shape."""

    def __init__(self, responses: list[LLMResponse]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def create_message(self, *, system, history, tools):
        self.calls.append({"system": system, "history": list(history), "tools": tools})
        if not self._responses:
            raise AssertionError("FakeLLMClient ran out of scripted responses")
        return self._responses.pop(0)


def _make_case_and_alert() -> tuple[Case, dict]:
    alert = Alert(
        source=AlertSource.EDR_SYNTHETIC,
        source_alert_id="test-1",
        rule_name="Test Rule",
        occurred_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        description="A test alert.",
        host="WKS-EU-0231",
        user="jsmith",
        dst_ip="185.220.101.47",
    )
    case = Case(
        case_id="correlated-case-001",
        alert_ids=[alert.alert_id],
        source_alert_ids=[alert.source_alert_id],
        first_seen=alert.occurred_at,
        last_seen=alert.occurred_at,
        hosts=["WKS-EU-0231"],
        users=["jsmith"],
        ips=["185.220.101.47"],
    )
    return case, {alert.alert_id: alert}


def _agent(fake_client, enrichment=None, asset_inventory=None, max_iterations=8):
    return SocAnalystAgent(
        llm_client=fake_client,
        enrichment_service=enrichment or EnrichmentService(),
        asset_lookup=make_asset_lookup(asset_inventory or {}),
        max_iterations=max_iterations,
    )


VALID_VERDICT_INPUT = {
    "severity": "high",
    "confidence": 90,
    "mitre_techniques": ["T1071"],
    "recommended_action": "recommend_escalate_urgent",
    "reasoning": "The destination IP is a known Tor exit node with malicious detections.",
    "key_evidence": ["VirusTotal flagged the IP as malicious"],
}


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------

def test_happy_path_investigates_then_converges_on_verdict():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeLLMClient(
        [
            LLMResponse(
                text="Let me check this IP and the host's context.",
                tool_calls=[
                    ToolCall(id="t1", name="enrich_ip", input={"ip": "185.220.101.47"}),
                    ToolCall(id="t2", name="get_asset_context", input={"hostname": "WKS-EU-0231"}),
                ],
            ),
            LLMResponse(tool_calls=[ToolCall(id="t3", name="submit_verdict", input=VALID_VERDICT_INPUT)]),
        ]
    )
    agent = _agent(
        fake,
        asset_inventory={"WKS-EU-0231": {"owner": "jsmith", "criticality": "high", "department": "IT", "asset_type": "workstation"}},
    )

    result = agent.investigate(case, alerts_by_id)

    assert result.verdict.severity == Severity.HIGH
    assert result.verdict.recommended_action == RecommendedAction.RECOMMEND_ESCALATE_URGENT
    assert result.iterations == 2
    assert len(result.trace) == 2
    assert {c.name for c in result.trace[0].tool_calls} == {"enrich_ip", "get_asset_context"}
    assert result.trace[0].assistant_text == "Let me check this IP and the host's context."


def test_history_accumulates_correctly_shaped_turns():
    """Verifies the loop builds a coherent normalized conversation: the
    assistant's tool calls go in, and a matching tool_results turn comes
    back before the next LLM call."""
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeLLMClient(
        [
            LLMResponse(tool_calls=[ToolCall(id="abc123", name="enrich_ip", input={"ip": "185.220.101.47"})]),
            LLMResponse(tool_calls=[ToolCall(id="t2", name="submit_verdict", input=VALID_VERDICT_INPUT)]),
        ]
    )
    agent = _agent(fake)
    agent.investigate(case, alerts_by_id)

    second_call_history = fake.calls[1]["history"]
    assert second_call_history[1].role == "assistant"
    assert second_call_history[1].tool_calls[0].id == "abc123"
    assert second_call_history[2].role == "tool_results"
    assert second_call_history[2].tool_results[0].tool_call_id == "abc123"


# --------------------------------------------------------------------------
# graceful degradation
# --------------------------------------------------------------------------

def test_failing_tool_becomes_an_error_result_not_a_crash():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeLLMClient(
        [
            # enrich_hash with no VT configured -> EnrichmentService raises RuntimeError
            LLMResponse(tool_calls=[ToolCall(id="t1", name="enrich_hash", input={"sha256": "a" * 64})]),
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="t2",
                        name="submit_verdict",
                        input={**VALID_VERDICT_INPUT, "confidence": 20, "reasoning": "Hash enrichment was unavailable; low confidence."},
                    )
                ]
            ),
        ]
    )
    agent = _agent(fake, enrichment=EnrichmentService())  # no VT/AbuseIPDB clients configured

    result = agent.investigate(case, alerts_by_id)  # must not raise

    assert result.trace[0].tool_calls[0].name == "enrich_hash"
    assert "error" in result.trace[0].tool_calls[0].result
    assert result.verdict.confidence == 20


def test_unknown_tool_name_becomes_an_error_result_not_a_crash():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeLLMClient(
        [
            LLMResponse(tool_calls=[ToolCall(id="t1", name="some_tool_that_does_not_exist", input={})]),
            LLMResponse(tool_calls=[ToolCall(id="t2", name="submit_verdict", input=VALID_VERDICT_INPUT)]),
        ]
    )
    agent = _agent(fake)
    result = agent.investigate(case, alerts_by_id)
    assert "Unknown tool" in result.trace[0].tool_calls[0].result["error"]


def test_malformed_verdict_is_rejected_and_agent_gets_a_chance_to_retry():
    case, alerts_by_id = _make_case_and_alert()
    bad_verdict = {**VALID_VERDICT_INPUT, "confidence": 150}  # out of the 0-100 range
    fake = FakeLLMClient(
        [
            LLMResponse(tool_calls=[ToolCall(id="t1", name="submit_verdict", input=bad_verdict)]),
            LLMResponse(tool_calls=[ToolCall(id="t2", name="submit_verdict", input=VALID_VERDICT_INPUT)]),
        ]
    )
    agent = _agent(fake)
    result = agent.investigate(case, alerts_by_id)

    assert result.iterations == 2
    assert result.verdict.confidence == 90  # the corrected, valid submission
    second_call_history = fake.calls[1]["history"]
    tool_result = second_call_history[2].tool_results[0]
    assert tool_result.is_error is True


# --------------------------------------------------------------------------
# non-convergence
# --------------------------------------------------------------------------

def test_raises_if_agent_never_calls_submit_verdict():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeLLMClient([LLMResponse(text="I'm thinking about it."), LLMResponse(text="Still thinking.")])
    agent = _agent(fake, max_iterations=2)

    with pytest.raises(AgentDidNotConverge, match="correlated-case-001"):
        agent.investigate(case, alerts_by_id)


def test_nudge_message_is_sent_when_agent_responds_with_no_tool_use():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeLLMClient(
        [
            LLMResponse(text="Hmm."),
            LLMResponse(tool_calls=[ToolCall(id="t1", name="submit_verdict", input=VALID_VERDICT_INPUT)]),
        ]
    )
    agent = _agent(fake, max_iterations=3)
    result = agent.investigate(case, alerts_by_id)

    assert result.iterations == 2
    second_call_history = fake.calls[1]["history"]
    assert "submit_verdict" in second_call_history[2].text
