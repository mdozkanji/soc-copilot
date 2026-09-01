from datetime import datetime, timezone
from uuid import uuid4

import pytest

from soc_copilot.agent.assets import make_asset_lookup
from soc_copilot.agent.loop import AgentDidNotConverge, SocAnalystAgent
from soc_copilot.agent.models import RecommendedAction
from soc_copilot.correlate.models import Case
from soc_copilot.enrich.service import EnrichmentService
from soc_copilot.ingest.schema import Alert, AlertSource, Severity


class FakeClaudeClient:
    """Returns scripted responses in order; records every call for
    inspection, so tests can assert on the exact message history the loop
    builds, not just the final result."""

    def __init__(self, responses: list[dict]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def create_message(self, *, system, messages, tools, max_tokens=2048):
        self.calls.append({"system": system, "messages": [dict(m) for m in messages], "tools": tools})
        if not self._responses:
            raise AssertionError("FakeClaudeClient ran out of scripted responses")
        return self._responses.pop(0)


def _text_block(text: str) -> dict:
    return {"type": "text", "text": text}


def _tool_use_block(tool_id: str, name: str, input_: dict) -> dict:
    return {"type": "tool_use", "id": tool_id, "name": name, "input": input_}


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
        claude_client=fake_client,
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
    fake = FakeClaudeClient(
        [
            {
                "content": [
                    _text_block("Let me check this IP and the host's context."),
                    _tool_use_block("t1", "enrich_ip", {"ip": "185.220.101.47"}),
                    _tool_use_block("t2", "get_asset_context", {"hostname": "WKS-EU-0231"}),
                ],
                "stop_reason": "tool_use",
            },
            {"content": [_tool_use_block("t3", "submit_verdict", VALID_VERDICT_INPUT)], "stop_reason": "tool_use"},
        ]
    )
    agent = _agent(fake, asset_inventory={"WKS-EU-0231": {"owner": "jsmith", "criticality": "high", "department": "IT", "asset_type": "workstation"}})

    result = agent.investigate(case, alerts_by_id)

    assert result.verdict.severity == Severity.HIGH
    assert result.verdict.recommended_action == RecommendedAction.RECOMMEND_ESCALATE_URGENT
    assert result.iterations == 2
    assert len(result.trace) == 2
    assert {c.name for c in result.trace[0].tool_calls} == {"enrich_ip", "get_asset_context"}
    assert result.trace[0].assistant_text == "Let me check this IP and the host's context."


def test_second_call_includes_properly_formed_tool_results():
    """Verifies the loop actually implements the Anthropic multi-turn
    tool-use protocol correctly: the assistant's own content goes back
    verbatim, and each tool_use gets a matching tool_result keyed by the
    same tool_use_id."""
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeClaudeClient(
        [
            {"content": [_tool_use_block("abc123", "enrich_ip", {"ip": "185.220.101.47"})], "stop_reason": "tool_use"},
            {"content": [_tool_use_block("t2", "submit_verdict", VALID_VERDICT_INPUT)], "stop_reason": "tool_use"},
        ]
    )
    agent = _agent(fake)
    agent.investigate(case, alerts_by_id)

    second_call_messages = fake.calls[1]["messages"]
    assert second_call_messages[1]["role"] == "assistant"
    assert second_call_messages[1]["content"][0]["id"] == "abc123"
    assert second_call_messages[2]["role"] == "user"
    tool_result = second_call_messages[2]["content"][0]
    assert tool_result["type"] == "tool_result"
    assert tool_result["tool_use_id"] == "abc123"


# --------------------------------------------------------------------------
# graceful degradation
# --------------------------------------------------------------------------

def test_failing_tool_becomes_an_error_result_not_a_crash():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeClaudeClient(
        [
            # enrich_hash with no VT configured -> EnrichmentService raises RuntimeError
            {"content": [_tool_use_block("t1", "enrich_hash", {"sha256": "a" * 64})], "stop_reason": "tool_use"},
            {
                "content": [
                    _tool_use_block(
                        "t2",
                        "submit_verdict",
                        {**VALID_VERDICT_INPUT, "confidence": 20, "reasoning": "Hash enrichment was unavailable; low confidence."},
                    )
                ],
                "stop_reason": "tool_use",
            },
        ]
    )
    agent = _agent(fake, enrichment=EnrichmentService())  # no VT/AbuseIPDB clients configured

    result = agent.investigate(case, alerts_by_id)  # must not raise

    assert result.trace[0].tool_calls[0].name == "enrich_hash"
    assert "error" in result.trace[0].tool_calls[0].result
    assert result.verdict.confidence == 20


def test_unknown_tool_name_becomes_an_error_result_not_a_crash():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeClaudeClient(
        [
            {"content": [_tool_use_block("t1", "some_tool_that_does_not_exist", {})], "stop_reason": "tool_use"},
            {"content": [_tool_use_block("t2", "submit_verdict", VALID_VERDICT_INPUT)], "stop_reason": "tool_use"},
        ]
    )
    agent = _agent(fake)
    result = agent.investigate(case, alerts_by_id)
    assert "Unknown tool" in result.trace[0].tool_calls[0].result["error"]


def test_malformed_verdict_is_rejected_and_agent_gets_a_chance_to_retry():
    case, alerts_by_id = _make_case_and_alert()
    bad_verdict = {**VALID_VERDICT_INPUT, "confidence": 150}  # out of the 0-100 range
    fake = FakeClaudeClient(
        [
            {"content": [_tool_use_block("t1", "submit_verdict", bad_verdict)], "stop_reason": "tool_use"},
            {"content": [_tool_use_block("t2", "submit_verdict", VALID_VERDICT_INPUT)], "stop_reason": "tool_use"},
        ]
    )
    agent = _agent(fake)
    result = agent.investigate(case, alerts_by_id)

    assert result.iterations == 2
    assert result.verdict.confidence == 90  # the corrected, valid submission
    # the first (rejected) attempt should be reflected in the second API call's messages
    second_call_messages = fake.calls[1]["messages"]
    tool_result = second_call_messages[2]["content"][0]
    assert tool_result.get("is_error") is True


# --------------------------------------------------------------------------
# non-convergence
# --------------------------------------------------------------------------

def test_raises_if_agent_never_calls_submit_verdict():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeClaudeClient(
        [
            {"content": [_text_block("I'm thinking about it.")], "stop_reason": "end_turn"},
            {"content": [_text_block("Still thinking.")], "stop_reason": "end_turn"},
        ]
    )
    agent = _agent(fake, max_iterations=2)

    with pytest.raises(AgentDidNotConverge, match="correlated-case-001"):
        agent.investigate(case, alerts_by_id)


def test_nudge_message_is_sent_when_agent_responds_with_no_tool_use():
    case, alerts_by_id = _make_case_and_alert()
    fake = FakeClaudeClient(
        [
            {"content": [_text_block("Hmm.")], "stop_reason": "end_turn"},
            {"content": [_tool_use_block("t1", "submit_verdict", VALID_VERDICT_INPUT)], "stop_reason": "tool_use"},
        ]
    )
    agent = _agent(fake, max_iterations=3)
    result = agent.investigate(case, alerts_by_id)

    assert result.iterations == 2
    second_call_messages = fake.calls[1]["messages"]
    assert "submit_verdict" in second_call_messages[2]["content"]
