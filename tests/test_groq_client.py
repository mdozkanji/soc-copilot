import json

import httpx
import pytest

from soc_copilot.agent.groq_client import BASE_URL, GroqAPIError, GroqClient
from soc_copilot.agent.llm_types import ToolCall, Turn

TEXT_RESPONSE = {
    "choices": [{"message": {"role": "assistant", "content": "Hello.", "tool_calls": None}, "finish_reason": "stop"}]
}

TOOL_CALL_RESPONSE = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "enrich_ip", "arguments": '{"ip": "1.2.3.4"}'}}
                ],
            },
            "finish_reason": "tool_calls",
        }
    ]
}

MALFORMED_ARGS_RESPONSE = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "enrich_ip", "arguments": "not valid json{{"}}
                ],
            },
            "finish_reason": "tool_calls",
        }
    ]
}


def _client_with_handler(handler, sleep_fn=lambda s: None):
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(base_url=BASE_URL, transport=transport)
    return GroqClient(api_key="test-key", http_client=http_client, sleep_fn=sleep_fn)


# --------------------------------------------------------------------------
# request translation (system prompt, tool_calls arguments, tool results)
# --------------------------------------------------------------------------

def test_system_prompt_goes_into_messages_array_not_a_separate_field():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["messages"][0] == {"role": "system", "content": "sys prompt"}
        assert "system" not in body  # not a top-level field, unlike Anthropic
        return httpx.Response(200, json=TEXT_RESPONSE)

    client = _client_with_handler(handler)
    client.create_message(system="sys prompt", history=[Turn(role="user", text="hi")], tools=[])


def test_tools_are_wrapped_in_function_type_with_parameters_key():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["tools"] == [
            {"type": "function", "function": {"name": "enrich_ip", "description": "d", "parameters": {"type": "object"}}}
        ]
        return httpx.Response(200, json=TEXT_RESPONSE)

    client = _client_with_handler(handler)
    client.create_message(
        system="s",
        history=[Turn(role="user", text="hi")],
        tools=[{"name": "enrich_ip", "description": "d", "input_schema": {"type": "object"}}],
    )


def test_assistant_tool_calls_are_encoded_as_json_string_arguments():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assistant_msg = body["messages"][2]
        assert assistant_msg["role"] == "assistant"
        wire_call = assistant_msg["tool_calls"][0]
        assert wire_call["function"]["name"] == "enrich_ip"
        assert json.loads(wire_call["function"]["arguments"]) == {"ip": "1.2.3.4"}
        return httpx.Response(200, json=TEXT_RESPONSE)

    client = _client_with_handler(handler)
    history = [
        Turn(role="user", text="hi"),
        Turn(role="assistant", tool_calls=[ToolCall(id="call_1", name="enrich_ip", input={"ip": "1.2.3.4"})]),
    ]
    client.create_message(system="s", history=history, tools=[])


def test_tool_results_become_separate_role_tool_messages():
    from soc_copilot.agent.llm_types import ToolResult

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert len(tool_msgs) == 2
        assert tool_msgs[0] == {"role": "tool", "tool_call_id": "t1", "content": "ok"}
        assert tool_msgs[1]["content"].startswith("ERROR:")
        return httpx.Response(200, json=TEXT_RESPONSE)

    client = _client_with_handler(handler)
    history = [
        Turn(role="user", text="hi"),
        Turn(
            role="tool_results",
            tool_results=[
                ToolResult(tool_call_id="t1", content="ok"),
                ToolResult(tool_call_id="t2", content="boom", is_error=True),
            ],
        ),
    ]
    client.create_message(system="s", history=history, tools=[])


# --------------------------------------------------------------------------
# response parsing
# --------------------------------------------------------------------------

def test_parses_text_only_response():
    client = _client_with_handler(lambda r: httpx.Response(200, json=TEXT_RESPONSE))
    result = client.create_message(system="s", history=[Turn(role="user", text="hi")], tools=[])
    assert result.text == "Hello."
    assert result.tool_calls == []


def test_parses_tool_call_response_decoding_json_string_arguments():
    client = _client_with_handler(lambda r: httpx.Response(200, json=TOOL_CALL_RESPONSE))
    result = client.create_message(system="s", history=[Turn(role="user", text="hi")], tools=[])
    assert result.tool_calls == [ToolCall(id="call_1", name="enrich_ip", input={"ip": "1.2.3.4"})]


def test_malformed_tool_call_arguments_do_not_crash_parsing():
    """Real, observed failure mode for some open-weight models: emitting
    tool arguments that aren't valid JSON. Must degrade to a flagged error
    payload, not raise, so the agent loop can turn it into a tool-error
    result instead of the whole request blowing up."""
    client = _client_with_handler(lambda r: httpx.Response(200, json=MALFORMED_ARGS_RESPONSE))
    result = client.create_message(system="s", history=[Turn(role="user", text="hi")], tools=[])
    assert result.tool_calls[0].input["_parse_error"] == "arguments were not valid JSON"


# --------------------------------------------------------------------------
# retry / error handling
# --------------------------------------------------------------------------

def test_retries_on_429_then_succeeds():
    responses = iter([httpx.Response(429, text="rate limited"), httpx.Response(200, json=TEXT_RESPONSE)])
    client = _client_with_handler(lambda r: next(responses))
    result = client.create_message(system="s", history=[Turn(role="user", text="hi")], tools=[])
    assert result.text == "Hello."


def test_raises_after_exhausting_retries():
    client = _client_with_handler(lambda r: httpx.Response(500, text="down"))
    with pytest.raises(GroqAPIError):
        client.create_message(system="s", history=[Turn(role="user", text="hi")], tools=[])


def test_does_not_retry_on_401():
    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        return httpx.Response(401, text="bad key")

    client = _client_with_handler(handler)
    with pytest.raises(GroqAPIError):
        client.create_message(system="s", history=[Turn(role="user", text="hi")], tools=[])
    assert call_count["n"] == 1


def test_from_env_requires_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        GroqClient.from_env()
