import json

import httpx
import pytest

from soc_copilot.agent.claude_client import ANTHROPIC_VERSION, BASE_URL, ClaudeAPIError, ClaudeClient

SAMPLE_RESPONSE = {
    "id": "msg_01",
    "type": "message",
    "role": "assistant",
    "content": [{"type": "text", "text": "Hello."}],
    "stop_reason": "end_turn",
}


def _client_with_handler(handler, sleep_fn=lambda s: None):
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(base_url=BASE_URL, transport=transport)
    return ClaudeClient(api_key="test-key", http_client=http_client, sleep_fn=sleep_fn)


def test_create_message_sends_correct_request_shape():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/messages"
        assert request.headers["x-api-key"] == "test-key"
        assert request.headers["anthropic-version"] == ANTHROPIC_VERSION
        body = json.loads(request.content)
        assert body["system"] == "sys prompt"
        assert body["messages"] == [{"role": "user", "content": "hi"}]
        assert body["tools"] == [{"name": "t1", "description": "d", "input_schema": {}}]
        assert body["model"]  # some model string is set
        return httpx.Response(200, json=SAMPLE_RESPONSE)

    client = _client_with_handler(handler)
    result = client.create_message(
        system="sys prompt",
        messages=[{"role": "user", "content": "hi"}],
        tools=[{"name": "t1", "description": "d", "input_schema": {}}],
    )
    assert result == SAMPLE_RESPONSE


def test_retries_on_529_overloaded_then_succeeds():
    responses = iter([httpx.Response(529, text="overloaded"), httpx.Response(200, json=SAMPLE_RESPONSE)])

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    client = _client_with_handler(handler)
    result = client.create_message(system="s", messages=[], tools=[])
    assert result == SAMPLE_RESPONSE


def test_raises_after_exhausting_retries():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="down")

    client = _client_with_handler(handler)
    with pytest.raises(ClaudeAPIError):
        client.create_message(system="s", messages=[], tools=[])


def test_does_not_retry_on_401():
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(401, text="bad key")

    client = _client_with_handler(handler)
    with pytest.raises(ClaudeAPIError):
        client.create_message(system="s", messages=[], tools=[])
    assert call_count["n"] == 1


def test_from_env_requires_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        ClaudeClient.from_env()
