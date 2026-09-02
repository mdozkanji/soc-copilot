"""
Groq client -- OpenAI-compatible chat completions API, implementing the
LLMClient interface from llm_types.py.

Using Groq's free tier (https://console.groq.com, no credit card required)
instead of a paid Anthropic key so this project runs as a demo without
requiring anyone -- including a reviewer cloning the repo -- to pay for API
access. Model: openai/gpt-oss-120b, OpenAI's own open-weight model hosted
on Groq's infrastructure, documented by Groq specifically as "designed for
high-capability agentic use" (console.groq.com/docs/model/openai/gpt-oss-120b).

NOTE on model choice: Groq's free-tier catalog changes frequently -- this
project's original choice (llama-3.3-70b-versatile) was deprecated and
returning 404 within about two weeks of being picked, which is what
prompted switching to gpt-oss-120b and, more importantly, adding the
GROQ_MODEL override below. Don't hardcode a model as a silent assumption;
if this one gets deprecated too, set GROQ_MODEL in .env rather than
waiting on a code change -- see console.groq.com/docs/models for the
current list.

Built in the same style as every other HTTP client in this project:
injectable httpx.Client, explicit retry/backoff, no SDK -- so the actual
wire protocol is visible rather than hidden. The one genuinely tricky part
of this client is translation, not networking: Groq's OpenAI-compatible
protocol differs from Anthropic's in several concrete ways that
_build_wire_messages and _parse_response exist specifically to bridge --
see the comments inline.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

import httpx

from soc_copilot.agent.llm_types import LLMResponse, ToolCall, Turn

BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "openai/gpt-oss-120b"

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503}
_MAX_RETRIES = 3
_BACKOFF_BASE_SECONDS = 2.0


class GroqAPIError(RuntimeError):
    pass


class GroqClient:
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        http_client: Optional[httpx.Client] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self._api_key = api_key
        self._model = model
        self._sleep_fn = sleep_fn
        self._client = http_client or httpx.Client(base_url=BASE_URL, timeout=120.0)

    @classmethod
    def from_env(cls, **kwargs) -> "GroqClient":
        import os

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Get a free key (no credit card required) at https://console.groq.com/keys"
            )
        model = os.environ.get("GROQ_MODEL")
        if model:
            kwargs.setdefault("model", model)
        return cls(api_key=api_key, **kwargs)

    def create_message(self, *, system: str, history: list[Turn], tools: list[dict[str, Any]]) -> LLMResponse:
        body = {
            "model": self._model,
            "messages": self._build_wire_messages(system, history),
            "tools": self._build_wire_tools(tools),
            "tool_choice": "auto",
        }
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

        last_exc: Optional[Exception] = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._client.post("/chat/completions", json=body, headers=headers)
            except httpx.TransportError as e:
                last_exc = e
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            if resp.status_code == 200:
                return self._parse_response(resp.json())
            if resp.status_code in _RETRYABLE_STATUS_CODES:
                last_exc = GroqAPIError(f"Groq API returned {resp.status_code}")
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            # Non-retryable: bad API key, malformed request, or Groq's own
            # tool_use_failed (400) when the model emits something that
            # doesn't parse as a valid tool call server-side.
            raise GroqAPIError(f"Groq API returned {resp.status_code}: {resp.text[:500]}")

        raise GroqAPIError(f"Groq API request failed after {_MAX_RETRIES} attempts") from last_exc

    @staticmethod
    def _build_wire_messages(system: str, history: list[Turn]) -> list[dict]:
        # Difference #1 from Anthropic: the system prompt is a message in
        # the array, not a separate top-level field.
        messages: list[dict] = [{"role": "system", "content": system}]

        for turn in history:
            if turn.role == "user":
                messages.append({"role": "user", "content": turn.text or ""})

            elif turn.role == "assistant":
                msg: dict = {"role": "assistant", "content": turn.text}
                if turn.tool_calls:
                    # Difference #2: tool-call arguments are a JSON *string*
                    # on the wire, not a nested object.
                    msg["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.name, "arguments": json.dumps(tc.input)},
                        }
                        for tc in turn.tool_calls
                    ]
                messages.append(msg)

            elif turn.role == "tool_results":
                # Difference #3: each tool result is its own role="tool"
                # message, not grouped into one user message like
                # Anthropic's tool_result content blocks.
                for tr in turn.tool_results:
                    content = f"ERROR: {tr.content}" if tr.is_error else tr.content
                    messages.append({"role": "tool", "tool_call_id": tr.tool_call_id, "content": content})

        return messages

    @staticmethod
    def _build_wire_tools(tools: list[dict[str, Any]]) -> list[dict]:
        # Difference #4: tools are wrapped in {"type": "function",
        # "function": {...}}, and the schema key is "parameters", not
        # "input_schema". Otherwise this is the same JSON-schema shape
        # agent/tools.py already defines, so no change needed there.
        return [
            {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in tools
        ]

    @staticmethod
    def _parse_response(raw: dict) -> LLMResponse:
        message = raw["choices"][0]["message"]
        text = message.get("content")

        tool_calls: list[ToolCall] = []
        for tc in message.get("tool_calls") or []:
            raw_args = tc["function"].get("arguments") or "{}"
            try:
                parsed_args = json.loads(raw_args)
            except json.JSONDecodeError:
                # Real, observed failure mode for some open-weight models:
                # emitting arguments that aren't valid JSON. Surface it as
                # data the agent loop can turn into a tool-error result
                # rather than letting a malformed response crash parsing.
                parsed_args = {"_parse_error": "arguments were not valid JSON", "_raw_arguments": raw_args}
            tool_calls.append(ToolCall(id=tc["id"], name=tc["function"]["name"], input=parsed_args))

        return LLMResponse(text=text, tool_calls=tool_calls)
