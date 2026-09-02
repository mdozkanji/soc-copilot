"""
Provider-agnostic types for the agent loop.

Week 4 originally had the agent loop directly manipulate Anthropic's raw
message-block format (content blocks with "type": "text"/"tool_use",
appended verbatim into a growing `messages` list). That worked, but it
meant the loop itself knew about a specific vendor's wire protocol -- and
one week later, switching to Groq's free tier to avoid requiring anyone to
pay for a demo meant touching loop.py, not just the client, because the
two protocols differ in real ways: Groq (OpenAI-compatible) puts the
system prompt inside the messages array instead of as a separate field,
represents tool results as role="tool" messages instead of "user" messages
containing tool_result blocks, and encodes tool-call arguments as a JSON
*string* rather than a nested object.

This module exists so that refactor only has to happen once. The loop only
ever sees these normalized types; every provider-specific client (today:
groq_client.py) is entirely responsible for translating to and from its
own wire format inside create_message(). Adding a third provider later
means writing one new client class implementing this same shape, not
touching loop.py at all.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    id: str
    name: str
    input: dict[str, Any]


class ToolResult(BaseModel):
    tool_call_id: str
    content: str
    is_error: bool = False


class Turn(BaseModel):
    """One turn of normalized conversation history. Exactly one of
    text/tool_calls (role="assistant"), text (role="user"), or
    tool_results (role="tool_results") is populated, depending on role."""

    role: str  # "user" | "assistant" | "tool_results"
    text: Optional[str] = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)


class LLMResponse(BaseModel):
    text: Optional[str] = None
    tool_calls: list[ToolCall] = Field(default_factory=list)


class LLMClient(Protocol):
    """The interface every provider-specific client must implement. Not
    enforced at runtime (Python duck-types this fine, and tests use plain
    fakes) -- this Protocol exists for readability and static type
    checking, documenting the contract in one place."""

    def create_message(
        self, *, system: str, history: list[Turn], tools: list[dict[str, Any]]
    ) -> LLMResponse: ...
