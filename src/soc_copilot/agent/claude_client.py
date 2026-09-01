"""
A thin wrapper around the Anthropic Messages API (raw HTTP, not the SDK).

Built deliberately in the same style as enrich/virustotal.py and
enrich/abuseipdb.py: an injectable httpx.Client so tests can use
httpx.MockTransport instead of live network or a real API key, and
explicit retry/backoff instead of relying on a library to hide it. Using
the raw REST API instead of the anthropic SDK is also just a good way to
actually see the tool-use wire protocol (the exact shape of a tool_use
content block, how tool_result gets fed back as the next user message)
rather than have it hidden behind an SDK abstraction -- worth understanding
directly for a project whose whole point is agent architecture.

Returns the raw parsed response JSON rather than a normalized model,
unlike the Week 2 clients. This is intentional, not an inconsistency: the
Anthropic API's multi-turn tool-use protocol requires feeding the
assistant's exact `content` blocks back verbatim as the next message to
keep the conversation valid -- normalizing them into our own model and
translating back would just be extra surface area for a subtle bug.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

import httpx

BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5"

# 529 is Anthropic's "overloaded" status code -- included here alongside
# the standard retryable set because it's a real, documented response this
# API specifically returns under load, not a generic guess.
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 529}
_MAX_RETRIES = 3
_BACKOFF_BASE_SECONDS = 2.0


class ClaudeAPIError(RuntimeError):
    pass


class ClaudeClient:
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
    def from_env(cls, **kwargs) -> "ClaudeClient":
        import os

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set.")
        return cls(api_key=api_key, **kwargs)

    def create_message(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 2048,
    ) -> dict[str, Any]:
        """Returns the raw parsed response JSON. Callers are expected to
        read response["content"] (a list of content blocks) and
        response["stop_reason"] directly -- see agent/loop.py."""
        body = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        last_exc: Optional[Exception] = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._client.post("/v1/messages", json=body, headers=headers)
            except httpx.TransportError as e:
                last_exc = e
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in _RETRYABLE_STATUS_CODES:
                last_exc = ClaudeAPIError(f"Anthropic API returned {resp.status_code}")
                self._sleep_fn(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue

            # Non-retryable: bad API key, malformed request, etc.
            raise ClaudeAPIError(f"Anthropic API returned {resp.status_code}: {resp.text[:500]}")

        raise ClaudeAPIError(f"Anthropic API request failed after {_MAX_RETRIES} attempts") from last_exc
