"""
The agent's output models.

Verdict is deliberately produced via a tool call (submit_verdict), not
parsed out of free text -- see loop.py's module docstring for why. Reusing
ingest.schema.Severity here (rather than a second severity enum) is
intentional: it's the same scale as a source alert's own severity, and the
whole point, documented back in Week 1's Alert.severity, is that the two
are allowed to disagree. A source alert marked "high" that the agent
downgrades to "informational, confirmed benign" is a success case, not a
bug.

AgentTraceEntry exists so an investigation is auditable step by step, not
just as a final answer -- this is the actual point of the whole project
(see docs/PROJECT_OVERVIEW.md): every claim in a verdict should be
traceable back to a specific tool call an analyst can inspect.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from soc_copilot.ingest.schema import Severity


class RecommendedAction(str, Enum):
    """What the agent thinks a HUMAN should do next -- never something the
    agent itself does. Named as recommendations, not actions, on purpose:
    this project's stated posture (see docs/PROJECT_OVERVIEW.md) is
    recommend-only, never auto-execute containment."""

    RECOMMEND_CLOSE_BENIGN = "recommend_close_benign"
    RECOMMEND_MONITOR = "recommend_monitor"
    RECOMMEND_ESCALATE_ANALYST = "recommend_escalate_analyst"
    RECOMMEND_ESCALATE_URGENT = "recommend_escalate_urgent"


class Verdict(BaseModel):
    severity: Severity
    confidence: int = Field(..., ge=0, le=100, description="0-100 confidence in this verdict.")
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction
    reasoning: str = Field(..., min_length=1)
    key_evidence: list[str] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    name: str
    input: dict[str, Any]
    result: Any  # usually a dict; kept permissive since tool results vary by tool


class AgentTraceEntry(BaseModel):
    iteration: int
    assistant_text: Optional[str] = None
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)


class AgentResult(BaseModel):
    case_id: str
    verdict: Verdict
    trace: list[AgentTraceEntry]
    iterations: int
