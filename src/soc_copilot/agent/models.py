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

Week 6: evidence_sufficient is a deliberate, explicit boolean, not just a
low confidence number. The reasoning: an LLM can write confidence=15 while
its prose still reads confidently, because natural-language hedging and a
numeric score aren't the same thing and can drift apart. Forcing a
discrete "do I actually have enough to conclude this, yes or no" decision
through the JSON schema is a stronger lever than hoping the number and the
tone agree, and it gives downstream code (a dashboard, an analyst queue)
something to hard-filter on instead of picking an arbitrary confidence
threshold. The cross-field validators below enforce that the two can't
silently contradict each other -- and because a validation failure here
routes through the exact same is_error tool_result / self-correction path
Week 4 already built for a malformed submit_verdict call, this required no
changes to loop.py at all.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from soc_copilot.ingest.schema import Severity

# A verdict claiming evidence is insufficient shouldn't also claim high
# confidence -- that's a direct contradiction in what the two fields mean,
# not a style preference. Chosen conservatively (40, not 50) so "borderline
# confident" still has to admit it's borderline.
MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT = 40

# With insufficient evidence, only these two actions are coherent: keep
# watching, or hand it to a human. Confidently closing something as benign
# or escalating it as urgent both assert a level of certainty that
# directly contradicts evidence_sufficient=False.
_ACTIONS_ALLOWED_WHEN_EVIDENCE_INSUFFICIENT = frozenset(
    {"recommend_monitor", "recommend_escalate_analyst"}
)


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
    evidence_sufficient: bool = Field(
        ...,
        description="Whether the gathered evidence is actually enough to support a confident conclusion. "
        "False is a legitimate, expected answer, not a failure -- see the module docstring.",
    )
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction
    reasoning: str = Field(..., min_length=1)
    key_evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_evidence_sufficiency_is_internally_consistent(self) -> "Verdict":
        if not self.evidence_sufficient:
            if self.confidence > MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT:
                raise ValueError(
                    f"evidence_sufficient=False but confidence={self.confidence} "
                    f"(must be <= {MAX_CONFIDENCE_WHEN_EVIDENCE_INSUFFICIENT}): "
                    "a verdict can't claim both 'I don't have enough evidence' and 'I'm quite confident.'"
                )
            if self.recommended_action.value not in _ACTIONS_ALLOWED_WHEN_EVIDENCE_INSUFFICIENT:
                raise ValueError(
                    f"evidence_sufficient=False but recommended_action={self.recommended_action.value}: "
                    f"with insufficient evidence, only {sorted(_ACTIONS_ALLOWED_WHEN_EVIDENCE_INSUFFICIENT)} "
                    "are coherent -- confidently closing as benign or escalating as urgent both assert a "
                    "certainty that contradicts insufficient evidence."
                )
        return self


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
