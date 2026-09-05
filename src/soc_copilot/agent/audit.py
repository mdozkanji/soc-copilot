"""
A cheap, rule-based auditor that checks whether a verdict's claims are
actually backed by its own trace -- independent of whether the underlying
model is trustworthy. This is deliberately NOT a correctness check (it
can't tell you if the verdict is *right*), and an empty warning list is
not a certification of quality. It's a narrower, useful claim: "nothing
here is obviously self-contradictory or asserted without any supporting
tool call."

Why this matters for a project whose stated differentiator is
"explainable, tool-grounded triage" (docs/PROJECT_OVERVIEW.md): an LLM can
write confident, well-formatted prose that simply isn't backed by anything
it actually looked up. The Verdict schema's own validators (models.py)
catch internal contradictions between a verdict's own fields
(evidence_sufficient vs. confidence vs. recommended_action); this module
catches a different, complementary kind of contradiction -- between the
verdict and the trace that supposedly produced it.
"""

from __future__ import annotations

import re

from soc_copilot.agent.models import AgentResult, RecommendedAction

HIGH_CONFIDENCE_THRESHOLD = 70

# Matches things like "15/91", "92%", "3 engines", "543 reports" -- the
# kind of specific figure that should only appear if a tool actually
# returned it, not something an LLM should be inventing from memory.
_FIGURE_PATTERN = re.compile(r"\b\d+(\.\d+)?\s*(%|/\s*\d+|engines?|reports?|detections?)\b", re.IGNORECASE)


def audit_verdict(result: AgentResult) -> list[str]:
    """Returns human-readable warnings. Empty list = no red flags found by
    this specific, narrow set of checks -- not a guarantee the verdict is
    correct."""
    warnings: list[str] = []
    verdict = result.verdict

    all_tool_calls = [call for entry in result.trace for call in entry.tool_calls]
    investigative_calls = [c for c in all_tool_calls if c.name != "submit_verdict"]
    successful_calls = [c for c in investigative_calls if not (isinstance(c.result, dict) and "error" in c.result)]
    called_tool_names = {c.name for c in investigative_calls}

    if verdict.confidence >= HIGH_CONFIDENCE_THRESHOLD and not successful_calls:
        warnings.append(
            f"confidence={verdict.confidence} (>= {HIGH_CONFIDENCE_THRESHOLD}) but no investigative tool call "
            "in the trace succeeded -- this verdict isn't grounded in anything the agent actually looked up."
        )

    if verdict.mitre_techniques:
        confirmed_ids: set[str] = set()
        for call in investigative_calls:
            if call.name == "search_mitre" and isinstance(call.result, dict):
                for r in call.result.get("results", []):
                    if isinstance(r, dict) and "technique_id" in r:
                        confirmed_ids.add(r["technique_id"])

        unconfirmed = [t for t in verdict.mitre_techniques if t not in confirmed_ids]
        if unconfirmed:
            warnings.append(
                f"cites MITRE technique(s) {unconfirmed} that never appeared in any search_mitre result in "
                "this trace -- confirming one technique via search_mitre doesn't confirm the others cited "
                "alongside it."
            )

    if verdict.key_evidence:
        cites_figures = any(_FIGURE_PATTERN.search(item) for item in verdict.key_evidence)
        enrichment_called = bool({"enrich_ip", "enrich_hash"} & called_tool_names)
        if cites_figures and not enrichment_called:
            warnings.append(
                "key_evidence cites a specific figure (a score, a detection count, a percentage) but no "
                "enrich_ip/enrich_hash call appears in the trace -- that figure isn't traceable to a tool result."
            )

    if verdict.recommended_action == RecommendedAction.RECOMMEND_CLOSE_BENIGN and verdict.confidence < 50:
        warnings.append(
            f"recommends closing as benign with confidence={verdict.confidence} (< 50) -- a low-confidence "
            "benign call is a softer version of the same tension the Verdict schema's own validators check for "
            "evidence_sufficient=False; worth a second look even though it isn't a hard model-level contradiction."
        )

    return warnings
