"""
The agent loop.

Design: the loop alternates between calling Claude and executing whatever
tools it asks for, feeding results back as the next message, exactly like
any tool-use agent. The one deliberate choice worth explaining is how it
*ends*: rather than asking Claude to end its turn with plain text and
trying to parse a verdict out of that, submit_verdict is a tool like any
other, and the loop's termination condition is simply "Claude called
submit_verdict, and its input validated against our Verdict schema."

Why this matters: it means structured output isn't a separate mechanism
bolted on after the investigation -- it's the same tool-calling protocol
already being used to gather evidence, so there's exactly one code path to
get right, not two. It also means an ill-formed verdict doesn't crash the
loop: it comes back to Claude as a tool_result with is_error=True, and
Claude gets a chance to correct it -- see test_agent_loop.py for a case
that exercises exactly this.

Every tool dispatch is wrapped so a single failing tool (a down enrichment
API, a malformed input) becomes a {"error": ...} tool result the agent can
reason about and route around, never an exception that kills the whole
investigation. Same principle as enrich/service.py's per-source graceful
degradation in Week 2, applied one layer up.
"""

from __future__ import annotations

import json
from typing import Callable, Optional
from uuid import UUID

from pydantic import ValidationError

from soc_copilot.agent.claude_client import ClaudeClient
from soc_copilot.agent.models import AgentResult, AgentTraceEntry, ToolCallRecord, Verdict
from soc_copilot.agent.tools import TOOL_DEFINITIONS
from soc_copilot.correlate.models import Case
from soc_copilot.enrich.service import EnrichmentService
from soc_copilot.ingest.schema import Alert

DEFAULT_MAX_ITERATIONS = 8

SYSTEM_PROMPT = """You are a Tier-1 SOC (Security Operations Center) analyst copilot.

You will be given a "case": a group of alerts that a correlation engine has determined are likely related, drawn from SIEM and EDR sources. Your job is to investigate the case using the tools available to you, then submit a structured verdict via the submit_verdict tool.

Rules you must follow:
- Ground every specific claim in evidence you actually gathered via a tool call. Do not state a detection count, reputation score, or asset fact unless a tool returned it to you.
- If a tool returns no data, an error, or genuinely ambiguous evidence, say so honestly in your reasoning rather than guessing. Reporting low confidence, or recommending escalation for human review, is a better outcome than a confident conclusion you can't actually support.
- You are producing a RECOMMENDATION only. You cannot and will not take any containment action (blocking an IP, disabling an account, isolating a host) -- only a human analyst can do that. Your recommended_action should reflect what you think a human should do next, not something you are doing yourself.
- Internal/private IP addresses will not return threat-intel data -- enrich_ip will tell you an address was skipped for this reason. This is expected, not an error.
- Call submit_verdict exactly once, as your final action, once you have gathered enough evidence to reach a conclusion (including the conclusion that evidence is insufficient)."""


class AgentDidNotConverge(RuntimeError):
    pass


class SocAnalystAgent:
    def __init__(
        self,
        claude_client: ClaudeClient,
        enrichment_service: EnrichmentService,
        asset_lookup: Callable[[str], dict],
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
    ):
        self._client = claude_client
        self._enrichment = enrichment_service
        self._asset_lookup = asset_lookup
        self._max_iterations = max_iterations

    def investigate(self, case: Case, alerts_by_id: dict[UUID, Alert]) -> AgentResult:
        case_alerts = [alerts_by_id[aid] for aid in case.alert_ids]
        messages: list[dict] = [{"role": "user", "content": _build_case_prompt(case, case_alerts)}]
        trace: list[AgentTraceEntry] = []

        for iteration in range(1, self._max_iterations + 1):
            response = self._client.create_message(system=SYSTEM_PROMPT, messages=messages, tools=TOOL_DEFINITIONS)
            content = response.get("content", [])
            messages.append({"role": "assistant", "content": content})

            text_blocks = [b["text"] for b in content if b.get("type") == "text" and b.get("text")]
            tool_use_blocks = [b for b in content if b.get("type") == "tool_use"]

            entry = AgentTraceEntry(iteration=iteration, assistant_text="\n".join(text_blocks) or None)

            if not tool_use_blocks:
                trace.append(entry)
                messages.append(
                    {
                        "role": "user",
                        "content": "You must call the submit_verdict tool to provide your final structured "
                        "conclusion. Please do so now, using the evidence you've already gathered.",
                    }
                )
                continue

            tool_results: list[dict] = []
            verdict: Optional[Verdict] = None

            for block in tool_use_blocks:
                name = block["name"]
                tool_input = block.get("input", {}) or {}

                if name == "submit_verdict":
                    try:
                        verdict = Verdict.model_validate(tool_input)
                    except ValidationError as e:
                        tool_results.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": block["id"],
                                "content": f"Your submitted verdict was invalid: {e}. Please correct it and call submit_verdict again.",
                                "is_error": True,
                            }
                        )
                        entry.tool_calls.append(ToolCallRecord(name=name, input=tool_input, result={"error": "validation failed"}))
                        continue
                    entry.tool_calls.append(ToolCallRecord(name=name, input=tool_input, result={"accepted": True}))
                    continue

                result = self._dispatch_tool(name, tool_input)
                entry.tool_calls.append(ToolCallRecord(name=name, input=tool_input, result=result))
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block["id"], "content": json.dumps(result, default=str)}
                )

            trace.append(entry)

            if verdict is not None:
                return AgentResult(case_id=case.case_id, verdict=verdict, trace=trace, iterations=iteration)

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        raise AgentDidNotConverge(
            f"Agent did not submit a valid verdict within {self._max_iterations} iterations for case {case.case_id}"
        )

    def _dispatch_tool(self, name: str, tool_input: dict) -> dict:
        try:
            if name == "enrich_ip":
                return self._enrichment.enrich_ip(tool_input["ip"]).model_dump(mode="json")
            if name == "enrich_hash":
                return self._enrichment.enrich_hash(tool_input["sha256"]).model_dump(mode="json")
            if name == "get_asset_context":
                return self._asset_lookup(tool_input["hostname"])
            return {"error": f"Unknown tool '{name}'"}
        except Exception as e:  # noqa: BLE001 - a failing tool must degrade to an error result, never crash the loop
            return {"error": str(e)}


def _build_case_prompt(case: Case, case_alerts: list[Alert]) -> str:
    lines = [
        f"Case {case.case_id}: {len(case_alerts)} correlated alert(s) spanning {case.first_seen.isoformat()} to {case.last_seen.isoformat()}.",
        "",
        "Entities involved:",
    ]
    if case.hosts:
        lines.append(f"  Hosts: {', '.join(case.hosts)}")
    if case.users:
        lines.append(f"  Users: {', '.join(case.users)}")
    if case.ips:
        lines.append(f"  IPs: {', '.join(case.ips)}")
    if case.file_hashes:
        lines.append(f"  File hashes: {', '.join(case.file_hashes)}")

    lines += ["", "Alerts (chronological):"]
    for i, a in enumerate(case_alerts, 1):
        lines.append(f"{i}. [{a.occurred_at.isoformat()}] ({a.severity.value}) {a.rule_name} -- {a.description}")
        details = []
        for label, value in (
            ("host", a.host),
            ("user", a.user),
            ("src_ip", a.src_ip),
            ("dst_ip", a.dst_ip),
            ("process", a.process_name),
            ("cmdline", a.command_line),
            ("sha256", a.file_hash_sha256),
            ("mitre_hint", a.mitre_technique_hint),
        ):
            if value:
                details.append(f"{label}={value}")
        if details:
            lines.append("   " + ", ".join(details))

    lines += ["", "Investigate using the available tools, then call submit_verdict with your conclusion."]
    return "\n".join(lines)
