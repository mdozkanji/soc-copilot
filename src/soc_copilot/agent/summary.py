"""
Renders an AgentResult into a human-readable investigation report -- the
kind an analyst reviewing dozens of these a day would actually want to
read: case overview, the evidence actually gathered, the verdict, and any
grounding-audit warnings (audit.py).

Deliberately NOT the full raw trace dumped verbatim. An analyst doesn't
need a blow-by-blow of every intermediate LLM turn; they need what was
found and what it means. The full trace stays available on the
AgentResult object itself for anyone who wants to audit deeper -- this is
the summary someone reads first, not the only record kept.
"""

from __future__ import annotations

import json

from soc_copilot.agent.audit import audit_verdict
from soc_copilot.agent.models import AgentResult
from soc_copilot.correlate.models import Case


def render_summary(result: AgentResult, case: Case) -> str:
    lines: list[str] = []
    v = result.verdict

    lines.append(f"# Investigation Report — {result.case_id}")
    lines.append("")
    lines.append(
        f"**{case.alert_count} alert(s)**, {case.first_seen.isoformat()} to {case.last_seen.isoformat()} "
        f"· investigated in {result.iterations} iteration(s)"
    )
    lines.append("")
    if case.hosts:
        lines.append(f"- **Hosts**: {', '.join(case.hosts)}")
    if case.users:
        lines.append(f"- **Users**: {', '.join(case.users)}")
    if case.ips:
        lines.append(f"- **IPs**: {', '.join(case.ips)}")
    if case.file_hashes:
        lines.append(f"- **File hashes**: {', '.join(h[:16] + '...' for h in case.file_hashes)}")
    lines.append("")

    lines.append("## Verdict")
    lines.append("")
    confidence_note = "" if v.evidence_sufficient else " — evidence marked **insufficient**"
    lines.append(f"**{v.severity.value.upper()}** · confidence {v.confidence}/100{confidence_note}")
    lines.append("")
    lines.append(f"**Recommended action**: {v.recommended_action.value.replace('_', ' ')}")
    if v.mitre_techniques:
        lines.append(f"**MITRE ATT&CK**: {', '.join(v.mitre_techniques)}")
    lines.append("")
    lines.append(v.reasoning)
    lines.append("")

    if v.key_evidence:
        lines.append("### Key evidence")
        for item in v.key_evidence:
            lines.append(f"- {item}")
        lines.append("")

    investigative_calls = [
        call for entry in result.trace for call in entry.tool_calls if call.name != "submit_verdict"
    ]
    if investigative_calls:
        lines.append("## Evidence gathered")
        lines.append("")
        for call in investigative_calls:
            summary = _summarize_tool_result(call.name, call.result)
            lines.append(f"- **{call.name}**({_format_input(call.input)}): {summary}")
        lines.append("")

    warnings = audit_verdict(result)
    if warnings:
        lines.append("## ⚠ Automated consistency check")
        lines.append("")
        lines.append(
            "The checks below flag verdict claims that don't appear to be backed by this trace. "
            "This is not a correctness check -- it's a narrower, cheap check for internal consistency."
        )
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines)


def _format_input(tool_input: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in tool_input.items())


def _summarize_tool_result(tool_name: str, result) -> str:
    if not isinstance(result, dict):
        return str(result)
    if "error" in result:
        return f"error -- {result['error']}"
    if tool_name == "enrich_ip":
        if result.get("skipped"):
            return f"skipped ({result.get('skip_reason')})"
        sources = result.get("sources", [])
        if not sources:
            return "no source data"
        parts = []
        for s in sources:
            if s.get("source") == "virustotal" and s.get("found"):
                parts.append(f"VT {s.get('malicious_votes')}/{s.get('total_votes')} malicious")
            elif s.get("source") == "abuseipdb" and s.get("found"):
                parts.append(f"AbuseIPDB {s.get('abuse_confidence_score')}% confidence")
        return "; ".join(parts) if parts else "no data from configured sources"
    if tool_name == "enrich_hash":
        if not result.get("found"):
            return "not found in VirusTotal"
        return f"VT {result.get('malicious_detections')}/{result.get('total_engines')} malicious"
    if tool_name == "get_asset_context":
        if not result.get("found"):
            return "not in asset inventory"
        return f"{result.get('criticality', '?')}-criticality, owner={result.get('owner', '?')}"
    if tool_name == "search_mitre":
        top = (result.get("results") or [None])[0]
        if not top:
            return "no matches"
        return f"top match {top.get('technique_id')} {top.get('name')} (score {top.get('score', 0):.2f})"
    return json.dumps(result)[:150]
