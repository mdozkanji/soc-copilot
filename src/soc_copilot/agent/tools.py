"""
Tool definitions (name / description / JSON input_schema) shared across
whatever LLM provider is in use. This shape is intentionally close to
plain JSON Schema rather than any one vendor's wire format -- each
provider-specific client (see groq_client.py) is responsible for
translating it into whatever shape its own API actually expects (e.g.
Groq wraps each entry in {"type": "function", "function": {...,
"parameters": ...}}).

submit_verdict is a tool like any other, not a special case at the API
level -- but it's the mechanism the whole structured-output design relies
on: the agent loop (loop.py) treats a call to submit_verdict as the signal
to stop investigating, and its `input` (validated against
agent.models.Verdict) IS the final answer. This is a deliberate
alternative to asking the model to emit JSON in free text and hoping it
parses -- tool-call input is schema-constrained by the provider's API
itself, and it lets a single mechanism (tool calls) drive both "gather
more evidence" and "conclude."
"""

from __future__ import annotations

from soc_copilot.agent.models import RecommendedAction
from soc_copilot.ingest.schema import Severity

ENRICH_IP_TOOL = {
    "name": "enrich_ip",
    "description": (
        "Look up reputation data for an IP address from VirusTotal and AbuseIPDB. "
        "For private/internal IP addresses (RFC1918, loopback, etc.), this returns "
        "a 'skipped' result instead of querying external services -- external threat "
        "intel has no data on your internal network, so this is expected, not an error."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"ip": {"type": "string", "description": "The IPv4 or IPv6 address to look up."}},
        "required": ["ip"],
    },
}

ENRICH_HASH_TOOL = {
    "name": "enrich_hash",
    "description": "Look up reputation data for a file's SHA-256 hash from VirusTotal (detection count, known malware family names, first-seen date).",
    "input_schema": {
        "type": "object",
        "properties": {"sha256": {"type": "string", "description": "The 64-character hex SHA-256 hash."}},
        "required": ["sha256"],
    },
}

GET_ASSET_CONTEXT_TOOL = {
    "name": "get_asset_context",
    "description": (
        "Look up business context for an internal hostname: owner, department, "
        "criticality, and any relevant notes (e.g. admin privileges). Use this to "
        "judge how sensitive an affected asset is -- the same technical finding on "
        "a low-criticality kiosk vs. a high-criticality admin workstation can "
        "warrant a different severity."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"hostname": {"type": "string"}},
        "required": ["hostname"],
    },
}

SEARCH_MITRE_TOOL = {
    "name": "search_mitre",
    "description": (
        "Search the real MITRE ATT&CK Enterprise technique corpus for techniques matching "
        "a description of observed behavior. Use this to confirm a specific technique ID "
        "and its official name/description before citing it -- do not rely on your own "
        "memory of ATT&CK IDs, which can be wrong, outdated, or refer to a technique that's "
        "since been deprecated or restructured. Returns the top-k matches ranked by relevance."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "A description of the observed behavior, e.g. an alert's rule name and description.",
            },
            "k": {"type": "integer", "description": "Number of results to return (default 5).", "default": 5},
        },
        "required": ["query"],
    },
}

SUBMIT_VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": (
        "Submit your final triage verdict for this case. Call this exactly once, "
        "as your last action, after you've gathered enough evidence via the other "
        "tools (or concluded that evidence is insufficient). This ends the investigation."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": [s.value for s in Severity],
                "description": "Your own severity assessment -- may differ from the source alerts' reported severity.",
            },
            "confidence": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100,
                "description": "Your confidence in this verdict, 0-100. Low confidence is a valid, honest answer.",
            },
            "mitre_techniques": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK technique IDs supported by the evidence you gathered, e.g. ['T1059.001']. Leave empty if none clearly apply.",
            },
            "recommended_action": {
                "type": "string",
                "enum": [a.value for a in RecommendedAction],
                "description": "What you think a human analyst should do next. You are not taking this action yourself.",
            },
            "reasoning": {
                "type": "string",
                "description": "Your justification, referencing the specific evidence you gathered via tool calls.",
            },
            "key_evidence": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Short, specific citations of your strongest evidence, e.g. 'VirusTotal: 15/91 engines flag this IP as malicious'.",
            },
        },
        "required": ["severity", "confidence", "recommended_action", "reasoning"],
    },
}

TOOL_DEFINITIONS = [ENRICH_IP_TOOL, ENRICH_HASH_TOOL, GET_ASSET_CONTEXT_TOOL, SEARCH_MITRE_TOOL, SUBMIT_VERDICT_TOOL]
