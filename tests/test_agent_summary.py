from datetime import datetime, timezone

from soc_copilot.agent.models import AgentResult, AgentTraceEntry, RecommendedAction, ToolCallRecord, Verdict
from soc_copilot.agent.summary import render_summary
from soc_copilot.correlate.models import Case
from soc_copilot.ingest.schema import Severity


def _case(**overrides) -> Case:
    defaults = dict(
        case_id="correlated-case-001",
        alert_ids=[],
        source_alert_ids=["sig-0001"],
        first_seen=datetime(2026, 8, 20, 14, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 8, 20, 14, 20, tzinfo=timezone.utc),
        hosts=["WKS-EU-0231"],
        users=["jsmith"],
        ips=["185.220.101.47"],
        file_hashes=[],
    )
    defaults.update(overrides)
    return Case(**defaults)


def _verdict(**overrides) -> Verdict:
    defaults = dict(
        severity=Severity.HIGH,
        confidence=90,
        evidence_sufficient=True,
        mitre_techniques=["T1059.001"],
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_URGENT,
        reasoning="Strong evidence of a Tor-exit C2 connection.",
        key_evidence=["VirusTotal: 15/91 engines flagged this IP as malicious"],
    )
    defaults.update(overrides)
    return Verdict(**defaults)


def test_summary_includes_case_id_and_core_verdict_fields():
    result = AgentResult(case_id="correlated-case-001", verdict=_verdict(), trace=[], iterations=1)
    summary = render_summary(result, _case())
    assert "correlated-case-001" in summary
    assert "HIGH" in summary
    assert "90/100" in summary
    assert "recommend escalate urgent" in summary
    assert "T1059.001" in summary


def test_summary_marks_insufficient_evidence_clearly():
    verdict = _verdict(
        confidence=20,
        evidence_sufficient=False,
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_ANALYST,
        mitre_techniques=[],
    )
    result = AgentResult(case_id="c", verdict=verdict, trace=[], iterations=1)
    summary = render_summary(result, _case())
    assert "insufficient" in summary.lower()


def test_summary_renders_key_evidence_bullets():
    result = AgentResult(case_id="c", verdict=_verdict(), trace=[], iterations=1)
    summary = render_summary(result, _case())
    assert "- VirusTotal: 15/91 engines flagged this IP as malicious" in summary


def test_summary_summarizes_enrich_ip_result():
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[
                ToolCallRecord(
                    name="enrich_ip",
                    input={"ip": "185.220.101.47"},
                    result={
                        "sources": [
                            {"source": "virustotal", "found": True, "malicious_votes": 15, "total_votes": 91},
                            {"source": "abuseipdb", "found": True, "abuse_confidence_score": 100},
                        ]
                    },
                )
            ],
        )
    ]
    result = AgentResult(case_id="c", verdict=_verdict(), trace=trace, iterations=1)
    summary = render_summary(result, _case())
    assert "VT 15/91 malicious" in summary
    assert "AbuseIPDB 100% confidence" in summary


def test_summary_summarizes_skipped_enrich_ip():
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[
                ToolCallRecord(
                    name="enrich_ip",
                    input={"ip": "10.0.0.1"},
                    result={"skipped": True, "skip_reason": "private address"},
                )
            ],
        )
    ]
    result = AgentResult(case_id="c", verdict=_verdict(), trace=trace, iterations=1)
    summary = render_summary(result, _case())
    assert "skipped (private address)" in summary


def test_summary_summarizes_tool_error():
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[ToolCallRecord(name="enrich_hash", input={"sha256": "a" * 64}, result={"error": "VT down"})],
        )
    ]
    result = AgentResult(case_id="c", verdict=_verdict(), trace=trace, iterations=1)
    summary = render_summary(result, _case())
    assert "error -- VT down" in summary


def test_summary_excludes_submit_verdict_from_evidence_gathered():
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[ToolCallRecord(name="submit_verdict", input={}, result={"accepted": True})],
        )
    ]
    result = AgentResult(case_id="c", verdict=_verdict(), trace=trace, iterations=1)
    summary = render_summary(result, _case())
    assert "## Evidence gathered" not in summary


def test_summary_includes_audit_warnings_section_when_present():
    # high confidence, no tool calls at all -> auditor should flag it
    result = AgentResult(case_id="c", verdict=_verdict(confidence=95), trace=[], iterations=1)
    summary = render_summary(result, _case())
    assert "Automated consistency check" in summary


def test_summary_omits_audit_section_when_no_warnings():
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[
                ToolCallRecord(name="enrich_ip", input={"ip": "185.220.101.47"}, result={"sources": [{"source": "virustotal", "found": True, "malicious_votes": 15, "total_votes": 91}]}),
                ToolCallRecord(name="search_mitre", input={"query": "x"}, result={"results": [{"technique_id": "T1059.001", "name": "PowerShell", "score": 0.9}]}),
            ],
        )
    ]
    result = AgentResult(case_id="c", verdict=_verdict(), trace=trace, iterations=1)
    summary = render_summary(result, _case())
    assert "Automated consistency check" not in summary
