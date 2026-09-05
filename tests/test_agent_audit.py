from soc_copilot.agent.audit import audit_verdict
from soc_copilot.agent.models import AgentResult, AgentTraceEntry, RecommendedAction, ToolCallRecord, Verdict
from soc_copilot.ingest.schema import Severity


def _result(verdict: Verdict, trace: list[AgentTraceEntry]) -> AgentResult:
    return AgentResult(case_id="test-case", verdict=verdict, trace=trace, iterations=len(trace))


def _verdict(**overrides) -> Verdict:
    defaults = dict(
        severity=Severity.MEDIUM,
        confidence=50,
        evidence_sufficient=True,
        mitre_techniques=[],
        recommended_action=RecommendedAction.RECOMMEND_MONITOR,
        reasoning="Some reasoning.",
        key_evidence=[],
    )
    defaults.update(overrides)
    return Verdict(**defaults)


# --------------------------------------------------------------------------
# high confidence without supporting tool calls
# --------------------------------------------------------------------------

def test_flags_high_confidence_with_no_successful_tool_calls():
    verdict = _verdict(confidence=90)
    trace = [AgentTraceEntry(iteration=1, tool_calls=[])]
    warnings = audit_verdict(_result(verdict, trace))
    assert any("no investigative tool call" in w for w in warnings)


def test_does_not_flag_high_confidence_backed_by_a_successful_call():
    verdict = _verdict(confidence=90)
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[ToolCallRecord(name="enrich_ip", input={"ip": "1.2.3.4"}, result={"found": True})],
        )
    ]
    warnings = audit_verdict(_result(verdict, trace))
    assert not any("no investigative tool call" in w for w in warnings)


def test_does_not_flag_low_confidence_with_no_tool_calls():
    verdict = _verdict(confidence=20, evidence_sufficient=False, recommended_action=RecommendedAction.RECOMMEND_ESCALATE_ANALYST)
    trace = [AgentTraceEntry(iteration=1, tool_calls=[])]
    warnings = audit_verdict(_result(verdict, trace))
    assert not any("no investigative tool call" in w for w in warnings)


def test_a_tool_call_that_errored_does_not_count_as_grounding():
    """An enrich_ip call that came back with {'error': ...} isn't
    supporting evidence -- confidence built on top of a failed lookup
    should still be flagged."""
    verdict = _verdict(confidence=90)
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[ToolCallRecord(name="enrich_ip", input={"ip": "1.2.3.4"}, result={"error": "VT down"})],
        )
    ]
    warnings = audit_verdict(_result(verdict, trace))
    assert any("no investigative tool call" in w for w in warnings)


# --------------------------------------------------------------------------
# MITRE citation without search_mitre
# --------------------------------------------------------------------------

def test_flags_mitre_citation_without_any_search_mitre_call():
    verdict = _verdict(mitre_techniques=["T1059.001"])
    trace = [AgentTraceEntry(iteration=1, tool_calls=[])]
    warnings = audit_verdict(_result(verdict, trace))
    assert any("T1059.001" in w and "search_mitre" in w for w in warnings)


def test_does_not_flag_mitre_citation_actually_confirmed_by_search_mitre():
    verdict = _verdict(mitre_techniques=["T1059.001"])
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[
                ToolCallRecord(
                    name="search_mitre",
                    input={"query": "x"},
                    result={"results": [{"technique_id": "T1059.001", "name": "PowerShell"}]},
                )
            ],
        )
    ]
    warnings = audit_verdict(_result(verdict, trace))
    assert not any("search_mitre" in w for w in warnings)


def test_flags_only_the_specific_techniques_never_confirmed():
    """Real gap this test locks in: confirming ONE cited technique via
    search_mitre must not silently vouch for every other technique cited
    alongside it. Found by testing the auditor against a realistic
    multi-technique verdict (see devlog/0011-*.md) -- the original version
    of this check only asked 'was search_mitre called at all,' which this
    exact scenario slipped past."""
    verdict = _verdict(mitre_techniques=["T1059.001", "T1021.002", "T1003"])
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[
                ToolCallRecord(
                    name="search_mitre",
                    input={"query": "x"},
                    result={"results": [{"technique_id": "T1059.001", "name": "PowerShell"}]},
                )
            ],
        )
    ]
    warnings = audit_verdict(_result(verdict, trace))
    mitre_warnings = [w for w in warnings if "search_mitre" in w]
    assert len(mitre_warnings) == 1
    assert "T1021.002" in mitre_warnings[0]
    assert "T1003" in mitre_warnings[0]
    assert "T1059.001" not in mitre_warnings[0]  # this one WAS confirmed -- must not be flagged


# --------------------------------------------------------------------------
# key_evidence figures without enrichment
# --------------------------------------------------------------------------

def test_flags_key_evidence_figures_without_enrichment_call():
    verdict = _verdict(key_evidence=["VirusTotal: 15/91 engines flagged this IP as malicious"])
    trace = [AgentTraceEntry(iteration=1, tool_calls=[])]
    warnings = audit_verdict(_result(verdict, trace))
    assert any("figure" in w for w in warnings)


def test_does_not_flag_key_evidence_figures_backed_by_enrichment():
    verdict = _verdict(key_evidence=["VirusTotal: 15/91 engines flagged this IP as malicious"])
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[ToolCallRecord(name="enrich_ip", input={"ip": "1.2.3.4"}, result={"found": True})],
        )
    ]
    warnings = audit_verdict(_result(verdict, trace))
    assert not any("figure" in w for w in warnings)


def test_does_not_flag_key_evidence_with_no_figures():
    verdict = _verdict(key_evidence=["The host is a high-criticality admin workstation."])
    trace = [AgentTraceEntry(iteration=1, tool_calls=[])]
    warnings = audit_verdict(_result(verdict, trace))
    assert not any("figure" in w for w in warnings)


# --------------------------------------------------------------------------
# low-confidence benign close
# --------------------------------------------------------------------------

def test_flags_low_confidence_close_benign():
    verdict = _verdict(confidence=30, recommended_action=RecommendedAction.RECOMMEND_CLOSE_BENIGN)
    warnings = audit_verdict(_result(verdict, [AgentTraceEntry(iteration=1, tool_calls=[])]))
    assert any("closing as benign" in w for w in warnings)


def test_does_not_flag_high_confidence_close_benign():
    verdict = _verdict(confidence=85, recommended_action=RecommendedAction.RECOMMEND_CLOSE_BENIGN)
    warnings = audit_verdict(_result(verdict, [AgentTraceEntry(iteration=1, tool_calls=[])]))
    assert not any("closing as benign" in w for w in warnings)


# --------------------------------------------------------------------------
# clean verdict, no warnings
# --------------------------------------------------------------------------

def test_well_grounded_verdict_produces_no_warnings():
    verdict = _verdict(
        confidence=85,
        mitre_techniques=["T1059.001"],
        key_evidence=["VirusTotal: 15/91 engines flagged this IP as malicious"],
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_URGENT,
    )
    trace = [
        AgentTraceEntry(
            iteration=1,
            tool_calls=[
                ToolCallRecord(name="enrich_ip", input={"ip": "1.2.3.4"}, result={"found": True}),
                ToolCallRecord(
                    name="search_mitre",
                    input={"query": "x"},
                    result={"results": [{"technique_id": "T1059.001", "name": "PowerShell"}]},
                ),
            ],
        )
    ]
    assert audit_verdict(_result(verdict, trace)) == []
