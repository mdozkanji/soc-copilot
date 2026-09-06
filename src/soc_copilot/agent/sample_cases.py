"""
Builds two illustrative (Case, AgentResult) examples from real project
data, for use anywhere a stand-in for a live agent run is needed while
live runs are blocked (devlog/0009-*.md): eval/generate_sample_reports.py
(renders them to Markdown) and api/seed.py (loads them into the UI's
result store).

This lives in the library, not in eval/, deliberately: eval/ is a
consumer of soc_copilot, and api/ is part of soc_copilot itself, so a
library module depending on a top-level eval/ script would be backwards.
Moved here in Week 7 specifically because api/seed.py needed the same
logic eval/generate_sample_reports.py already had.

Honesty note, worth repeating at every place this gets used: every piece
of evidence embedded in these examples is real -- the case comes from
actually running correlate() over the Week 1 sample data, the enrich_ip
evidence is the actual live VirusTotal/AbuseIPDB response captured in
devlog/0002-week2-enrichment.md, the asset context is the real
data/asset_inventory.json entry, and the search_mitre results are the
actual, unfiltered output of the Week 5 TF-IDF retriever. Only the Verdict
object itself is hand-authored, standing in for what a live model would
produce.
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_copilot.agent.assets import load_asset_inventory, make_asset_lookup
from soc_copilot.agent.models import AgentResult, AgentTraceEntry, RecommendedAction, ToolCallRecord, Verdict
from soc_copilot.correlate.cluster import correlate
from soc_copilot.correlate.models import Case
from soc_copilot.ingest.schema import Alert
from soc_copilot.rag.service import default_retriever

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_alerts_and_cases() -> tuple[list, dict]:
    alerts = [Alert.model_validate(a) for a in json.loads((REPO_ROOT / "data" / "normalized_alerts.json").read_text())]
    alerts_by_id = {a.alert_id: a for a in alerts}
    cases = correlate(alerts)
    return cases, alerts_by_id


def _load_case001() -> tuple[Case, dict]:
    cases, alerts_by_id = _load_alerts_and_cases()
    case = max(cases, key=lambda c: c.alert_count)  # the 8-alert intrusion chain
    return case, alerts_by_id


def build_malicious_example() -> tuple[Case, AgentResult]:
    case, alerts_by_id = _load_case001()
    case_alerts = [alerts_by_id[aid] for aid in case.alert_ids]

    # Real, live-captured VirusTotal + AbuseIPDB data for 185.220.101.47
    # from devlog/0002-week2-enrichment.md -- not fabricated.
    enrich_ip_result = {
        "ip": "185.220.101.47",
        "skipped": False,
        "sources": [
            {"source": "virustotal", "found": True, "malicious_votes": 15, "total_votes": 91, "country": "DE"},
            {
                "source": "abuseipdb",
                "found": True,
                "abuse_confidence_score": 100,
                "total_reports": 132,
                "is_tor": True,
                "country": "DE",
            },
        ],
        "source_errors": {},
        "likely_malicious_heuristic": True,
    }

    asset_lookup = make_asset_lookup(load_asset_inventory())
    asset_result = asset_lookup("WKS-EU-0231")  # real data/asset_inventory.json entry

    # Real search_mitre call per alert in the chain -- using the actual,
    # unfiltered TF-IDF retriever output, not cherry-picked. Consistent
    # with Week 5's documented retrieval limitations (devlog/0010-*.md):
    # only some of these come back as a strong match. A confidence
    # threshold, not a ground-truth lookup, decides what the verdict is
    # allowed to cite -- exactly the calibration Week 6 is about.
    retriever = default_retriever()
    STRONG_MATCH_THRESHOLD = 0.25
    mitre_calls = []
    strong_matches = []
    weak_matches = []
    for alert in case_alerts:
        query = f"{alert.rule_name}. {alert.description}"
        if alert.process_name:
            query += f" Process: {alert.process_name}"
        if alert.command_line:
            query += f" Command line: {alert.command_line}"
        top = retriever.search(query, k=1)[0]
        mitre_calls.append(ToolCallRecord(name="search_mitre", input={"query": query}, result={"results": [top.model_dump()]}))
        if top.score >= STRONG_MATCH_THRESHOLD:
            strong_matches.append((alert.source_alert_id, top))
        else:
            weak_matches.append((alert.source_alert_id, top))

    trace = [
        AgentTraceEntry(
            iteration=1,
            assistant_text="This case touches a Tor-exit IP and involves the account's own admin workstation. Checking reputation and asset context first.",
            tool_calls=[
                ToolCallRecord(name="enrich_ip", input={"ip": "185.220.101.47"}, result=enrich_ip_result),
                ToolCallRecord(name="get_asset_context", input={"hostname": "WKS-EU-0231"}, result=asset_result),
            ],
        ),
        AgentTraceEntry(
            iteration=2,
            assistant_text="Confirming a MITRE technique for each alert in the chain before citing any of them.",
            tool_calls=mitre_calls,
        ),
    ]

    strong_ids = [t.technique_id for _, t in strong_matches]
    weak_note = (
        "; ".join(f"{sid} scored only {t.score:.2f} for {t.technique_id} ({t.name})" for sid, t in weak_matches)
        if weak_matches
        else "none"
    )

    # Hand-authored, standing in for a live model's output -- see module
    # docstring. Deliberately cites only the technique IDs that scored
    # above STRONG_MATCH_THRESHOLD, and the reasoning explicitly discusses
    # the weak matches instead of silently dropping them.
    verdict = Verdict(
        severity="critical",
        confidence=88,
        evidence_sufficient=True,
        mitre_techniques=strong_ids,
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_URGENT,
        reasoning=(
            "This case is an 8-alert chain on WKS-EU-0231 spanning encoded PowerShell execution, DNS activity, "
            "SMB lateral movement, scheduled-task persistence, LSASS credential dumping, a PowerShell reverse "
            "shell, archive staging, and a large outbound transfer -- consistent with a full intrusion "
            "lifecycle on a single host rather than isolated noise. The destination IP 185.220.101.47 is "
            "confirmed malicious by both sources: VirusTotal flags it 15/91, and AbuseIPDB reports 100% abuse "
            "confidence with 132 reports and Tor-exit status. The affected host is not a routine workstation: "
            "asset context confirms it belongs to IT Operations with local admin rights on multiple servers, "
            "meaningfully raising the impact of compromise. Overall severity and recommended action are based "
            "primarily on the IP reputation, asset criticality, and the coherence of the alert chain itself, "
            "not on the MITRE mapping alone: search_mitre returned a confident match "
            f"(score >= {STRONG_MATCH_THRESHOLD}) for only {len(strong_ids)} of the chain's {len(case_alerts)} "
            f"alerts, listed below. The remaining alerts' technique mappings were too weak to cite with "
            f"confidence ({weak_note}) -- included here for transparency, not treated as confirmed."
        ),
        key_evidence=[
            "VirusTotal: 15/91 engines flag 185.220.101.47 as malicious",
            "AbuseIPDB: 100% abuse confidence, 132 reports, confirmed Tor exit node",
            "Asset context: WKS-EU-0231 has admin rights on multiple servers (IT Operations)",
        ]
        + [f"search_mitre confirmed {t.technique_id} ({t.name}) for {sid}, score {t.score:.2f}" for sid, t in strong_matches],
    )

    result = AgentResult(case_id=case.case_id, verdict=verdict, trace=trace, iterations=2)
    return case, result


def build_abstention_example() -> tuple[Case, AgentResult]:
    """edr-9003 (the 'unsigned installer' alert) was deliberately designed
    in Week 1 as a 'looks suspicious but isn't' case specifically to test
    whether the agent avoids over-triggering on surface-level suspicion --
    see docs/data-notes.md.

    Uses the REAL Case object correlate() actually produces for this
    alert, not a hand-constructed stand-in. An earlier version of this
    function built its own synthetic Case with a made-up case_id
    ("correlated-case-example") that correlate() would never actually
    assign -- harmless for rendering a standalone Markdown sample, but a
    real bug once api/seed.py needed this example to be look-up-able by
    the API's case_detail route, which finds cases via real correlate()
    output, not the store. Fixed by deriving the case directly from the
    real pipeline instead of guessing its shape.
    """
    cases, alerts_by_id = _load_alerts_and_cases()
    alert = next(a for a in alerts_by_id.values() if a.source_alert_id == "edr-9003")
    case = next(c for c in cases if alert.alert_id in c.alert_ids)

    asset_lookup = make_asset_lookup(load_asset_inventory())
    asset_result = asset_lookup("WKS-EU-0450")  # real data/asset_inventory.json entry

    # Genuine, realistic shape for "VT has no data on this hash" -- not
    # fabricated detection numbers, since this alert has none in reality either.
    enrich_hash_result = {"sha256": alert.file_hash_sha256, "source": "virustotal", "found": False}

    trace = [
        AgentTraceEntry(
            iteration=1,
            assistant_text="Unsigned binary from a temp directory is ambiguous on its own -- checking hash reputation and asset context before concluding anything.",
            tool_calls=[
                ToolCallRecord(name="enrich_hash", input={"sha256": alert.file_hash_sha256}, result=enrich_hash_result),
                ToolCallRecord(name="get_asset_context", input={"hostname": "WKS-EU-0450"}, result=asset_result),
            ],
        )
    ]

    verdict = Verdict(
        severity="informational",
        confidence=25,
        evidence_sufficient=False,
        mitre_techniques=[],
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_ANALYST,
        reasoning=(
            "The only concrete signal is that the binary is unsigned and ran from a Downloads/Temp directory, "
            "which is common for both legitimate installers and malware droppers -- not distinguishing on its "
            "own. VirusTotal has no record of this file hash at all (found=false), which is genuinely "
            "ambiguous: it could mean the file is new/rare (consistent with either a fresh legitimate tool or "
            "unseen malware), not evidence in either direction. The asset is a standard Finance workstation "
            "with no elevated privileges, which caps the plausible impact but doesn't resolve whether this is "
            "malicious. There is no network, persistence, or lateral-movement signal in this alert to "
            "corroborate a malicious read, but there is also no user or business context confirming this was "
            "an expected/approved installation. Recommending human review rather than a confident call either way."
        ),
        key_evidence=[],
    )

    result = AgentResult(case_id=case.case_id, verdict=verdict, trace=trace, iterations=1)
    return case, result
