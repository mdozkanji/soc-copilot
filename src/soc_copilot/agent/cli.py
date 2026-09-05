"""
Run the agent end-to-end over a real case from the sample dataset.

Usage:
    python -m soc_copilot.agent.cli                      # picks the largest case
    python -m soc_copilot.agent.cli --source-id sig-0001  # picks the case containing this alert

Requires GROQ_API_KEY -- free, no credit card required: https://console.groq.com/keys.
Enrichment API keys (VT_API_KEY / ABUSEIPDB_API_KEY) are optional -- if
neither is set, enrich_ip/enrich_hash tool calls will come back as errors,
which the agent is expected to reason about honestly rather than crash on
(see loop.py).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from soc_copilot.agent.assets import load_asset_inventory, make_asset_lookup
from soc_copilot.agent.groq_client import GroqClient
from soc_copilot.agent.loop import AgentDidNotConverge, SocAnalystAgent
from soc_copilot.agent.summary import render_summary
from soc_copilot.correlate.cluster import correlate
from soc_copilot.enrich.service import EnrichmentService
from soc_copilot.ingest.schema import Alert
from soc_copilot.rag.service import default_retriever

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

REPO_ROOT = Path(__file__).resolve().parents[3]
NORMALIZED_PATH = REPO_ROOT / "data" / "normalized_alerts.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SOC copilot agent over one case from the sample dataset.")
    parser.add_argument("--source-id", help="Pick the case containing this source_alert_id (e.g. sig-0001).")
    parser.add_argument("--verbose", action="store_true", help="Also print the raw iteration-by-iteration trace before the summary report.")
    args = parser.parse_args()

    raw = json.loads(NORMALIZED_PATH.read_text())
    alerts = [Alert.model_validate(a) for a in raw]
    alerts_by_id = {a.alert_id: a for a in alerts}
    cases = correlate(alerts)

    if args.source_id:
        case = next((c for c in cases if args.source_id in c.source_alert_ids), None)
        if case is None:
            raise SystemExit(f"No case contains source_alert_id={args.source_id!r}")
    else:
        case = max(cases, key=lambda c: c.alert_count)  # the biggest case is the most interesting demo by default

    print(f"Investigating {case.case_id} ({case.alert_count} alerts: {', '.join(case.source_alert_ids)})\n")

    try:
        enrichment = EnrichmentService.from_env()
    except RuntimeError as e:
        print(f"[warning] {e} Enrichment tools will return errors the agent must reason around.\n")
        enrichment = EnrichmentService()

    asset_lookup = make_asset_lookup(load_asset_inventory())
    llm_client = GroqClient.from_env()
    retriever = default_retriever()
    agent = SocAnalystAgent(
        llm_client=llm_client, enrichment_service=enrichment, asset_lookup=asset_lookup, retriever=retriever
    )

    try:
        result = agent.investigate(case, alerts_by_id)
    except AgentDidNotConverge as e:
        print(f"AGENT DID NOT CONVERGE: {e}")
        return

    if args.verbose:
        for entry in result.trace:
            print(f"--- iteration {entry.iteration} ---")
            if entry.assistant_text:
                print(f"[reasoning] {entry.assistant_text}")
            for call in entry.tool_calls:
                print(f"  tool: {call.name}({call.input})")
                print(f"    -> {json.dumps(call.result, default=str)[:300]}")
            print()

    print(render_summary(result, case))


if __name__ == "__main__":
    main()
