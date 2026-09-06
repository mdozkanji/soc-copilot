"""
Seeds data/agent_results/ with the two Week 6 illustrative examples
(devlog/0011-*.md) via soc_copilot.agent.sample_cases -- the same
real-data construction logic eval/generate_sample_reports.py uses to
render these as Markdown. Live agent runs are blocked (devlog/0009-*.md),
so this is what the UI has to show today; once that's unblocked, real
cases get populated by calling AgentResultStore.save() after
agent.investigate(), and this seed script stops being the only source of
data in the store.

Run with: python -m soc_copilot.api.seed
"""

from __future__ import annotations

from soc_copilot.agent.sample_cases import build_abstention_example, build_malicious_example
from soc_copilot.api.store import AgentResultStore


def main() -> None:
    store = AgentResultStore()

    case, result = build_malicious_example()
    store.save(case, result)

    case, result = build_abstention_example()
    store.save(case, result)

    print(f"Seeded {len(store.all_case_ids())} stored investigation(s).")


if __name__ == "__main__":
    main()
