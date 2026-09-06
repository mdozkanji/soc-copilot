"""
Generates the sample investigation reports in eval/samples/.

The actual (Case, AgentResult)-building logic lives in
soc_copilot.agent.sample_cases -- shared with api/seed.py, which needs the
exact same real-data examples to seed the Week 7 review UI. This module is
just the Markdown-rendering wrapper.

Run with: python -m eval.generate_sample_reports
"""

from __future__ import annotations

from pathlib import Path

from soc_copilot.agent.sample_cases import build_abstention_example, build_malicious_example
from soc_copilot.agent.summary import render_summary

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "eval" / "samples"

HONESTY_HEADER = """> **Note:** live agent runs are currently blocked (see `devlog/0009-pausing-live-agent-verification.md`).
> Every piece of evidence in this report is real project data -- the case is from actually running
> `correlate()`, enrichment figures are real live results (VirusTotal/AbuseIPDB from
> `devlog/0002-week2-enrichment.md`, or a real `found: false` VirusTotal response where applicable), asset
> context is the real `data/asset_inventory.json` entry, and any MITRE match is the real Week 5 TF-IDF
> retriever's actual output for that exact query -- not cherry-picked. Only the verdict itself (severity,
> confidence, reasoning, recommended action) is hand-authored, standing in for what a live model would
> produce, so the *report format* can be reviewed now.

---

"""


def generate_malicious_example() -> str:
    case, result = build_malicious_example()
    return HONESTY_HEADER + render_summary(result, case)


def generate_abstention_example() -> str:
    case, result = build_abstention_example()
    return HONESTY_HEADER + render_summary(result, case)


def main() -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    (SAMPLES_DIR / "example-malicious-intrusion-chain.md").write_text(generate_malicious_example())
    (SAMPLES_DIR / "example-abstention-ambiguous-installer.md").write_text(generate_abstention_example())

    print(f"Wrote 2 sample reports to {SAMPLES_DIR}")


if __name__ == "__main__":
    main()
