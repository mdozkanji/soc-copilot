"""
Run correlation over data/normalized_alerts.json and print a human-readable
case summary.

Usage:
    python -m soc_copilot.correlate.cli
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_copilot.correlate.cluster import correlate
from soc_copilot.ingest.schema import Alert

REPO_ROOT = Path(__file__).resolve().parents[3]
NORMALIZED_PATH = REPO_ROOT / "data" / "normalized_alerts.json"


def main() -> None:
    raw = json.loads(NORMALIZED_PATH.read_text())
    alerts = [Alert.model_validate(a) for a in raw]
    cases = correlate(alerts)

    print(f"{len(alerts)} alerts -> {len(cases)} cases\n")
    for case in cases:
        span = case.last_seen - case.first_seen
        print(f"{case.case_id}  ({case.alert_count} alert{'s' if case.alert_count != 1 else ''}, span {span})")
        print(f"  source_alert_ids: {', '.join(case.source_alert_ids)}")
        if case.hosts:
            print(f"  hosts: {', '.join(case.hosts)}")
        if case.users:
            print(f"  users: {', '.join(case.users)}")
        if case.ips:
            print(f"  ips: {', '.join(case.ips)}")
        if case.file_hashes:
            print(f"  file_hashes: {', '.join(h[:12] + '...' for h in case.file_hashes)}")
        if case.link_reasons:
            print(f"  linked by: {'; '.join(case.link_reasons)}")
        print()


if __name__ == "__main__":
    main()
