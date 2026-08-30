"""
Load every raw sample source, normalize it, and write out one combined,
normalized alert set.

Run with:
    python -m soc_copilot.ingest.load_samples

This is intentionally a thin script — the real logic lives in normalize.py
and is unit-tested directly. This file exists so there's one obvious,
reproducible command that regenerates data/normalized_alerts.json whenever
a raw sample or a normalizer changes, rather than that file drifting out of
sync with its inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_copilot.ingest.normalize import normalize
from soc_copilot.ingest.schema import Alert, AlertSource

REPO_ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = REPO_ROOT / "data" / "raw_samples"
OUT_PATH = REPO_ROOT / "data" / "normalized_alerts.json"

# Maps each raw sample filename to the AlertSource it should be normalized as.
_SOURCE_FILES: dict[str, AlertSource] = {
    "sigma_synthetic.json": AlertSource.SIGMA_SYNTHETIC,
    "edr_synthetic.json": AlertSource.EDR_SYNTHETIC,
}


def load_all() -> list[Alert]:
    alerts: list[Alert] = []
    for filename, source in _SOURCE_FILES.items():
        path = RAW_DIR / filename
        raw_records = json.loads(path.read_text())
        for raw in raw_records:
            alerts.append(normalize(raw, source))
    # Stable ordering makes diffs of the generated file meaningful in git.
    alerts.sort(key=lambda a: a.occurred_at)
    return alerts


def main() -> None:
    alerts = load_all()
    OUT_PATH.write_text(
        json.dumps([json.loads(a.model_dump_json()) for a in alerts], indent=2, default=str)
    )
    print(f"Normalized {len(alerts)} alerts from {len(_SOURCE_FILES)} sources -> {OUT_PATH}")


if __name__ == "__main__":
    main()
