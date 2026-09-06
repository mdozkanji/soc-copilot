"""
Two small, separate stores, deliberately not one:

AgentResultStore holds a (Case, AgentResult) pair per case_id -- one JSON
file per case under a directory. This project's live agent runs are
currently blocked (devlog/0009-*.md), so what's actually stored here today
is the two Week 6 illustrative examples (seed.py), not fresh live output.
The store itself doesn't know or care where a result came from -- once
live runs are unblocked, populating it for real is a matter of calling
.save() after agent.investigate(), not a schema change.

FeedbackStore is the actual point of this week: every analyst decision
(accept or override) gets appended to a JSONL log, one line per review,
each entry self-contained (it snapshots the verdict at review time rather
than pointing at a case_id and hoping the underlying data doesn't change
later). This log matters more than any single accuracy number this
project could report -- it's the first real signal about where the
agent's calibration actually needs work, and it's the dataset a future
"does the agent's confidence track analyst agreement" analysis would
run against. An empty log is a legitimate starting state, not a bug.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from soc_copilot.agent.models import AgentResult
from soc_copilot.correlate.models import Case

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RESULTS_DIR = REPO_ROOT / "data" / "agent_results"
DEFAULT_FEEDBACK_PATH = REPO_ROOT / "data" / "feedback_log.jsonl"


class AgentResultStore:
    def __init__(self, results_dir: Path = DEFAULT_RESULTS_DIR):
        self._dir = results_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, case: Case, result: AgentResult) -> None:
        payload = {"case": json.loads(case.model_dump_json()), "result": json.loads(result.model_dump_json())}
        (self._dir / f"{case.case_id}.json").write_text(json.dumps(payload, indent=2))

    def load(self, case_id: str) -> Optional[tuple[Case, AgentResult]]:
        path = self._dir / f"{case_id}.json"
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        return Case.model_validate(payload["case"]), AgentResult.model_validate(payload["result"])

    def all_case_ids(self) -> set[str]:
        return {p.stem for p in self._dir.glob("*.json")}


class FeedbackStore:
    def __init__(self, path: Path = DEFAULT_FEEDBACK_PATH):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        case_id: str,
        decision: str,
        verdict_snapshot: dict,
        reason: Optional[str] = None,
        corrected_severity: Optional[str] = None,
        corrected_action: Optional[str] = None,
    ) -> dict:
        entry = {
            "case_id": case_id,
            "decision": decision,
            "reason": reason,
            "corrected_severity": corrected_severity,
            "corrected_action": corrected_action,
            "verdict_snapshot": verdict_snapshot,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        with self._path.open() as f:
            return [json.loads(line) for line in f if line.strip()]

    def latest_decision_for(self, case_id: str) -> Optional[dict]:
        matching = [e for e in self.read_all() if e["case_id"] == case_id]
        return matching[-1] if matching else None
