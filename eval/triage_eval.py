"""
Full triage evaluation: precision, recall, false-negative rate, and
abstention rate for agent verdicts against eval/labels.json ground truth.

Status, stated plainly: the harness below is complete and thoroughly unit
tested (tests/test_triage_eval.py) against synthetic verdicts covering
every classification path. Running it against real agent output across
the whole 16-alert labeled set is blocked -- that requires a working live
LLM integration, and Groq's free tier has not been made to work reliably
for this workload (devlog/0009-pausing-live-agent-verification.md). This
is the measurement instrument, built and verified; the measurement itself
is what's waiting on an unblocked live model. `main()` below runs it
against whatever IS in AgentResultStore today -- currently the two Week 6
illustrative examples -- and says so explicitly rather than presenting
that as a real evaluation result.

Methodology, stated explicitly rather than left implicit (see docs/data
-notes.md and eval/retrieval_eval.py for the same practice elsewhere in
this project -- an eval whose scoring rules are hidden is not
trustworthy, whether or not the hiding is deliberate):

- Ground truth is per-alert in eval/labels.json but this harness scores
  per-CASE, since that's the actual unit of agent output. A case's true
  label is the ground_truth of any of its alerts -- safe because Week 3's
  cluster-purity tests (test_correlate.py) guarantee no case mixes benign
  and malicious alerts. This harness re-checks that invariant itself
  rather than assuming it.
- evidence_sufficient=False is scored as ABSTAINED, a distinct outcome
  from any TP/FP/TN/FN classification -- not silently folded into
  "predicted benign." Treating an honest "I don't know" as equivalent to
  a confident wrong-or-right guess would be exactly the kind of gamed
  eval this project's own build plan (docs/BUILD_PLAN.md, Week 8) warns
  against.
- A verdict counts as "predicted malicious" if recommended_action is
  recommend_escalate_analyst or recommend_escalate_urgent; "predicted
  benign" if recommend_close_benign or recommend_monitor. This is a real
  judgment call, not a neutral fact -- recommend_monitor could arguably
  represent low-confidence-but-still-flagged-as-malicious in some
  taxonomies. Scored the way a receiving analyst would actually read it:
  monitor and close-benign both mean "nothing needs to happen right now,"
  which is the operationally relevant distinction for a precision/recall
  number.
"""

from __future__ import annotations

import json
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from soc_copilot.agent.models import RecommendedAction, Verdict
from soc_copilot.api.store import AgentResultStore

REPO_ROOT = Path(__file__).resolve().parents[1]
LABELS_PATH = REPO_ROOT / "eval" / "labels.json"

_MALICIOUS_ACTIONS = frozenset({RecommendedAction.RECOMMEND_ESCALATE_ANALYST, RecommendedAction.RECOMMEND_ESCALATE_URGENT})
_BENIGN_ACTIONS = frozenset({RecommendedAction.RECOMMEND_CLOSE_BENIGN, RecommendedAction.RECOMMEND_MONITOR})

assert _MALICIOUS_ACTIONS | _BENIGN_ACTIONS == set(RecommendedAction), (
    "Every RecommendedAction must be classified as malicious or benign for this harness -- "
    "a new action value was added without updating this classification."
)


class EvalOutcome(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    ABSTAINED = "abstained"


def classify_verdict(verdict: Verdict, true_malicious: bool) -> EvalOutcome:
    if not verdict.evidence_sufficient:
        return EvalOutcome.ABSTAINED

    predicted_malicious = verdict.recommended_action in _MALICIOUS_ACTIONS

    if predicted_malicious and true_malicious:
        return EvalOutcome.TRUE_POSITIVE
    if predicted_malicious and not true_malicious:
        return EvalOutcome.FALSE_POSITIVE
    if not predicted_malicious and true_malicious:
        return EvalOutcome.FALSE_NEGATIVE
    return EvalOutcome.TRUE_NEGATIVE


class TriageEvalReport(BaseModel):
    total: int
    outcome_counts: dict[str, int]
    precision: Optional[float]
    recall: Optional[float]
    false_negative_rate: Optional[float]
    abstention_rate: float


def compute_report(outcomes: list[EvalOutcome]) -> TriageEvalReport:
    counts = Counter(outcomes)
    tp = counts[EvalOutcome.TRUE_POSITIVE]
    fp = counts[EvalOutcome.FALSE_POSITIVE]
    fn = counts[EvalOutcome.FALSE_NEGATIVE]
    abstained = counts[EvalOutcome.ABSTAINED]
    total = len(outcomes)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fnr = fn / (fn + tp) if (fn + tp) else None
    abstention_rate = abstained / total if total else 0.0

    return TriageEvalReport(
        total=total,
        outcome_counts={o.value: counts[o] for o in EvalOutcome},
        precision=precision,
        recall=recall,
        false_negative_rate=fnr,
        abstention_rate=abstention_rate,
    )


def _true_label_for_case(source_alert_ids: list[str], labels: dict) -> bool:
    """Returns True if the case is malicious. Raises if the case's own
    alerts disagree on ground truth -- that would mean either a
    correlation bug (Week 3's purity guarantee broken) or a labeling bug,
    and this harness should fail loudly rather than silently pick one."""
    truths = {labels[sid]["ground_truth"] for sid in source_alert_ids if sid in labels}
    if len(truths) > 1:
        raise ValueError(f"Case alerts disagree on ground truth: {source_alert_ids} -> {truths}")
    if not truths:
        raise ValueError(f"No labeled alerts found for case alerts: {source_alert_ids}")
    return truths.pop() == "malicious"


def main() -> None:
    labels = {k: v for k, v in json.loads(LABELS_PATH.read_text()).items() if k != "_readme"}
    store = AgentResultStore()
    case_ids = sorted(store.all_case_ids())

    if not case_ids:
        print("No stored agent results found. Run `python -m soc_copilot.api.seed` first, or, once live agent")
        print("runs are unblocked, populate the store with real investigations.")
        return

    print(
        f"NOTE: evaluating {len(case_ids)} stored case(s) -- NOT the full labeled set. Live agent runs remain "
        "blocked (devlog/0009-*.md), so this is a harness demonstration against whatever is currently seeded, "
        "not a real evaluation result. Do not cite these numbers as the project's actual triage accuracy.\n"
    )

    outcomes = []
    for case_id in case_ids:
        case, result = store.load(case_id)
        try:
            true_malicious = _true_label_for_case(case.source_alert_ids, labels)
        except ValueError as e:
            print(f"  {case_id}: skipped -- {e}")
            continue
        outcome = classify_verdict(result.verdict, true_malicious)
        outcomes.append(outcome)
        print(f"  {case_id}: true={'malicious' if true_malicious else 'benign'}, outcome={outcome.value}")

    if not outcomes:
        print("\nNo scoreable cases (none of the stored results had matching ground-truth labels).")
        return

    report = compute_report(outcomes)
    print(f"\n{report.model_dump_json(indent=2)}")


if __name__ == "__main__":
    main()
