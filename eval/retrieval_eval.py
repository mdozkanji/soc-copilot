"""
Retrieval-quality evaluation for search_mitre.

This substitutes for the Week 5 build plan's originally-planned deliverable
("an ablation script comparing agent verdicts with vs. without RAG on 10
hand-picked cases"). That comparison needs full agent verdicts, which need
a live LLM call -- currently blocked (see devlog/0009-*.md; Groq's free
tier hasn't been made to work for this workload yet). Rather than skip
evaluation entirely while that's unresolved, this measures the piece that
*is* fully testable without any live LLM: whether search_mitre's retrieval
actually surfaces the correct technique at all, using eval/labels.json's
true_mitre_technique as ground truth. Arguably more rigorous than the
original plan for what it covers -- a clean quantitative IR metric against
real ground truth, not a qualitative before/after read of a few verdicts --
while covering less: it says nothing about whether an LLM would actually
*use* a correct retrieval result well, which the original ablation would
have (once live agent runs are unblocked, that comparison is still worth
doing on top of this, not instead of it).

Usage:
    python -m eval.retrieval_eval
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_copilot.ingest.schema import Alert
from soc_copilot.rag.service import default_retriever

REPO_ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_ALERTS_PATH = REPO_ROOT / "data" / "normalized_alerts.json"
LABELS_PATH = REPO_ROOT / "eval" / "labels.json"

TOP_K = 5


def _query_for_alert(alert: Alert) -> str:
    """Deliberately excludes alert.mitre_technique_hint: several sample
    alerts carry a hint field that happens to exactly match this eval's own
    ground truth (both were authored by the same hand in Week 1), so
    including it would make the evaluation circular for those cases. Real
    observable fields only -- rule name, description, and (when present)
    the actual process/command-line evidence, which is exactly the kind of
    detail that should ground a technique match and was originally missing
    from this query entirely -- a real methodology bug caught while
    reviewing edr-9002's miss (process_name='powershell.exe' was sitting
    right there in the alert and wasn't being used)."""
    parts = [f"{alert.rule_name}. {alert.description}"]
    if alert.process_name:
        parts.append(f"Process: {alert.process_name}")
    if alert.command_line:
        parts.append(f"Command line: {alert.command_line}")
    return " ".join(parts)


def _is_parent_child_match(retrieved_id: str, true_id: str) -> bool:
    """True technique labels in eval/labels.json are sometimes the parent
    ID (e.g. 'T1003') where a more specific sub-technique (e.g.
    'T1003.001') is actually what the content matches -- a real imprecision
    in the Week 1 hand-authored ground truth, not a retrieval bug. Reported
    as a separate, clearly-labeled 'lenient' metric rather than silently
    folded into the strict one."""
    base_retrieved = retrieved_id.split(".")[0]
    base_true = true_id.split(".")[0]
    return base_retrieved == base_true and retrieved_id != true_id


def main() -> None:
    alerts = {a.source_alert_id: a for a in (Alert.model_validate(x) for x in json.loads(NORMALIZED_ALERTS_PATH.read_text()))}
    labels = {k: v for k, v in json.loads(LABELS_PATH.read_text()).items() if k != "_readme"}

    cases = [
        (source_id, info["true_mitre_technique"])
        for source_id, info in labels.items()
        if info.get("true_mitre_technique")
    ]

    retriever = default_retriever()

    strict_hits_at_1 = 0
    strict_hits_at_k = 0
    lenient_hits_at_1 = 0
    reciprocal_ranks: list[float] = []

    print(f"Retrieval evaluation: {len(cases)} alerts with a known ground-truth MITRE technique, top-{TOP_K}\n")
    print(f"{'alert':12s} {'true':12s} {'rank':6s} {'top-1 result':40s} match")
    print("-" * 90)

    for source_id, true_id in cases:
        alert = alerts[source_id]
        results = retriever.search(_query_for_alert(alert), k=TOP_K)
        retrieved_ids = [r.technique_id for r in results]

        rank = retrieved_ids.index(true_id) + 1 if true_id in retrieved_ids else None
        reciprocal_ranks.append(1.0 / rank if rank else 0.0)

        strict_top1 = retrieved_ids[0] == true_id
        lenient_top1 = strict_top1 or _is_parent_child_match(retrieved_ids[0], true_id)

        strict_hits_at_1 += int(strict_top1)
        strict_hits_at_k += int(rank is not None)
        lenient_hits_at_1 += int(lenient_top1)

        top1 = results[0]
        match_label = "exact" if strict_top1 else ("parent/sub" if lenient_top1 else ("in top-5" if rank else "MISS"))
        print(f"{source_id:12s} {true_id:12s} {str(rank or '-'):6s} {top1.technique_id + ' ' + top1.name:40.40s} {match_label}")

    n = len(cases)
    print()
    print(f"Strict top-1 accuracy:  {strict_hits_at_1}/{n} ({strict_hits_at_1 / n:.0%})")
    print(f"Lenient top-1 accuracy: {lenient_hits_at_1}/{n} ({lenient_hits_at_1 / n:.0%})  (credits a correct parent/sub-technique)")
    print(f"Top-{TOP_K} recall:        {strict_hits_at_k}/{n} ({strict_hits_at_k / n:.0%})")
    print(f"Mean reciprocal rank:   {sum(reciprocal_ranks) / n:.3f}")


if __name__ == "__main__":
    main()
