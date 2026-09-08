# Evaluation Report

This report consolidates every evaluation this project has actually run, across all eight weeks, into one place. Nothing here is new measurement — it's the honest state of what's been verified, what hasn't, and why, written the way a technical reviewer should be able to trust: numbers with their methodology stated, gaps stated as gaps, and the one metric that matters most for a triage system flagged clearly as not yet obtained.

## 1. What's actually been measured

### 1.1 Enrichment reliability (Week 2) — live-verified

`enrich/virustotal.py` and `enrich/abuseipdb.py` were run against the real APIs, not just mocked. Checked against a known-clean address (`8.8.8.8`, Google DNS) and a known-malicious one (`185.220.101.47`, a Tor exit node): both parsed correctly, and the derived `likely_malicious_heuristic` was correct in both directions (`false` for the clean IP, `true` for the malicious one, independently confirmed by three separate signals — VirusTotal ratio, malicious-vote count, and AbuseIPDB score). Full detail: `devlog/0002-week2-enrichment.md`.

The private/internal-IP guard (`enrich/service.py`) was checked against all 13 distinct IPs across the 16-alert sample set: 8 internal addresses correctly skipped with zero API calls, 5 external addresses correctly queried.

### 1.2 Correlation quality (Week 3) — verified against ground truth

`correlate/cluster.py`'s entity-based, time-windowed clustering was tested against `eval/labels.json`'s case groupings, not just against synthetic scenarios: the real 8-alert intrusion chain (`case-001`) clusters into exactly one case, and cluster purity holds across the whole sample set — no produced case mixes a benign and a malicious alert. Building this eval caught a real Week 1 data-authoring bug (`sig-0002` sharing a host field with the intrusion chain by mistake) before it could silently produce a false merge. Full detail: `devlog/0003-week3-correlation.md`.

### 1.3 Retrieval quality (Week 5) — measured, and not flattering

`eval/retrieval_eval.py` checks whether `search_mitre`'s TF-IDF backend actually surfaces the correct MITRE technique for each of the 9 alerts with a known ground-truth technique ID:

```
Strict top-1 accuracy:  2/10 (20%)
Lenient top-1 accuracy: 3/10 (30%)  (credits a correct parent/sub-technique)
Top-5 recall:           5/10 (50%)
Mean reciprocal rank:   0.350
```

These numbers are not good, and are reported as such — TF-IDF is lexical, and several real misses (DGA beaconing matched to "DNS Server" instead of "Domain Generation Algorithms"; exfiltration matched to "Ingress Tool Transfer," lexically close but semantically backwards) are documented with the actual retrieved output in `devlog/0010-week5-rag.md`. Building this eval caught two real bugs: the eval's own query construction was discarding `process_name`/`command_line` evidence, and one ground-truth label (`sig-0002`) was itself imprecise (`T1046` corrected to `T1595`) — both fixed and documented, not silently absorbed into a better-looking number.

A dense-embedding backend (`rag/chroma_retriever.py`) is code-complete and would plausibly do better on exactly these lexical-gap misses, but is unverified from this development environment (no network path to the model-weights host) — see Section 3.

### 1.4 Grounding auditor (Week 6) — verified against realistic, not just synthetic, cases

`agent/audit.py`'s rule-based consistency checks were tested against synthetic verdicts (`test_agent_audit.py`) and, more importantly, against a *realistic* hand-assembled example built from real project data (`eval/samples/example-malicious-intrusion-chain.md`): the first draft of that sample cited 6 MITRE techniques while `search_mitre` had only been called once, and the auditor's original implementation didn't catch it — a real gap, found by reading the auditor's own output rather than trusting a green test suite, and fixed to check each cited technique individually. Full detail: `devlog/0011-week6-verdicts-and-audit.md`.

### 1.5 The triage evaluation harness (Week 8) — built and tested, not yet run for real

`eval/triage_eval.py` computes precision, recall, false-negative rate, and abstention rate for agent verdicts against `eval/labels.json` ground truth, with an explicit, stated methodology (case-level scoring derived from per-alert labels, `evidence_sufficient=False` scored as a distinct `ABSTAINED` outcome rather than folded into "predicted benign"). The harness logic itself is thoroughly unit tested — 15 tests covering every classification path (`tests/test_triage_eval.py`) — using synthetic verdicts, since real agent output across the labeled set doesn't exist yet (Section 2).

Running it today against the two Week 6/7 illustrative examples (clearly labeled in the harness's own output as a demonstration, not a result) gives:

```
{
  "total": 2,
  "outcome_counts": {"true_positive": 1, "false_positive": 0, "true_negative": 0, "false_negative": 0, "abstained": 1},
  "precision": 1.0,
  "recall": 1.0,
  "false_negative_rate": 0.0,
  "abstention_rate": 0.5
}
```

**This is not a real evaluation result and must not be cited as one.** Two cases, one of which was hand-authored specifically to demonstrate abstention working correctly, tells you nothing about actual triage accuracy. It demonstrates that the harness itself runs correctly end-to-end.

## 2. The one metric that actually matters most, and why it's missing

The build plan's original Week 8 deliverable was full-pipeline precision/recall/false-negative-rate across the whole labeled set, computed from **live agent verdicts**. That has not been obtained. Live agent runs against Groq's free tier have been blocked since Week 4, across four distinct, real, individually-fixed problems — a model deprecation, a dropped `max_tokens` parameter, `gpt-oss`'s reasoning-token overhead exceeding the free tier's TPM ceiling even after that fix, and, after those three fixes, a fourth attempt (`reasoning_effort=low`) that still didn't resolve it, at which point continuing to guess blind — with no way to inspect the live API's actual behavior from this development environment — stopped being productive (`devlog/0009-pausing-live-agent-verification.md`).

This is the honest state of the project's most important number: **not obtained, not faked, not approximated by something that looks similar.** Every other section of this report exists specifically because the actual triage-accuracy number doesn't, and each of those other measurements is real, methodologically stated, and independently useful — but none of them substitute for it, and this report does not pretend otherwise.

## 3. Other known gaps

- **Dense-embedding retrieval** (`rag/chroma_retriever.py`): code-complete, integration-tested against a fake embedding function, unverified with a real model from this environment.
- **RAG corpus integrity**: no checksum/signature verification on the downloaded MITRE ATT&CK data (`docs/threat-model.md`, Section 5).
- **Prompt-injection mitigation**: the delimiting added in Week 8 is verified structurally (the prompt is built correctly), not behaviorally (whether a live model actually respects it) — see `docs/threat-model.md`, Section 2.

## 4. How this report tries to avoid the common ways security-AI evals get gamed

Stated explicitly, since an eval whose own trustworthiness isn't argued for is exactly the kind of thing a technical reviewer should be skeptical of by default:

- **No train/eval leakage, because there's no training.** This project doesn't fine-tune anything; the only place "leakage" could hide is ground-truth labels being adjusted to make a downstream number look better after the fact. Both label corrections made during this project (`sig-0002`'s host field in Week 3, `sig-0002`'s MITRE technique in Week 5) are documented with the independent reasoning behind each correction (a factual inconsistency in the raw data; MITRE's own technique description not matching the labeled ID) — not "this made the pass rate go up."
- **No cherry-picked cases.** The retrieval eval (Section 1.3) runs against all 9 available ground-truth-labeled alerts, not a selected subset, and reports the honest 20%/50% numbers rather than only the queries that worked. The Week 6 malicious-case sample calls `search_mitre` once per real alert in the chain and uses the unfiltered top-1 result every time, including the four weak matches that don't help the narrative.
- **The harness is separated from the (currently absent) result.** `eval/triage_eval.py` was built and fully tested before there was real data to run it against, specifically so its logic couldn't be shaped to fit a known answer.
- **Every number in this report links to the devlog entry from the week it was actually produced**, so the chronology (and any bugs found along the way) is checkable, not just asserted.
