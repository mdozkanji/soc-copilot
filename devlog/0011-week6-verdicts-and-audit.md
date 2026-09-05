# Devlog 0011 — Week 6: Verdicts, abstention, and a grounding auditor

**Date**: 2026-09-04

## What we built
- `src/soc_copilot/agent/models.py` — `Verdict` gets a first-class `evidence_sufficient: bool` field, not just a low confidence number. Two `model_validator` rules enforce it can't contradict itself: `evidence_sufficient=False` caps confidence at 40 and restricts `recommended_action` to `recommend_monitor`/`recommend_escalate_analyst` (confidently closing as benign or escalating urgently both assert a certainty that contradicts "insufficient evidence"). A validation failure here routes through the exact same `is_error` tool-result / self-correction path Week 4 already built for a malformed `submit_verdict` call — **no changes to `loop.py` were needed** for this to work.
- `src/soc_copilot/agent/tools.py` / `loop.py` — `evidence_sufficient` added to the `submit_verdict` schema as required; system prompt gets concrete abstention criteria (tools returning no data, `search_mitre` not confirming a technique, conflicting signals) instead of just "be honest."
- `src/soc_copilot/agent/audit.py` — a **grounding auditor**: cheap, rule-based checks for whether a verdict's claims are actually backed by its own trace, independent of whether the model is trustworthy. Not a correctness check — a narrower, complementary one to the Verdict schema's own internal-consistency validators.
- `src/soc_copilot/agent/summary.py` — renders an `AgentResult` into a human-readable investigation report (case overview, verdict, evidence gathered, audit warnings if any), not a raw trace dump.
- `eval/generate_sample_reports.py` + `eval/samples/*.md` — two sample reports built from **real project data** (Week 2's live-captured VirusTotal/AbuseIPDB results, Week 3's real correlation output, Week 5's real TF-IDF retriever), with only the verdict text itself hand-authored as a stand-in for live model output.
- `agent/cli.py` now prints the rendered summary (with `--verbose` for the raw trace).
- 32 new tests (153 total): `test_verdict_model.py`, `test_agent_audit.py`, `test_agent_summary.py`, plus new agent-loop scenarios for legitimate vs. self-contradictory abstention.

## A real gap the auditor caught in its own sample, not in a synthetic test
First draft of the malicious-case sample cited six MITRE techniques while only calling `search_mitre` once. The original `audit_verdict` check was just "was `search_mitre` called at all" — true, so it passed silently, which was wrong: confirming one technique doesn't confirm five others cited alongside it. Caught by actually reading the generated sample rather than trusting a green test suite, and fixed by making the check per-technique: it now tracks every `technique_id` that actually appeared in a `search_mitre` result and flags any cited technique that never did. `test_flags_only_the_specific_techniques_never_confirmed` locks this in.

## The sample reports turned a real limitation into the actual content, instead of hiding it
Rebuilt the malicious-case sample to call `search_mitre` once per alert in the real 8-alert chain and use the **real, unfiltered** top-1 result each time — no cherry-picking. Consistent with Week 5's documented retrieval limitations: only 4 of 8 alerts got a confident match (score ≥ 0.25); the rest were weak (0.12–0.22), including the exact same DGA→"DNS Server" and exfiltration→"Ingress Tool Transfer" misses already documented in devlog 0010. Rather than paper over this, the sample verdict's reasoning explicitly says so: severity and action are based on IP reputation, asset criticality, and chain coherence, not the MITRE mapping alone, and the four weak matches are listed as *not* treated as confirmed. This is exactly the calibration behavior this week's system-prompt rules ask for, demonstrated with real data instead of asserted in the abstract.

## Push checklist
```bash
cd soc-copilot
git am 0010-feat-verdict-abstention-and-grounding-auditor.patch
pytest                              # confirm 153/153
python -m eval.generate_sample_reports   # regenerate the samples yourself, compare
```

## Still blocked, unrelated to this week
Live agent verification remains blocked on the Groq free-tier issue (devlog 0009) — nothing here required a live model call, and nothing here is closer to unblocking it either. Once it is unblocked, the abstention design in this week's work is exactly what should get exercised first: does a real model actually set `evidence_sufficient=False` on the ambiguous cases (the unsigned-installer alert this week's abstention sample is modeled on), or does it need the system-prompt rules sharpened further?

## Next session (Week 7)
Minimal analyst UI + feedback loop: a small FastAPI + frontend showing the alert queue and each case's rendered summary (already built this week) with Accept/Override buttons, logging every override — the first real feedback dataset, and the first place the naive enrichment heuristic (Week 2) and the audit warnings (this week) could start getting checked against actual human judgment instead of just internal consistency.
