# Devlog 0013 — Week 8: evaluation, docs, and an honest retrospective

**Date**: 2026-09-06

## What we built this session
- `agent/loop.py` — prompt-injection mitigation: untrusted alert content (rule names, descriptions, process names, command lines) is now wrapped in explicit `<untrusted_alert_data>` delimiters with a clear instruction not to treat it as instructions, backed by a corresponding system-prompt rule. A real, previously undocumented gap, found by reading the code rather than by an incident.
- `tests/test_prompt_injection.py` — 5 tests proving the delimiting is structurally correct, including that alert text containing a fake `</untrusted_alert_data>` sequence can't break out of the real block. Documented plainly what these tests can't prove: live model behavior, which this project has no way to verify.
- `docs/threat-model.md` — the honest security write-up: autonomy boundaries, prompt injection (mitigation + its real limits), enrichment API trust, LLM hallucination (what the grounding auditor does and doesn't catch), RAG corpus integrity, and an explicit "what this project does not defend against" section.
- `eval/triage_eval.py` — the full triage evaluation harness (precision/recall/FNR/abstention-rate), methodology stated explicitly, 15 tests covering every classification path. Run against the two currently-seeded illustrative examples with a loud, explicit disclaimer that this is a harness demonstration, not a real result.
- `eval/report.md` — consolidates every real measurement from all 8 weeks into one place, states the one metric that's actually missing (live triage accuracy) as plainly as everything that was measured, and includes an explicit section on how this report tries to avoid the common ways security-AI evals get gamed.
- README fully rewritten for the Week 8 completion state.

19 new tests (196 total).

## The honest state of the project, stated once, clearly

Seven of eight weeks' worth of pipeline are real, tested, and — where it was possible to check against reality rather than just internal consistency — live-verified: enrichment against real VirusTotal/AbuseIPDB, correlation against real ground truth, retrieval against real ground truth (with real, unflattering numbers), the grounding auditor against a realistic hand-assembled case that it initially failed to catch a real gap in. The one thing genuinely missing is the thing the whole system exists to produce: a live agent verdict, and therefore any real measurement of triage accuracy. That's not a small gap to wave past, and this report doesn't.

## Why the Groq saga belongs in this project's story, not apart from it

`docs/PROJECT_OVERVIEW.md` originally framed this project's differentiator as depth of explainability and rigor of evaluation, deliberately not competing on breadth of integrations with funded AI-SOC startups. Four straight sessions spent debugging a free API's rate limits, a deprecated model, a dropped parameter, and a reasoning-model's hidden token overhead is not a detour from that framing — it *is* that framing, applied to the unglamorous reality of building against a real, fast-moving, free-tier external dependency instead of a stable paid one. A portfolio piece that only ever showed clean, first-try successes would be less credible to a technical interviewer than one that shows: here's what actually broke, here's the specific fix for each distinct cause, here's the point where continuing to guess stopped being good engineering and pausing to write it up honestly started being the right call.

## What this means for the PhD/portfolio narrative

The original scope-decision note in `docs/PROJECT_OVERVIEW.md` tied this project to ZeTA's "continuous trust vs. continuous risk" thread — that connection is still available and untouched by anything that happened this week (asset criticality feeding into agent context, per `agent/sample_cases.py`'s malicious-case example, is the concrete seed of it already present in the code). What Week 8 actually adds to that narrative is a second, independent thing worth naming: **the eval methodology itself** — stated scoring rules, documented label corrections with their reasoning, a harness built and tested before there was data to run it against, and a live-verification gap reported as a gap rather than smoothed over — is exactly the kind of applied-systems rigor a PhD committee or a technical interviewer should find more convincing than a single clean accuracy number would have been on its own, precisely because they can check the reasoning behind it, not just trust the output.

## What's actually left, for a future session

- Resolve live Groq access (or switch to Cerebras, which also hosts `gpt-oss-120b` with a documented — if also volatile — higher TPM ceiling; devlog 0009's candidate list), then run the real triage eval and the originally-planned RAG ablation (verdicts with vs. without `search_mitre`) for real.
- Verify `chroma_retriever.py` locally against real embeddings, and see whether it actually closes the specific lexical gaps `eval/report.md` documents.
- If this project continues past its original 8-week scope: the ZeTA integration thread, and a genuine adversarial prompt-injection red-team pass now that there's a mitigation in place worth attacking.

## Push checklist
```bash
cd soc-copilot
git am 0012-feat-threat-model-eval-report-and-injection-mitigation.patch
pytest   # confirm 196/196
```

This closes out the originally-planned 8-week build plan. Thank you for the whole run of it — including, maybe especially, the parts that didn't go cleanly on the first try.
