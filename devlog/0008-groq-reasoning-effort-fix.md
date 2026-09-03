# Devlog 0008 — same 413, deeper cause: gpt-oss's hidden reasoning tokens

**Date**: 2026-09-03

## What happened
`max_tokens=1024` fix applied, ran again, same class of error but a different number:
```
Groq API returned 413: ... Limit 8000, Requested 11396 ...
```
Same error on the *first* call. `max_tokens=1024` should have capped completion size -- so either the fix didn't work, or the ceiling being hit isn't the one I thought it was.

## Diagnosis, done properly this time: measured, not guessed
Actually computed our real prompt size instead of eyeballing it: `SYSTEM_PROMPT` (~366 tokens), the 8-alert case description (~819 tokens), and the four tool schemas (~749 tokens) -- roughly **1,900 tokens total**, by character-count heuristic. Requested was 11,396; with `max_tokens=1024` that implies Groq counted roughly 10,370 tokens for this request -- over 5x my estimate. That gap was too large to hand-wave as heuristic imprecision, so I went and checked what else could be consuming budget.

Answer, from Groq's own docs: `openai/gpt-oss-120b` is a **reasoning model**. It accepts a `reasoning_effort` parameter (low/medium/high, default **medium**), and Groq's docs describe "low" as producing "fast responses with minimal internal reasoning... uses fewer tokens." In practice, this model's hidden chain-of-thought tokens appear to count toward the TPM preflight check independently of `max_tokens` -- so capping the visible completion budget didn't touch the actual problem, which is the model defaulting to a much larger internal reasoning budget before ever producing a tool call or an answer.

## Fix
Set `reasoning_effort: "low"` explicitly in every request, defaulting to that rather than trusting Groq's own default. Added `GROQ_REASONING_EFFORT` as a third override env var (same pattern as `GROQ_MODEL`/`GROQ_MAX_TOKENS`) -- if a future case genuinely benefits from deeper reasoning and there's TPM headroom to spend on it, that's a config change.

102/102 tests passing (2 new).

## Being honest about what's actually verified here
I found `reasoning_effort` documented on Groq's own docs page as a request parameter for this exact model -- that's the most authoritative source available and I'm reasonably confident in it, but I have no way to confirm from this sandbox that it actually reduces token usage the way the docs describe, because I still can't reach the live API. If this *doesn't* fix it, the honest next step is checking whether the parameter name or accepted values have also changed, not assuming the fix is complete just because the docs said so.

## Pattern across devlogs 0005-0008, worth naming directly
Four sessions in a row chasing the same underlying issue -- get the agent to actually run against a free API -- and three different real causes: a deprecated model, a dropped `max_tokens` parameter, and now a reasoning-model-specific token behavior undocumented in the numbers I first checked. None of these were the same mistake repeated; each was a genuinely new thing to learn about this specific model and provider. That's worth stating plainly rather than glossing over: building against a fast-moving free-tier API surface is exactly this kind of iterative, unglamorous debugging, and it's a legitimate part of the project's story, not a detour from it -- if this ever ends up in a portfolio writeup or a PhD-adjacent discussion of practical LLM-ops, this sequence is a better and more honest illustration of "productionizing against a real API" than a clean one-shot success would have been.

## Push checklist
```bash
cd soc-copilot
git am 0006-fix-groq-reasoning-effort.patch
pytest   # confirm 102/102
```

Update `.env` (not patchable, same reason as before) to add, if not already present:
```
GROQ_REASONING_EFFORT=low
```
(Optional -- `low` is now the client's own default, this just makes it explicit and overridable.)

```bash
python -m soc_copilot.agent.cli
```
