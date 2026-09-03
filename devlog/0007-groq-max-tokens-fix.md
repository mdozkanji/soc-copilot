# Devlog 0007 — Groq 413: the real bug was mine, not Groq's catalog this time

**Date**: 2026-09-02

## What happened
Model deprecation fixed, ran again, new error:
```
GroqAPIError: Groq API returned 413: {"error":{"message":"Request too large for model
`openai/gpt-oss-120b` ... on tokens per minute (TPM): Limit 8000, Requested 11250,
please reduce your message size and try again.
```

## Diagnosis
Checked Groq's actual published free-tier numbers this time rather than estimating: `openai/gpt-oss-120b` free tier is 30 RPM, **8,000 TPM**, 1,000 RPD -- confirmed against multiple current sources, not just one.

Then looked at our own client rather than assuming the limit itself was the whole story: `GroqClient.create_message()` never set `max_tokens` in the request body at all. This is a real bug from the Week 4-follow-up port, not a new Groq surprise. Anthropic's API *requires* `max_tokens` on every request, so the original Claude client always had it (2048, explicit). Groq's OpenAI-compatible API makes it optional -- and I simply dropped it while rewriting the client, instead of carrying the concept over deliberately. Without it, Groq applied its own (apparently sizeable) default completion allocation, and prompt tokens (system + 4 tool schemas + an 8-alert case description) plus that default landed at 11,250 -- comfortably over the 8,000 ceiling on the very first call.

Worth being precise about which of last two sessions' failures was "Groq changed something out from under us" (the deprecation) versus "I made a mistake porting the client" (this one). Both are real, but only one of them was actually preventable by me at the time -- this one was.

## Fix
- Added `max_tokens` back into the request body, defaulting to 1024 -- enough for a verdict or an intermediate reasoning turn, comfortably inside the 8,000 TPM ceiling alongside our prompt size.
- Added a `GROQ_MAX_TOKENS` env override, same resilience pattern as `GROQ_MODEL` from the last fix -- if 1024 turns out to be wrong in either direction once you're actually running multi-turn investigations against the free tier's rolling TPM budget, it's a `.env` change.
- New test (`test_request_includes_a_bounded_max_tokens`) asserts `max_tokens` is always present and bounded -- specifically so this exact class of bug can't silently reappear.

100/100 tests passing (2 new).

## Honest caveat
TPM is a *rolling* budget, not a per-request-only limit. A single call now fits comfortably, but if the agent needs several iterations in quick succession within the same 60-second window (multiple tool calls, Claude -- sorry, old habit -- *Groq's* speed advantage cuts both ways here), it's plausible the cumulative total across 2-3 fast calls could still approach 8,000 TPM on a longer investigation. I can't observe that from here since it depends on real timing against the live API. If you hit another 413 mid-investigation rather than on the first call, that's the next thing to look at -- lowering `GROQ_MAX_TOKENS` further or trimming `SYSTEM_PROMPT`/tool descriptions are the two levers.

## Push checklist
```bash
cd soc-copilot
git am 0005-fix-groq-max-tokens.patch
pytest   # confirm 100/100
python -m soc_copilot.agent.cli
```
