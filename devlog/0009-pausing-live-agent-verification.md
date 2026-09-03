# Devlog 0009 — Pausing live agent verification

**Date**: 2026-09-03

## The call
Four sessions (0005-0008), three different real, targeted fixes, still a 413. Pausing here rather than continuing to guess blind — I have no way to inspect the live API's actual behavior from this sandbox (no network path to `api.groq.com`), which means every fix so far has been "best available evidence, unverified in practice." That's a defensible way to build against an API I can't reach, but four rounds of it without success is the point where continuing stops being productive and starts being guessing for its own sake.

## The full sequence, for the record
| Attempt | Change | Result |
|---|---|---|
| 1 | `llama-3.3-70b-versatile` (original pick) | 404 -- model deprecated by Groq on 2026-08-16 |
| 2 | Switched to `openai/gpt-oss-120b` | 413 -- TPM limit 8,000, requested **11,250** |
| 3 | Added `max_tokens=1024` (had been silently dropped in the Anthropic-to-Groq port) | 413 -- requested **11,396** |
| 4 | Added `reasoning_effort="low"` (gpt-oss's hidden reasoning tokens) | 413 -- requested **11,634** |

## The detail that actually matters here
The requested-token count **increased** across attempts 2 → 3 → 4 (11,250 → 11,396 → 11,634), despite attempt 4 specifically targeting a reduction via `reasoning_effort=low`, which Groq's own docs describe as using fewer tokens. That's the opposite of what a working fix should produce, and it's a real, specific signal, not just "still broken":

- It's possible `reasoning_effort` isn't actually being honored by the `/chat/completions` endpoint for this model the way the docs describe (the parameter may apply to a different endpoint, or Groq may be silently ignoring an unrecognized field rather than erroring on it).
- It's possible Groq's "Requested" figure in this error isn't a clean per-request estimate at all, but reflects something closer to organization-level headroom already partially consumed within the same rolling 60-second window -- plausible given how quickly these were retried each session.
- Either way: I can't distinguish between these from here. That requires either direct access to the live API (to inspect response headers like `x-ratelimit-remaining-tokens`, which Groq does document exposing) or a debugging session where you run `curl -v` yourself and share the raw headers back.

## What's solid, unaffected by any of this
- **Weeks 1-3**: fully working, live-verified where it matters (VirusTotal/AbuseIPDB against real IPs), tested against real ground truth (correlation purity checks). Nothing about this pause touches any of it.
- **Week 4's code**: complete, 102 tests passing, all exercised against scripted fakes/mocked HTTP transports -- the *architecture* (provider-agnostic loop, graceful tool-error degradation, self-correcting malformed verdicts) is verified. What's unverified is specifically "does a live call to Groq's free tier succeed for this workload," which is a narrower and more honest claim than "the agent doesn't work."

## Decision: pause, don't rip out
Keeping all of `src/soc_copilot/agent/` in the repo, not reverting it. It's real, tested, documented work, and the blocker is external (a specific free-tier provider's constraints for a reasoning-heavy multi-tool-call workload) rather than a flaw in the design. Marking it clearly in `README.md` as code-complete with live verification deferred, rather than checked off, so this doesn't quietly misrepresent status to a future reader (or a PhD committee, or an interviewer).

## Candidate next steps, for a future session -- not committing to any of these now
- **Cerebras' free tier also hosts `gpt-oss-120b`**, and its documented TPM limits are meaningfully higher than Groq's -- though sources disagree on the exact current number (I found figures ranging 30K-64K TPM depending on source and date, and Cerebras' own docs currently show a banner saying free-tier limits were "temporarily reduced" due to demand). Worth trying, but flagged with the same honesty this whole saga has needed: don't trust a single source on a free-tier number without checking again when it matters.
- Trim `SYSTEM_PROMPT` and the four tool descriptions further to shrink base prompt size regardless of provider.
- If you're willing, a manual `curl -v` against Groq directly, sharing back the raw `x-ratelimit-*` response headers, would tell us in one shot whether attempt 4's fix actually did anything -- more informative than another blind code change from me.

## Status
Week 4: code complete. Live agent verification: deferred, documented here, not silently dropped.

## Push checklist
```bash
cd soc-copilot
git am 0007-docs-pause-live-agent-verification.patch
pytest   # still 102/102 -- nothing functional changed this session
```
