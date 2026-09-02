# Devlog 0006 — Groq model deprecation, immediately

**Date**: 2026-09-02

## What happened
Ran `python -m soc_copilot.agent.cli` for the first time with a real `GROQ_API_KEY` and got:
```
GroqAPIError: Groq API returned 404: {"error":{"message":"The model `llama-3.3-70b-versatile`
does not exist or you do not have access to it.","type":"invalid_request_error","code":"model_not_found"}}
```

## Why
Checked properly this time instead of trusting last session's research: Groq deprecated `llama-3.3-70b-versatile` on **August 16, 2026** -- about two weeks before it was picked for this project. My original search results described it as currently supported; that was either already stale or I didn't dig past the model card into the deprecations page. Either way, the actual failure is exactly the kind of thing the client's own docstring now warns about: Groq's free-tier catalog changes frequently, and a single hardcoded model string is a real, demonstrated fragility, not a hypothetical one.

## The fix
- **Model**: switched to `openai/gpt-oss-120b` -- OpenAI's own open-weight model, hosted on Groq, documented specifically as "designed for high-capability agentic use." Arguably a better fit for this project than the Llama pick was, not just a same-quality substitute.
- **Resilience, not just a patch**: added a `GROQ_MODEL` environment variable override in `GroqClient.from_env()`. If this model gets deprecated too, that's a one-line `.env` change, not a wait for a code patch. Tested directly (`test_from_env_respects_groq_model_override`).

98/98 tests passing (2 new, covering the default-model and override paths of `from_env`).

## What I'm doing differently going forward
Model/provider catalogs for free-tier and fast-moving API products are exactly the kind of "current state" fact that shouldn't be trusted from a single search or from training knowledge, even a recent one -- this project's own `PROJECT_OVERVIEW.md` already says as much about journal APC policies and citation patterns; the same caution applies here. Before the next time a model string matters, I'll check the provider's live deprecations page specifically, not just its model catalog page, since a model can still be *listed* while being actively wound down.

## What you need to do
`.env.example` still isn't patchable for the reason explained in devlog 0005 (your copy already diverged from mine, so a diff has no context to match). Manual update, same as before:
```bash
cat > .env.example << 'EOF'
# Copy to .env and fill in your own keys. .env is gitignored -- never commit real keys.

# Required for the agent (Week 4+). Free, no credit card required:
# https://console.groq.com/keys
GROQ_API_KEY=

# Optional: override the default model (openai/gpt-oss-120b) if Groq
# deprecates it -- check https://console.groq.com/docs/models for the
# current list. Groq's free-tier catalog changes frequently.
# GROQ_MODEL=

# Free tier: https://www.virustotal.com/gui/my-apikey (4 req/min, 500 req/day)
VT_API_KEY=

# Free tier: https://www.abuseipdb.com/account/api (1000 req/day)
ABUSEIPDB_API_KEY=
EOF
```

Then:
```bash
git am 0004-fix-groq-model-deprecation.patch
pytest   # confirm 98/98
python -m soc_copilot.agent.cli
```

Genuinely hoping this is the run that works end-to-end -- please paste back whatever comes out, including another error if there is one.
