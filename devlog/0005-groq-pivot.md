# Devlog 0005 — Week 4 follow-up: parity check, and swapping Claude for free-tier Groq

**Date**: 2026-09-02

## Why this session happened
Two things prompted it: you uploaded your actual local repo so we could confirm it matched what I'd been building against, and you asked to remove the Anthropic/Claude dependency entirely and replace it with a free API, since you don't want to pay for API access on a portfolio demo.

## Part 1: parity check against your uploaded repo
Diffed your uploaded `soc-copilot.zip` against my sandbox's Week 4 commit, file by file (excluding `.git`, `.venv`, caches). Everything matched byte-for-byte **except two files**:

- **`.env.example`** was missing from every one of my delivered commits in your history until you added it yourself by hand (`docs: add agent environment example`) -- and that manual version is itself missing the `VT_API_KEY=` line and the entire AbuseIPDB section. This explains something from last session: when you ran the CLI in `~/soc-copilot` and saw "Neither VT_API_KEY nor ABUSEIPDB_API_KEY is set," it wasn't that your keys were wrong -- `.env.example` in that directory never had those variable names in it to copy from.
- **`.gitignore`** is missing one line (`data/enrichment_cache.sqlite3`) that I added mid-Week-2.

Both point to the same likely cause: a dotfile getting silently dropped somewhere between extracting a tarball and `git add`-ing it -- classic wildcard-copy gotcha (`cp -r * dest` skips dotfiles; `cp -r . dest` doesn't). Not something to chase further, just worth knowing about for future weeks. `.env.example` is corrected in this patch. `.gitignore` isn't -- a patch is a diff, and my copy already has the line, so there's nothing to diff against. **One manual fix needed on your end:**
```bash
echo "data/enrichment_cache.sqlite3" >> .gitignore
```

## Part 2: removing Claude, adding Groq
Confirmed current facts before touching anything (not assuming): Groq runs a genuinely free, no-credit-card developer tier, gated only by rate limits, at `https://api.groq.com/openai/v1` (OpenAI-compatible). `llama-3.3-70b-versatile` is documented by Groq specifically as supporting tool use.

### The refactor that mattered more than the swap itself
Week 4's agent loop was written directly against Anthropic's raw response format -- content blocks with `"type": "text"/"tool_use"`, appended verbatim into a growing message list. That was a real design mistake, visible only in hindsight: it meant the loop *itself* knew about a specific vendor's wire protocol, not just the client. Swapping providers one week later proved it, concretely -- Groq's OpenAI-compatible protocol differs from Anthropic's in several real ways:
- system prompt is a message in the array, not a separate field
- tool results are individual `role="tool"` messages, not grouped `tool_result` blocks inside one user message
- tool-call arguments arrive as a JSON *string*, not a nested object

Fixed properly, not patched around: added `src/soc_copilot/agent/llm_types.py` -- normalized `Turn`/`ToolCall`/`ToolResult`/`LLMResponse` types and an `LLMClient` protocol. The loop (`loop.py`) now only ever touches these normalized types; it has no idea which provider it's talking to. `src/soc_copilot/agent/claude_client.py` is deleted outright (not just unused) and replaced by `src/soc_copilot/agent/groq_client.py`, which is entirely responsible for translating normalized `Turn`s into Groq's wire format and Groq's response back into a normalized `LLMResponse`. A third provider later is one new client file, not a loop rewrite.

### A real bug in the new Groq client, worth keeping
Some open-weight models occasionally emit tool-call arguments that aren't valid JSON (a documented, observed failure mode, not a hypothetical -- third-party tool-calling wrappers around Groq/Llama report exactly this). `GroqClient._parse_response` catches `json.JSONDecodeError` on the arguments string and returns a flagged `{"_parse_error": ..., "_raw_arguments": ...}` payload instead of crashing -- so a malformed tool call becomes something the agent loop can turn into a tool-error result, same graceful-degradation principle as everywhere else in this project. Tested directly in `test_groq_client.py`.

### A real bug in my own test, caught by running it
`test_assistant_tool_calls_are_encoded_as_json_string_arguments` asserted `messages[1]` was the assistant turn -- off by one. The wire message order is `[system, user, assistant, ...]`, so the assistant turn is `messages[2]`. Caught immediately by actually running the suite, not by review this time. Fixed.

## What changed
- **Added**: `agent/llm_types.py`, `agent/groq_client.py`, `tests/test_groq_client.py`
- **Removed**: `agent/claude_client.py`, `tests/test_claude_client.py`
- **Rewritten**: `agent/loop.py` (provider-agnostic), `tests/test_agent_loop.py` (now scripts `LLMResponse` objects directly instead of raw Anthropic blocks -- genuinely simpler test code, not just different)
- **Updated**: `agent/tools.py` docstring (no longer Claude-specific), `agent/cli.py` (`GroqClient`, `GROQ_API_KEY`), `.env.example` (swapped key, fixed the truncation bug from Part 1), `README.md`
- **Annotated, not rewritten**: `docs/PROJECT_OVERVIEW.md` and `docs/BUILD_PLAN.md` get a follow-up note next to the original Claude-based plan, rather than silently editing history. The old devlog entries (0000, 0003, 0004) are untouched on purpose -- they're an honest record of what was actually built and decided at the time; this entry is where the pivot belongs.

96/96 tests passing (81 carried over unchanged + 15 new, 6 removed from the old Claude client suite). CLI smoke-tested with all keys unset: correctly picks `correlated-case-008`, correctly warns and degrades on missing enrichment keys, fails exactly at `GroqClient.from_env()` -- the one boundary needing your credentials.

## Push checklist
```bash
cd soc-copilot
echo "data/enrichment_cache.sqlite3" >> .gitignore   # manual fix, see Part 1
git am 0003-*.patch
pytest    # confirm 96/96
```

Get a free key at **https://console.groq.com/keys** (no credit card), add `GROQ_API_KEY=...` to `.env`, then:
```bash
python -m soc_copilot.agent.cli
```
This is still the one thing I can't run myself and am genuinely curious about -- please paste back the full trace + verdict.

## Next session (Week 5)
Back to the original plan: RAG over threat intel. Stand up Chroma, embed a MITRE ATT&CK export, add a `search_mitre` tool, and run the first real ablation (verdicts with vs. without RAG on a few hand-picked cases).
