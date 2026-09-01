# Devlog 0004 — Week 4: Agent core (tool-calling)

**Date**: 2026-09-01

## What we built
- `src/soc_copilot/agent/claude_client.py` — a raw HTTP client for the Anthropic Messages API, built in the same style as Week 2's VirusTotal/AbuseIPDB clients (injectable `httpx.Client`, explicit retry/backoff, no SDK). Deliberately using the raw REST API rather than the `anthropic` SDK, so the actual tool-use wire protocol is visible and understood rather than hidden behind a library.
- `src/soc_copilot/agent/tools.py` — the four tool definitions sent to Claude: `enrich_ip`, `enrich_hash`, `get_asset_context`, and `submit_verdict`.
- `src/soc_copilot/agent/assets.py` + `data/asset_inventory.json` — the mocked asset-inventory tool backing `get_asset_context`, covering the five hosts in the Week 1 sample data (owner, department, criticality, notes).
- `src/soc_copilot/agent/models.py` — `Verdict` (severity reused from `ingest.schema.Severity`, confidence 0-100, MITRE techniques, `RecommendedAction`, reasoning, key evidence), `AgentTraceEntry`/`ToolCallRecord` for a fully inspectable per-iteration trace, `AgentResult`.
- `src/soc_copilot/agent/loop.py` — `SocAnalystAgent.investigate(case, alerts_by_id)`: the core loop.
- `src/soc_copilot/agent/cli.py` — runs the whole thing end-to-end against a real case from the sample dataset.
- 15 new tests (90 total): the Claude client against `httpx.MockTransport` (request shape, retry on 429/500/**529** — Anthropic's specific "overloaded" code — no retry on 401), the asset lookup, and a full `FakeClaudeClient`-scripted suite covering the agent loop's actual behavior, not just its happy path.

## The one design decision worth understanding, not just accepting
`submit_verdict` is a tool like any other — not a special "the model is done now" signal parsed out of free text. The loop's termination condition is simply: Claude called `submit_verdict`, and its `input` validated against the `Verdict` schema. This means structured output isn't bolted on after the investigation with a second parsing mechanism; it's the exact same tool-calling protocol already being used to gather evidence. It also buys something concrete: if Claude submits a malformed verdict (tested explicitly — `confidence: 150`, out of the 0-100 range), the loop doesn't crash or discard it. It comes back as a `tool_result` with `is_error: true`, and Claude gets a real chance to self-correct on the next turn. `test_malformed_verdict_is_rejected_and_agent_gets_a_chance_to_retry` exercises exactly this and confirms the corrected second submission is what actually gets returned.

## Graceful degradation, one layer up from Week 2
Every tool dispatch is wrapped so a single failing tool becomes `{"error": ...}` fed back to the agent, never an exception that kills the whole investigation — same principle as `enrich/service.py`'s per-source degradation, applied at the agent layer. Tested directly: calling `enrich_hash` with no VirusTotal client configured raises inside `EnrichmentService`, and the loop still converges cleanly to a (correctly low-confidence) verdict instead of crashing.

## What was caught before running, not by a failing test
While writing `test_claude_client.py`, I used `httpx._content.json.loads(...)` to parse a mocked request body — a nonexistent, made-up internal path, not real httpx API. Caught it on review before running the suite and fixed it to plain `json.loads(request.content)`. Worth logging honestly even though no test failure surfaced it: it's a reminder that "looks plausible" isn't the same as "verified," and this project's own ethos (test everything, don't assume) applies to the tests themselves, not just the application code.

Beyond that, this was a clean run: all 90 tests passed on the first full suite execution, including the 15 new ones.

## What was NOT run live this session
This sandbox has no `ANTHROPIC_API_KEY`, and shouldn't — that's yours. Ran the CLI anyway to confirm everything up to the real API call works: it correctly picked `correlated-case-008` (the 8-alert intrusion chain, same one Week 3 validated), correctly warned and degraded when no `VT_API_KEY`/`ABUSEIPDB_API_KEY` was set, and failed exactly at `ClaudeClient.from_env()` — the one boundary that genuinely needs your credentials.

**Please run this locally and paste back the output**:
```bash
cd soc-copilot
git am 0002-*.patch
pip install -e ".[dev]"   # picks up no new deps -- agent/ only adds files, not packages
pytest                     # confirm 90/90
python -m soc_copilot.agent.cli
```
This is the first session where the thing being tested is the model's actual reasoning quality, not just code correctness — whether it grounds claims in real tool results, whether it's honest about weak evidence, whether `key_evidence` actually reflects what the tools returned. That can only be judged by reading real output, so please share the full trace + verdict, not just "it worked."

## State at end of Week 4
- 90/90 tests passing.
- Agent core complete and unit-verified; live reasoning quality unverified pending your run.

## Next session (Week 5)
- RAG over threat intel: stand up a local vector store (Chroma), embed a MITRE ATT&CK export, add a `search_mitre` tool so the agent grounds its technique mapping in retrieved reference text instead of parametric knowledge. First real ablation: compare verdicts with vs. without RAG on a few hand-picked cases.
