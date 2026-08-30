# Devlog 0000 — Kickoff

**Date**: 2026-08-29

## What happened this session
- Revisited the "AI-Powered SOC Copilot" project idea from the earlier portfolio brainstorm (Career 5 / Skill 5 / Effort 3 / Startup 5 / PhD 3).
- Wrote up the full project rationale: problem (alert fatigue, brittle SOAR automation, black-box ML triage), solution shape (tool-calling LLM agent that only claims what it can back with a real tool call), and why it's a credible portfolio/PhD artifact given the ZeTA/Zero-Trust background — see `docs/PROJECT_OVERVIEW.md`.
- Checked the current (mid-2026) competitive landscape (Dropzone AI, Prophet Security, Radiant Security, Torq HyperSOC, platform-native copilots from CrowdStrike/Microsoft/SentinelOne/Google). Category is crowded and well funded; the practical takeaway is to differentiate on explainability + rigorous evaluation on a small, honest dataset rather than trying to out-integrate the incumbents.
- Drafted the 8-week build plan in `docs/BUILD_PLAN.md`.

## Key decisions made
| Decision | Choice | Why |
|---|---|---|
| Dataset | TBD in Week 1 (leaning: synthetic/Sigma-derived alerts, MITRE-mapped) | Clean, reproducible ground truth; no data-access hurdles |
| LLM | Claude via Anthropic API, native tool use | Direct hands-on with the same agent architecture the AI-SOC vendors use |
| Language/stack | Python (FastAPI, Pydantic, Chroma) | LLM-agent/RAG tooling ecosystem is Python-first; also broadens your stack beyond ZeTA's TypeScript |
| Enrichment APIs | VirusTotal + AbuseIPDB free tiers | No paid access needed for a personal project |
| Autonomy posture | Recommend only, never auto-execute containment | Matches current buyer-guide best practice; keeps the threat model sane |
| Repo workflow | Same as ZeTA: I hand you patches/files, you apply + push | No GitHub MCP connector is currently available to push on your behalf — checked the connector registry this session, nothing relevant found |

## Open questions for you
1. Python vs. sticking with TypeScript for consistency with ZeTA — default is Python unless you object before Week 1.
2. Which sample dataset to commit to (I'll bring 2–3 concrete options with pros/cons at the start of Week 1).
3. Repo name — proposing `soc-copilot` or `ai-soc-triage-agent` under `mdozkanji`.

## Next session (Week 1)
- Scaffold the repo, lock in the dataset, build the alert normalizer + tests.
