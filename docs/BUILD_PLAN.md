# SOC Copilot — Build Plan

Cadence: one milestone per week, same workflow as ZeTA — I generate the week's code/docs as patch files, you apply with `git apply` / `git am` and push. Each week closes with a devlog entry in `/devlog`.

Repo layout (proposed):

```
soc-copilot/
├── docs/                  # this plan, the overview, architecture notes
├── devlog/                # one dated file per session, chronological
├── data/                  # sample alert datasets, MITRE ATT&CK export
├── src/
│   ├── ingest/            # alert normalization
│   ├── enrich/             # VirusTotal / AbuseIPDB clients + cache
│   ├── correlate/          # entity-based clustering
│   ├── agent/               # Claude tool-use agent loop, tool definitions
│   ├── rag/                 # embedding + vector store for ATT&CK/past cases
│   └── api/                 # FastAPI app
├── ui/                      # minimal analyst dashboard (later week)
├── eval/                    # labeled test set + scoring harness
├── tests/
└── README.md
```

## Week 1 — Foundations & data
- Repo scaffold, Python env (`uv` or `venv`), pre-commit/lint config.
- Decide and download the sample alert dataset; write the normalizer that maps it to a single internal `Alert` schema (loosely OCSF-inspired: entity fields for src/dst IP, user, host, hash, technique hint, timestamp, raw payload).
- Write 10–20 unit tests around the normalizer so later weeks don't silently break it.
- **Deliverable**: `src/ingest/`, `data/sample_alerts.json`, normalizer tests passing, `docs/data-notes.md` explaining dataset choice and licensing.
- **Teach**: alert schemas in real SOCs, why normalization is the unglamorous but load-bearing first step of every SIEM/XDR pipeline, intro to OCSF.

## Week 2 — Enrichment layer
- VirusTotal + AbuseIPDB clients with API key config, rate-limit handling, retries.
- Redis (or SQLite for simplicity) cache so repeated lookups on the same IP/hash don't burn API quota — you already learned this pattern's importance the hard way on ZeTA's RPC polling issue, same principle applies to rate-limited REST APIs.
- **Deliverable**: `src/enrich/`, cache-hit tests, a CLI script that enriches one alert end-to-end and prints the result.
- **Teach**: threat-intel API design patterns, why caching + backoff is non-negotiable at scale, reputation-score interpretation (what a VT detection ratio actually means vs. what it doesn't).

## Week 3 — Correlation
- Entity-based clustering: group alerts sharing an IP/host/user within a rolling time window into a single "case."
- Simple graph representation (networkx is enough) so a case can be visualized later.
- **Deliverable**: `src/correlate/`, tests on synthetic multi-alert scenarios (e.g., recon → exploit → lateral movement chain should cluster into one case).
- **Teach**: why correlation matters more than any single alert, kill-chain / MITRE ATT&CK tactic ordering as a correlation signal, false-merge vs. false-split tradeoffs.

## Week 4 — Agent core (tool-calling)
*(Follow-up note: built as planned below using Claude/Anthropic, then switched to Groq's free tier the same week to avoid requiring paid API access for a portfolio demo -- see `devlog/0005-*.md`. The plan is left as originally written; the pivot is documented where it happened, not retrofitted here.)*
- Define the tool schema for Claude: `enrich_ip`, `enrich_hash`, `get_asset_context` (mocked inventory), each with strict JSON schemas.
- Implement the agent loop: alert/case in → Claude decides which tools to call → tool results fed back → repeat until Claude emits a final structured verdict (Pydantic model: severity, confidence, MITRE technique(s), recommended action, reasoning trace).
- **Deliverable**: `src/agent/`, one working end-to-end trace on a real case from Week 3, logged verbosely so you can see every tool call.
- **Teach**: function calling / tool use mechanics, agent loop design (when to stop, how to bound iterations, how to handle a tool error gracefully), structured output via Pydantic + Claude.

## Week 5 — RAG over threat intel
- Stand up Chroma, embed a MITRE ATT&CK export (technique name, tactic, description) and a handful of public incident writeups.
- Add a `search_mitre` / `search_past_cases` tool the agent can call to ground its technique mapping instead of guessing from parametric knowledge.
- **Deliverable**: `src/rag/`, an ablation script comparing agent verdicts with vs. without RAG on 10 hand-picked cases — this becomes your first real evaluation artifact.
- **Teach**: embeddings and vector search fundamentals, chunking strategy for structured knowledge like ATT&CK, why RAG reduces (but doesn't eliminate) hallucination, what "grounding" actually buys you in a security context.

## Week 6 — Verdicts, summaries, and the trust layer
- Formalize the structured verdict schema and a human-readable investigation summary generator.
- Add explicit "insufficient evidence, escalate to human" as a first-class output — the agent must be able to say "I don't know" rather than force a confident-sounding guess. This is the single most important trust-building feature and the thing most toy demos skip.
- **Deliverable**: `src/agent/verdict.py`, sample generated investigation reports checked into `eval/samples/`.
- **Teach**: calibration and abstention in LLM systems, why "confident and wrong" is worse than "uncertain and honest" in a security context, prompt patterns that encourage appropriate hedging without becoming useless.

## Week 7 — Minimal analyst UI + feedback loop
- A small FastAPI + lightweight frontend (plain HTML/HTMX or a tiny React page — decide based on how much frontend time you want to spend) showing the alert queue, the agent's verdict and reasoning trace per case, and Accept/Override buttons.
- Every accept/override gets logged with a reason — this is your feedback dataset.
- **Deliverable**: `ui/`, `src/api/`, a screen-recorded walkthrough of triaging a batch of alerts end-to-end.
- **Teach**: human-in-the-loop system design, why the override log matters more than the raw accuracy number, basics of building a review UI that analysts will actually trust and use.

## Week 8 — Evaluation, docs, demo
- Build the eval harness: run the full pipeline over a labeled test set, compute precision/recall/false-negative rate against ground truth, and report the RAG ablation and the abstention rate from Week 5–6.
- Write `docs/threat-model.md` (same honest-documentation habit as ZeTA): what this agent should never be trusted to do autonomously, prompt-injection risk from alert payloads, what happens if an enrichment API is down or lies.
- Polish `README.md`, record a 3–5 minute demo video, write a short retrospective devlog tying this back to your PhD/portfolio narrative.
- **Deliverable**: `eval/report.md` with real numbers (however imperfect — document them honestly), demo video/GIF, final README.
- **Teach**: how to write an evaluation section a technical reviewer will actually trust, common ways security-AI evals are gamed (leakage between train/eval, cherry-picked cases) and how to avoid them in your own write-up.

## Stretch (Week 9+, optional)
- Prompt-injection red-teaming: craft malicious alert payloads designed to hijack the agent's instructions, measure the agent's robustness, document findings — this is a genuinely interesting angle for a short paper or blog post and ties well into your existing security-research profile.
- ZeTA integration: feed ABAC policy-evaluation context (unusual attribute changes, access outside policy) into the correlation layer as a signal — the "continuous trust + continuous risk" narrative mentioned in the overview doc.
- Small local classifier as a cheap pre-filter ahead of the LLM call, to demonstrate cost-awareness (a real objection every buyer guide raises about LLM-based triage at alert-volume scale).

## Working agreement
- Weekly cadence, same as ZeTA: I produce a patch (or a set of new files) at the start of each week's session, you apply and push, we debug against real output together.
- Every session gets a devlog entry in `/devlog`, written as we go, not reconstructed after the fact.
- I don't have your GitHub push credentials, so the flow stays: I hand you files/patches → you `git add`/`commit`/`push`. If you'd rather connect a GitHub MCP connector so I can open PRs directly, say the word and I'll check what's available.
