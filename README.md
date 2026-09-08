# soc-copilot

An AI-powered SOC alert triage & investigation copilot: a tool-calling LLM agent that ingests SIEM/EDR-style alerts, correlates them into cases, enriches them against real threat-intel APIs, and produces an explainable, citation-backed triage verdict for a human analyst to accept or override.

Built as a portfolio/research project over an 8-week build — see [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md) for the full rationale (problem, approach, why it matters, competitive landscape) and [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) for the week-by-week plan. Progress is tracked as it happened in [`devlog/`](devlog/), written during each build session rather than reconstructed afterward — that history is part of the point of this project, not incidental to it.

**Start here if you're evaluating this project**: [`eval/report.md`](eval/report.md) (what's actually been measured, and the one honest gap) and [`docs/threat-model.md`](docs/threat-model.md) (what this system should never be trusted to do, and why).

## Status: Week 8 of 8 — evaluation, docs, demo ✅ complete (core pipeline); live agent verification blocked

The originally-planned 8-week build is complete. One real gap remains, stated plainly rather than hidden: **live agent verification against a real LLM has not been achieved** — see below.

- [x] Ingestion: normalized `Alert` schema, per-source normalizers, 16-alert hand-authored sample dataset with ground-truth labels (`src/soc_copilot/ingest/`, `data/`, `eval/labels.json`)
- [x] Enrichment: VirusTotal + AbuseIPDB clients, retry/backoff, SQLite TTL cache, private-IP guard, **live-verified against real APIs** (`src/soc_copilot/enrich/`)
- [x] Correlation: entity-based, time-windowed clustering, **cluster-purity tested against real ground truth** (`src/soc_copilot/correlate/`)
- [x] Agent core: tool-calling loop (`enrich_ip`, `enrich_hash`, `get_asset_context`, `search_mitre`, `submit_verdict`), provider-agnostic interface, currently wired to Groq's free tier (`src/soc_copilot/agent/`)
- [x] RAG: real MITRE ATT&CK corpus (697 techniques, official STIX data), TF-IDF retriever verified end-to-end, **retrieval-quality measured and reported honestly** (strict top-1 20%, top-5 recall 50%) (`src/soc_copilot/rag/`)
- [x] Trust layer: first-class abstention (`evidence_sufficient` with consistency validators), a grounding auditor checking verdict claims against their own trace, human-readable investigation reports (`src/soc_copilot/agent/models.py`, `audit.py`, `summary.py`)
- [x] Analyst review UI: FastAPI + Jinja2, case queue, Accept/Override with a real feedback log (`src/soc_copilot/api/`)
- [x] Prompt-injection mitigation: untrusted alert content delimited and framed explicitly, verified structurally (`agent/loop.py`, `docs/threat-model.md`)
- [x] Triage evaluation harness: precision/recall/FNR/abstention-rate computation, fully unit-tested (`eval/triage_eval.py`)
- [x] Threat model and consolidated evaluation report (`docs/threat-model.md`, `eval/report.md`)
- [x] Unit tests, all passing (196/196, `tests/`)
- [ ] **Dense-embedding retriever** (`rag/chroma_retriever.py`) — code-complete, needs your machine to verify (`pip install -e ".[embeddings]"`; no `huggingface.co` access from the sandbox this was built in)
- [ ] **Live agent verification — blocked, not achieved.** Four distinct, individually-fixed problems in a row (a model deprecation, a dropped `max_tokens` parameter, `gpt-oss`'s reasoning-token overhead, and a fourth attempt that still didn't resolve it) against Groq's free-tier TPM limit. Paused deliberately rather than continuing to guess blind with no way to inspect the live API from this development environment. This is also why the project's single most important metric — real triage precision/recall against the labeled set — has not been obtained; see `eval/report.md` Section 2 for the full honest accounting.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# run tests
pytest

# regenerate the normalized sample dataset from raw sources
python -m soc_copilot.ingest.load_samples
```

## Repo layout

```
soc-copilot/
├── docs/          # project overview, build plan, data notes, threat model
├── devlog/        # dated session logs, written as we built -- the real history
├── data/          # raw + normalized sample alerts, MITRE corpus, seeded demo results
├── eval/          # ground-truth labels, evaluation harnesses, consolidated report, sample reports
├── src/
│   └── soc_copilot/
│       ├── ingest/     # alert schema + normalization (Week 1)
│       ├── enrich/     # VirusTotal / AbuseIPDB clients, cache, rate limiting (Week 2)
│       ├── correlate/  # entity-based clustering into cases (Week 3)
│       ├── agent/      # tool-calling agent loop (Groq/gpt-oss, provider-agnostic interface), verdict schema, sample cases (Week 4/6)
│       ├── rag/        # real MITRE ATT&CK corpus + retrieval for search_mitre (Week 5)
│       └── api/        # FastAPI analyst review UI + feedback log (Week 7)
└── tests/
```

```bash
# run correlation over the sample dataset and print a case summary
python -m soc_copilot.correlate.cli

# query the MITRE ATT&CK retriever directly
python -m soc_copilot.rag.cli "encoded PowerShell command execution"

# run the retrieval-quality evaluation against ground truth
python -m eval.retrieval_eval

# run the triage evaluation harness against whatever's currently seeded (demonstration only -- see eval/report.md)
python -m eval.triage_eval

# regenerate the sample investigation reports (built from real project data; see eval/samples/)
python -m eval.generate_sample_reports

# seed the analyst review UI with the two illustrative examples above
python -m soc_copilot.api.seed

# start the analyst review UI at http://127.0.0.1:8000/cases
uvicorn soc_copilot.api.app:app --reload --app-dir src

# run the agent end-to-end on a real case (needs GROQ_API_KEY; VT/AbuseIPDB keys optional; currently blocked, see devlog/0009-*.md)
python -m soc_copilot.agent.cli
```

## Environment variables

Copy `.env.example` to `.env` and fill in your own free-tier API keys (never commit `.env` — it's gitignored):
- `GROQ_API_KEY` — required for the agent. Free, no credit card: https://console.groq.com/keys
- `GROQ_MODEL` / `GROQ_MAX_TOKENS` / `GROQ_REASONING_EFFORT` — optional overrides; Groq's free-tier catalog and limits change frequently, see `devlog/0004-*.md` through `0008-*.md`
- `VT_API_KEY` — https://www.virustotal.com/gui/my-apikey
- `ABUSEIPDB_API_KEY` — https://www.abuseipdb.com/account/api

```bash
# one-off enrichment lookups
python -m soc_copilot.enrich.cli --ip 185.220.101.47
python -m soc_copilot.enrich.cli --hash <sha256>
```

## License

MIT
