# soc-copilot

An AI-powered SOC alert triage & investigation copilot: a tool-calling LLM agent that ingests SIEM/EDR-style alerts, correlates them into cases, enriches them against real threat-intel APIs, and produces an explainable, citation-backed triage verdict for a human analyst to accept or override.

Built as a portfolio/research project — see [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md) for the full rationale (problem, approach, why it matters, competitive landscape) and [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) for the week-by-week plan. Progress is tracked as we go in [`devlog/`](devlog/), written during each build session rather than reconstructed afterward.

## Status: Week 5 — RAG over threat intel ✅ complete (retrieval), Chroma backend unverified

- [x] Repo scaffold, `pyproject.toml`, package layout
- [x] Internal `Alert` schema (`src/soc_copilot/ingest/schema.py`)
- [x] Per-source normalizers for two sample formats (`src/soc_copilot/ingest/normalize.py`)
- [x] 16-alert hand-authored sample dataset with ground-truth labels (`data/`, `eval/labels.json`)
- [x] VirusTotal + AbuseIPDB clients with retry/backoff (`src/soc_copilot/enrich/`)
- [x] SQLite TTL cache + persisted daily-quota tracking + sliding-window rate limiter
- [x] Private/internal-IP guard (verified against all 13 distinct IPs in the sample set)
- [x] Live-verified against real VT/AbuseIPDB APIs
- [x] Entity-based correlation engine with time-windowed connected-components clustering (`src/soc_copilot/correlate/`)
- [x] Cluster-purity tests against real ground truth (`eval/labels.json`)
- [x] Tool-calling agent loop: `enrich_ip`, `enrich_hash`, `get_asset_context`, `search_mitre`, `submit_verdict` (`src/soc_copilot/agent/`), provider-agnostic (`llm_types.py`), currently wired to Groq's free tier (`groq_client.py`)
- [x] Real MITRE ATT&CK corpus (697 techniques, official STIX data) + TF-IDF retriever, verified end-to-end (`src/soc_copilot/rag/`)
- [x] Retrieval-quality evaluation against ground truth (`eval/retrieval_eval.py`) -- honest numbers, not polished: strict top-1 20%, top-5 recall 50%
- [ ] Dense-embedding retriever (`chroma_retriever.py`) -- code-complete, needs your machine to verify (`pip install -e ".[embeddings]"`, no huggingface.co access from this sandbox)
- [x] Unit tests, all passing (121/121, `tests/`)
- [ ] **Live agent run against the real Groq API — blocked, not yet achieved.** Four attempts (model deprecation, missing `max_tokens`, `gpt-oss` reasoning-token overhead) each fixed a real, distinct problem, but the free tier's 8,000 TPM ceiling is still being exceeded. Paused rather than continuing to guess blind with no way to inspect the live API from this environment. Full writeup: `devlog/0009-pausing-live-agent-verification.md`.
- [ ] Week 6: verdicts, summaries, and the trust layer (abstention)

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
├── docs/          # project overview, build plan, per-topic notes (data, architecture, threat model)
├── devlog/        # dated session logs, written as we build
├── data/          # raw + normalized sample alerts
├── eval/          # ground-truth labels and (from Week 8) the evaluation harness
├── src/
│   └── soc_copilot/
│       ├── ingest/     # alert schema + normalization (Week 1)
│       ├── enrich/     # VirusTotal / AbuseIPDB clients, cache, rate limiting (Week 2)
│       ├── correlate/  # entity-based clustering into cases (Week 3)
│       ├── agent/      # tool-calling agent loop (Groq/gpt-oss, provider-agnostic interface), verdict schema (Week 4)
│       └── rag/        # real MITRE ATT&CK corpus + retrieval for search_mitre (Week 5)
│           # api/ arrives in a later week
└── tests/
```

```bash
# run correlation over the sample dataset and print a case summary
python -m soc_copilot.correlate.cli

# query the MITRE ATT&CK retriever directly
python -m soc_copilot.rag.cli "encoded PowerShell command execution"

# run the retrieval-quality evaluation against ground truth
python -m eval.retrieval_eval

# run the agent end-to-end on a real case (needs GROQ_API_KEY -- free, no card: https://console.groq.com/keys; VT/AbuseIPDB keys optional; currently blocked, see devlog/0009-*.md)
python -m soc_copilot.agent.cli
```

## Environment variables

Copy `.env.example` to `.env` and fill in your own free-tier API keys (never commit `.env` — it's gitignored):
- `VT_API_KEY` — https://www.virustotal.com/gui/my-apikey
- `ABUSEIPDB_API_KEY` — https://www.abuseipdb.com/account/api

```bash
# one-off enrichment lookups
python -m soc_copilot.enrich.cli --ip 185.220.101.47
python -m soc_copilot.enrich.cli --hash <sha256>
```

## License

MIT
