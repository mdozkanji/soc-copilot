# soc-copilot

An AI-powered SOC alert triage & investigation copilot: a tool-calling LLM agent that ingests SIEM/EDR-style alerts, correlates them into cases, enriches them against real threat-intel APIs, and produces an explainable, citation-backed triage verdict for a human analyst to accept or override.

Built as a portfolio/research project — see [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md) for the full rationale (problem, approach, why it matters, competitive landscape) and [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) for the week-by-week plan. Progress is tracked as we go in [`devlog/`](devlog/), written during each build session rather than reconstructed afterward.

## Status: Week 1 — Foundations & data

- [x] Repo scaffold, `pyproject.toml`, package layout
- [x] Internal `Alert` schema (`src/soc_copilot/ingest/schema.py`)
- [x] Per-source normalizers for two sample formats (`src/soc_copilot/ingest/normalize.py`)
- [x] 16-alert hand-authored sample dataset with ground-truth labels (`data/`, `eval/labels.json`)
- [x] Unit tests, all passing (`tests/test_normalize.py`)
- [ ] Week 2: enrichment (VirusTotal / AbuseIPDB)

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
│       └── ingest/   # alert schema + normalization (Week 1)
│           # enrich/, correlate/, agent/, rag/, api/ arrive in later weeks
└── tests/
```

## License

MIT
