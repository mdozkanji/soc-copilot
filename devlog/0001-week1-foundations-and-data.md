# Devlog 0001 — Week 1: Foundations & data

**Date**: 2026-08-30

## What we built
- Repo scaffold: `pyproject.toml` (src layout, pytest configured via `pythonpath = ["src"]`), `.gitignore`, MIT `LICENSE`.
- `src/soc_copilot/ingest/schema.py` — the internal `Alert` model (Pydantic v2). Loosely OCSF-inspired, deliberately small. Ground truth is *not* part of this schema — see the docstring for why.
- `src/soc_copilot/ingest/normalize.py` — two per-source normalizers (`sigma_synthetic`, `edr_synthetic`) plus a dispatcher. Each source has genuinely different field names, a different severity encoding (level string vs. numeric score), and a different network-field shape (flat vs. nested) — chosen on purpose so the normalizer pattern gets exercised for real, not just on a single tidy format.
- `data/raw_samples/` — 16 hand-authored raw alerts across the two sources: one coherent 8-alert intrusion chain (`case-001`), two standalone incidents, and five benign alerts (three of them deliberately "looks suspicious but isn't", for later calibration testing).
- `eval/labels.json` — ground truth for all 16 alerts, keyed by the stable `source_alert_id`, kept fully separate from the operational schema.
- `src/soc_copilot/ingest/load_samples.py` — regenerates `data/normalized_alerts.json` from the raw sources; single reproducible entrypoint.
- `tests/test_normalize.py` — 20 tests: per-normalizer field mapping, severity-score boundary mapping (parametrized over all 10 score values), missing-optional-field handling, schema validation (sha256 shape, IP shape), an unregistered-source dispatch error, and two end-to-end checks (every raw sample normalizes without error; every normalized alert has a ground-truth label, so the dataset and the labels file can't silently drift apart).
- `docs/data-notes.md` — documents the dataset decision (synthetic-and-hand-crafted for now, with a concrete comparison against CICIDS2017/2018, Splunk BOTS, and OTRF Mordor+Sigma, and a stated plan to revisit before Week 8) and the schema design rationale.

## What actually broke (kept, on purpose)
Two of the six hand-written EDR sample records had malformed `sha256` values — one was a single character short (63 chars instead of 64), the other was also short. The schema's `field_validator` on `file_hash_sha256` caught both immediately as a `ValidationError` during `load_all()`, before any test suite logic even ran. Fixed by regenerating all six sample hashes deterministically (`sha256(event_id)`) instead of hand-typing hex strings.

This is a small thing, but it's a real instance of the exact lesson from ZeTA that's now written into `docs/data-notes.md` and worth restating here: validation at the schema boundary catches bad data immediately and loudly, rather than letting it silently propagate into correlation or the agent three weeks from now where it would be much harder to trace back.

## State at end of Week 1
- 20/20 tests passing, no warnings.
- `python -m soc_copilot.ingest.load_samples` runs clean: 16 alerts normalized from 2 sources.
- Nothing agent- or enrichment-related exists yet — that starts Week 2.

## Push checklist for you
```bash
cd soc-copilot
git init
git add .
git commit -m "Week 1: alert schema, per-source normalizers, sample dataset + labels, tests"
git branch -M main
git remote add origin git@github.com:mdozkanji/soc-copilot.git
git push -u origin main
```
(Create the empty `soc-copilot` repo on GitHub first if it doesn't exist yet — no README/license/gitignore from GitHub's side, since we already have all three here.)

## Next session (Week 2)
- VirusTotal + AbuseIPDB clients, rate-limit handling, a cache layer (SQLite to start — Redis is already proven from ZeTA if we want it later), and a CLI script that enriches one alert end-to-end.
