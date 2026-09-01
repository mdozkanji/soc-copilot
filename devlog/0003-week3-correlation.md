# Devlog 0003 — Week 3: Correlation engine

**Date**: 2026-09-01

## What we built
- `src/soc_copilot/correlate/models.py` — `Case`: a group of alerts, with a union of entities across the group and, importantly, `link_reasons` — an explicit record of *why* alerts got grouped, not just that they did. Every alert ends up in exactly one case, including singleton cases, so nothing downstream needs two code paths for "a case" vs. "a lone alert."
- `src/soc_copilot/correlate/cluster.py` — `correlate()`: entity-indexed, time-windowed graph construction (`networkx`), cases = connected components. Two entities are join keys with real judgment calls baked in and documented: a small denylist of well-known public DNS resolvers (`NOISY_ENTITY_VALUES`) that are never allowed to link otherwise-unrelated alerts, and a default 2-hour `max_gap` window.
- `src/soc_copilot/correlate/cli.py` — `python -m soc_copilot.correlate.cli`, prints a human-readable case summary over the real sample data.
- 12 new tests (75 total): 8 synthetic scenario tests (direct merge, window-exclusion, noisy-IP exclusion with a non-noisy control, transitive chaining across 3 alerts with no single shared entity, singleton handling, exhaustive coverage), plus 4 tests that run correlation over the **real** Week 1 sample data and check it against `eval/labels.json` ground truth — cluster purity checks, not just "does it run."

## Real bugs caught this session

**1. A Week 1 data-authoring bug, caught before it could hide inside correlation.** `sig-0002` (meant to be an unrelated external recon scan, `case-002` in the ground truth) had `"computer": "WKS-EU-0231"` — the exact same host as the entire case-001 intrusion chain. I noticed this didn't add up (its `dst_ip`, `10.20.4.10`, doesn't even match `WKS-EU-0231`'s real IP, `10.20.4.55`, used consistently everywhere else) and checked the raw file before writing any clustering logic. Left in, this would have silently merged an "unrelated" incident into case-001 the moment correlation ran, and — worse — it would have looked *correct*, because host-sharing is exactly the kind of strong signal correlation is supposed to catch. Fixed by setting `"computer": null` (a network-level scan detection realistically wouldn't resolve to a single endpoint hostname anyway) and regenerating `data/normalized_alerts.json`. This is exactly why the purity tests against ground truth exist — a bug like this is invisible to "does the code run" and only shows up when you check the actual grouping against a known-correct answer.

**2. Test bug: `eval/labels.json`'s `_readme` metadata key isn't a label.** The purity tests iterate `labels.items()` expecting every value to be a dict with a `case_id` key — but the file also has a `"_readme": "<explanatory string>"` entry for humans reading the file. First run: `AttributeError: 'str' object has no attribute 'get'`. Fixed by filtering `_readme` out in the test's `_load_labels()` helper. Small, but a reminder that a JSON file meant for both machines and humans needs its human-facing metadata explicitly excluded wherever the file gets parsed programmatically — this will matter again the moment anything else reads `labels.json` (the Week 8 eval harness, for one).

## What the real output shows (worth understanding, not just "tests passed")
Ran `python -m soc_copilot.correlate.cli` over the actual 16-alert sample set: 8 cases came out.
- **`case-001`'s 8 alerts correctly merged into one case** (`correlated-case-008`), linked by shared host (`WKS-EU-0231`), user (`jsmith`), and two of the shared IPs — exactly the intended intrusion-chain behavior.
- **A window-boundary case worth remembering**: `edr-9003` and `sig-0005` share the *exact same* host and user (`bpatel`/`WKS-EU-0450`) but stayed in **separate** cases, because they're about 13 hours apart. Strong entity match, correctly overridden by the time window — proof the window is actually doing work, not just theoretical.
- **`sig-0002` and `edr-9004`** (ground-truth `case-002` and `case-003`) both stayed as singletons, correctly separate despite sharing the external IP `45.146.164.12` about 2h45m apart — the documented boundary judgment call from `cluster.py`'s docstring, now locked in as a regression test.
- **`edr-9005` and `sig-0008`** (both benign, same host, same external vendor-update IP, 30 minutes apart) correctly merged into a 2-alert case — a good reminder that a "case" just means "believed related," not "malicious."

## State at end of Week 3
- 75/75 tests passing.
- `data/raw_samples/sigma_synthetic.json` and `data/normalized_alerts.json` both updated (the `sig-0002` fix) — if you already committed the pre-fix version, this week's patch includes the corrected data files.

## Push checklist
```bash
cd soc-copilot
git am 0001-week3-correlation-engine.patch
pytest   # confirm 75/75 locally before pushing
git push
```

## Next session (Week 4)
- Agent core: define the Claude tool-use schema (`enrich_ip`, `enrich_hash`, `get_asset_context`), implement the agent loop over a `Case`, and produce a first structured verdict (severity, confidence, MITRE mapping, recommended action) with a full, inspectable reasoning trace.
