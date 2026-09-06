# Devlog 0012 — Week 7: Minimal analyst UI + feedback loop

**Date**: 2026-09-05

## What we built
- `src/soc_copilot/api/` — a FastAPI app: `GET /cases` (queue), `GET /cases/{id}` (investigation report + review form), `POST /cases/{id}/review` (logs the decision), `GET /feedback` (the log itself). Server-rendered Jinja2 templates, plain HTML forms — no npm/React toolchain, since this project's differentiator is the pipeline, not frontend engineering, and FastAPI + Jinja2 needs nothing beyond what's already a backend dependency.
- `src/soc_copilot/api/store.py` — `AgentResultStore` (one JSON file per case) and `FeedbackStore` (an append-only JSONL log, one line per analyst decision, each entry self-contained with a verdict snapshot rather than depending on a join to mutable state).
- `src/soc_copilot/agent/sample_cases.py` — the two Week 6 illustrative examples, **moved into the library** (not left in `eval/`) specifically so `api/seed.py` and `eval/generate_sample_reports.py` share one real-data construction path instead of duplicating it.
- `src/soc_copilot/api/seed.py` — seeds the store with those two examples, since live agent runs are still blocked.
- 23 new tests (176 total), all via FastAPI's `TestClient` — no live server, no network, fully verified in this sandbox.

## A real bug caught before it ever shipped, not by a failing test
While wiring `api/seed.py`, I noticed `build_abstention_example()` (moved from `eval/`) hand-constructed a `Case` with a made-up `case_id` ("correlated-case-example") — harmless for a standalone Markdown file, but the API's `case_detail` route finds cases by running the real `correlate()` pipeline, which would **never** produce that ID. Checked what the real pipeline actually assigns before assuming anything: `correlated-case-006`. Rather than hardcode that (case IDs are enumeration-order-dependent, not stable identifiers — fragile to hand-copy), fixed it properly: `build_abstention_example()` now derives the real `Case` and `Alert` objects directly from `correlate()`'s actual output instead of reconstructing a stand-in. Caught by reading my own code before running it, not by a red test — same category as the `httpx._content.json` mistake back in Week 4.

## A test bug caught by actually debugging, not by guessing
`test_feedback_page_lists_reviews_most_recent_first` failed with `"accept"` appearing *before* `"second look"` in the rendered HTML — the opposite of the intended most-recent-first order. Printed the actual rendered table rows before assuming the ordering logic was wrong: the rows were correct. The word "accept" also appears in `base.html`'s shared `<style>` block (`button.accept { ... }`), which renders in every page's `<head>`, before any table content — a naive substring search matched the CSS class name, not the table cell. Fixed the assertion to search for `<td>accept</td>` specifically.

## A three-round warning-suppression saga, worth documenting because the actual cause was non-obvious
`StarletteDeprecationWarning` (from `fastapi.testclient`, about a future `httpx2` migration) resisted three different suppression attempts in a row: a message-regex `filterwarnings` ini entry, a module-targeted ini entry, a plain `warnings.filterwarnings()` call in `conftest.py`, and a `pytest_configure` hook -- all silently failed to match. Checked the warning's actual class hierarchy directly instead of trying a fourth variation blind: `StarletteDeprecationWarning` subclasses `UserWarning`, not `DeprecationWarning`. Every filter had been correctly failing to match a category the warning was never in. Fixed in one line once the real category was known (`tests/conftest.py`'s `pytest_configure` hook, category `UserWarning`). Worth keeping as a concrete example of "verify the actual mechanism, don't keep guessing at variations of the same wrong assumption."

## Why the feedback log matters more than any accuracy number
An empty `data/feedback_log.jsonl` is the correct starting state, not a gap -- it's user-generated (gitignored, like the enrichment cache and Chroma DB), and it's the actual point of this week: every accept/override becomes a self-contained, timestamped record of where the agent's calibration agreed or disagreed with a human. This is the dataset that would let a future session finally check the two "revisit later" promises this project has been carrying since Week 2 (the naive `likely_malicious_heuristic` thresholds) and Week 6 (the grounding auditor's soft warnings) against real human judgment instead of just internal consistency.

## Push checklist
```bash
cd soc-copilot
echo "data/chroma_db/" >> .gitignore
echo "data/feedback_log.jsonl" >> .gitignore
git am 0011-feat-analyst-review-ui-and-feedback-loop.patch
pip install -e ".[dev]"   # picks up fastapi, uvicorn, jinja2, python-multipart
pytest                     # confirm 176/176
uvicorn soc_copilot.api.app:app --reload --app-dir src
```
Then open **http://127.0.0.1:8000/cases** in a browser — this is the one deliverable from this whole project so far that's actually meant to be looked at, not just run from a terminal. Click into `correlated-case-008` (the malicious chain) and `correlated-case-006` (the abstention example), try Accept and Override, and check `/feedback` afterward. This is also the natural point for the screen-recorded walkthrough the original build plan called for -- I can't produce a video myself, but the app is fully functional for you to record if that's useful for a portfolio.

## Next session (Week 8)
Evaluation, docs, demo: the full triage eval harness across the labeled sample set (precision/recall/false-negative rate against `eval/labels.json`), the Week 5 RAG ablation once retrieval quality is the point again, and `docs/threat-model.md`. Also worth deciding then: keep chasing live Groq verification, or write up the free-tier saga (devlog 0005-0009) as its own honest section of the eval report, since "does this hold up against a real free-tier API" turned out to be a real, substantial part of this project's actual engineering story.
