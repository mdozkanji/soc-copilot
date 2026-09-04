# Devlog 0010 — Week 5: RAG over threat intel

**Date**: 2026-09-03

## What we built
- `src/soc_copilot/rag/mitre_loader.py` — downloads and cleans the **real** MITRE ATT&CK Enterprise dataset (STIX 2.1, from MITRE's official `github.com/mitre/cti` repo, not fabricated), extracting 697 current techniques/sub-techniques into `data/mitre_attack_techniques.json`. Strips citation markers and HTML remnants from descriptions, excludes revoked/deprecated entries.
- `src/soc_copilot/rag/retriever.py` — a `Retriever` protocol, decoupling `search_mitre` from any one retrieval technology. **Applied the same lesson as Week 4's `llm_types.py` proactively this time**, instead of learning it the hard way again.
- `src/soc_copilot/rag/tfidf_retriever.py` — the default backend: TF-IDF + cosine similarity, pure `scikit-learn`, zero network dependency, verified fully end-to-end in this sandbox.
- `src/soc_copilot/rag/chroma_retriever.py` — the "textbook" dense-embedding backend via Chroma. Code-complete, integration logic unit-tested against a deterministic fake embedding function, but real semantic quality is **unverified from here** — this sandbox has no network path to `huggingface.co` (confirmed directly: `host_not_allowed`), which is where a real sentence-transformer model's weights would download from.
- `src/soc_copilot/agent/tools.py` / `loop.py` — wired `search_mitre` in as a fifth tool, dispatched like the others, with a new system-prompt rule telling the agent to confirm technique IDs via retrieval rather than its own memory.
- `eval/retrieval_eval.py` — a real, quantitative retrieval-quality evaluation against `eval/labels.json`'s ground-truth MITRE techniques.
- 18 new tests across `test_mitre_loader.py`, `test_tfidf_retriever.py`, `test_chroma_retriever.py`, plus a `search_mitre` dispatch test in `test_agent_loop.py`. 121 total.

## Why this substitutes for the original "ablation" deliverable
The build plan's Week 5 deliverable was an ablation comparing full agent verdicts with vs. without RAG — that needs live LLM calls, which are still blocked (devlog 0009). Rather than skip evaluation while that's unresolved, `eval/retrieval_eval.py` measures the piece that *is* fully testable without any live model: does `search_mitre` actually surface the correct technique at all? This is arguably more rigorous for what it covers (a clean IR metric against real ground truth, not a qualitative read of a few verdicts) while covering less (it says nothing about whether an LLM would use a correct retrieval well) — the original ablation is still worth doing once live agent runs are unblocked, on top of this, not instead of it.

## The real numbers, not polished
```
Strict top-1 accuracy:  2/10 (20%)
Lenient top-1 accuracy: 3/10 (30%)  (credits a correct parent/sub-technique)
Top-5 recall:           5/10 (50%)
Mean reciprocal rank:   0.350
```
Not a strong result, and reported as such. TF-IDF is lexical: it only works when a query shares vocabulary with the ATT&CK description. Concrete misses that illustrate exactly why:
- `sig-0004` (DGA beaconing) → retrieved "DNS Server" (an infrastructure-acquisition technique) instead of "Domain Generation Algorithms" — both mention DNS, TF-IDF can't tell that's coincidental.
- `sig-0009` (large outbound transfer) → retrieved "Ingress Tool Transfer" (bringing tools *in*) instead of "Exfiltration Over C2 Channel" (*taking data out*) — lexically close ("transfer"), semantically opposite direction.
- `edr-9004` (malicious Office macro) → missed "Malicious File" entirely.

This is exactly the limitation `tfidf_retriever.py`'s docstring names up front, now with real evidence behind it rather than just a stated caveat — and it's the concrete, evidenced case for why `chroma_retriever.py` (dense embeddings, which *would* catch semantic-but-not-lexical matches like these) is a real next step, not a nice-to-have.

## Two real bugs, caught by building the eval, not by hoping it worked
**1. My own eval methodology was throwing away relevant data.** `edr-9002` (a PowerShell reverse shell) completely missed T1059.001 — not even in the top 20 results. Investigated instead of just recording it as "TF-IDF is imprecise": the alert's `process_name` is literally `"powershell.exe"` and `command_line` contains the PowerShell invocation, but `_query_for_alert()` only used `rule_name` + `description`, never touching those fields. Fixed to include process/command-line evidence when present. Result: `edr-9002` went from missing entirely to rank 2. This also *reduced* one other case's rank (`edr-9006` dropped from exact top-1 to rank 2 — the added command-line text pulled its top match toward a genuinely related but different technique, "Compression" vs. "Archive Collected Data"), which is worth stating plainly rather than only reporting the win: a methodology fix isn't guaranteed to improve every case, and pretending otherwise would be exactly the kind of smoothing-over this project's devlogs are supposed to avoid.

**2. A second real Week 1 ground-truth imprecision**, found the same way the `sig-0002` host-field bug was found in Week 3 — by building something that actually checks the data against reality. `sig-0002` was labeled `T1046` (Network Service Discovery), but reading MITRE's actual description: that's a post-compromise technique, typically run *from* an already-compromised host. The alert describes an *external* pre-compromise port scan — the correct technique is `T1595` (Active Scanning, Reconnaissance tactic). Corrected in `eval/labels.json`, with the reasoning left in the label's own `notes` field, not silently changed.

## A test warning, fixed properly (updated after your push)
`chromadb` initially logged a `DeprecationWarning` about an unregistered custom embedding function during tests. First attempt (`get_config`/`build_from_config` added, no registration) only silenced part of it. Checked chromadb's actual `register_embedding_function` source directly instead of guessing further: it calls `cls.name()` as a classmethod during registration, without an instance -- the fake's `name(self)` being a plain instance method was the real cause. Fixed by making `name()` a `@classmethod` and decorating the class with `@register_embedding_function`. 121/121, zero warnings now.

## What's still unverified, honestly
- **`ChromaRetriever` with real embeddings** — code-complete, needs your machine: `pip install -e ".[embeddings]"` (installs `sentence-transformers`, downloads `all-MiniLM-L6-v2` on first use, ~80MB, one-time, no API key). Then `python -m soc_copilot.rag.cli --backend chroma "your query"` and compare against the same query on `--backend tfidf` (the default). Given the concrete lexical misses above, I'd genuinely expect embeddings to do better on the DGA and exfiltration cases specifically — curious whether that holds.
- **`search_mitre` inside a live agent run** — still blocked on the Groq issue from devlog 0009, unrelated to anything built this week.

## Push checklist
```bash
cd soc-copilot
git am 0008-feat-rag-mitre-retrieval.patch
pip install -e ".[dev]"   # picks up scikit-learn, chromadb
pytest                     # confirm 121/121
python -m soc_copilot.correlate.cli   # still works, unaffected
python -m eval.retrieval_eval         # see the real numbers yourself
```

## Next session (Week 6)
Verdicts, summaries, and the trust layer: formalize abstention ("insufficient evidence, escalate to human" as a first-class output), which this week's TF-IDF results make a concrete case for — a low-confidence retrieval result should visibly lower the agent's stated confidence, not get silently treated as ground truth.
