# Devlog 0002 — Week 2: Enrichment layer

**Date**: 2026-08-31

## What we built
- `src/soc_copilot/enrich/cache.py` — SQLite-backed TTL cache, single file, no extra service to run (Redis stays available for later if profiling ever demands it).
- `src/soc_copilot/enrich/rate_limit.py` — `RateLimiter` (in-process sliding window, e.g. VirusTotal's 4/min) and `DailyQuota` (persisted via the same cache, survives a restart, e.g. VT's 500/day and AbuseIPDB's 1000/day).
- `src/soc_copilot/enrich/models.py` — normalized `IPReputation`, `FileReputation`, `IPEnrichment` — the shape the agent will see from Week 4 on, independent of either vendor's raw JSON.
- `src/soc_copilot/enrich/virustotal.py` / `abuseipdb.py` — clients with retry/backoff on 429/5xx, no retry on 4xx auth/client errors, and per-request (not client-level) API-key headers.
- `src/soc_copilot/enrich/service.py` — `EnrichmentService`: the only thing anything else should ever call. Handles the private/internal-IP guard, multi-source merge, per-source graceful degradation, and a clearly-labeled-naive `likely_malicious_heuristic`.
- `src/soc_copilot/enrich/cli.py` — `python -m soc_copilot.enrich.cli --ip ... / --hash ...` for one-off live lookups.
- `.env.example`, `pyproject.toml` updated with `httpx` + `python-dotenv`.
- 43 new tests (63 total now), all using `httpx.MockTransport` — no live network calls anywhere in the suite.

## Real bugs caught this session (kept, not smoothed over)
1. **API key silently dropped on injected clients.** Both `VirusTotalClient` and `AbuseIPDBClient` originally only set the auth header in the branch that constructs their *own* `httpx.Client`. Every test injects its own client (that's the whole point of dependency injection for testability) — so every single test was silently sending zero auth headers, and the very first assertion checking for the header caught it immediately. Fixed by sending the key as an explicit per-request header instead of a client-level default, in both clients. This means it's now also correct in production for anyone who wants to inject a shared `httpx.Client` for connection pooling — the original design would have quietly broken that use case too.
2. **Test helper's `or` short-circuit leaked a `tmp_path` kwarg into the constructor.** `cache = kwargs.pop("cache", None) or SqliteCache(kwargs.pop("tmp_path") / ...)` only calls the second `kwargs.pop("tmp_path")` when the first `pop` returns falsy — so any test that explicitly passed its own `cache` never consumed `tmp_path` from kwargs, and it got forwarded straight into `VirusTotalClient(**kwargs)`, raising a `TypeError` about an unexpected argument. Fixed by popping `tmp_path` unconditionally before the `or` branches. Small, but a good reminder that `or`-based defaulting hides control flow in a way that's easy to get wrong in test helpers specifically, because test helpers are exactly the code most likely to get copy-pasted and extended without a second look.

## Design decisions worth remembering
- **Private/internal IPs are never queried at all**, checked *before* either client is touched — not just to save quota, but because AbuseIPDB actively 422s on them and VirusTotal simply has no data on your internal network. Verified this against the real Week 1 sample set: 8 of the 13 distinct IPs across all 16 alerts are internal and get skipped; the 5 external ones (including the Tor-exit-looking IP from the case-001 intrusion chain) would go out to both APIs.
- **Ground truth for "unknown" vs. "checked and clean" vs. "confirmed malicious" is kept as three distinct states** (`likely_malicious_heuristic` is `None`/`False`/`True` respectively), not collapsed into a boolean. This matters a lot for Week 6's abstention behavior — "we have no data" and "we checked and it's fine" should never be treated the same way by the agent.
- **The malicious-heuristic thresholds are explicitly flagged as provisional** in both the code and here: they exist to give Week 4's agent something structured to reason over (and override), not as the real triage logic. Revisit once Week 7's override log gives real signal.

## Live verification — confirmed working

You ran this locally against the real APIs and it worked cleanly, first try:

```bash
python -m soc_copilot.enrich.cli --ip 8.8.8.8            # heuristic: false
python -m soc_copilot.enrich.cli --ip 185.220.101.47      # heuristic: true
```

Checked the arithmetic against the real payloads to make sure "worked" actually meant *correct*, not just *didn't crash*:

| IP | VT malicious/total | AbuseIPDB score | `likely_malicious_heuristic` |
|---|---|---|---|
| `8.8.8.8` (Google DNS) | 0/91 | 0 | `false` — correct |
| `185.220.101.47` (Tor exit) | 15/91 (16.5%) | 100, `isTor: true` | `true` — correct |

Both trip the heuristic through a different path than expected on the surface, worth noting: the 15/91 ratio (16.5%) clears the >5% threshold on its own, and separately the `malicious_votes >= 3` condition also fires, and separately AbuseIPDB's score of 100 clears its own >=50 threshold — three independent signals agreeing, which is a much stronger case than any single threshold firing alone. For `8.8.8.8`, all three come back negative. Good sign for a first-pass heuristic, though two data points obviously isn't a real evaluation.

### A real data quirk worth remembering for later weeks

VirusTotal's raw IP response contains a field literally called `"total_votes"`:
```json
"total_votes": { "harmless": 291, "malicious": 59 }
```
This is **not** what our code means by `total_votes` on `IPReputation` (which is our own sum of `last_analysis_stats` — i.e. how many AV engines scanned the IP). VT's `total_votes` is a completely different thing: community up/down votes from VirusTotal users, unrelated to the engine detection count. Our normalizer never touches VT's `total_votes` key (it only reads `last_analysis_stats`), so there's no bug here — but the name collision is exactly the kind of thing that causes a real bug later if someone (me, an agent prompt, a future contributor skimming the raw JSON) assumes they're the same field. Worth a one-line comment in `virustotal.py` and worth remembering when we get to Week 5's RAG/agent work, where the model will see raw VT JSON and could plausibly make the same mistake.

Also spotted in the raw `8.8.8.8` response: a `crowdsourced_context` entry flagging it as an *"AsyncRAT botnet C2 server (confidence level: 100%)"* from a 2023 ThreatFox report — clearly stale/wrong for a well-known Google DNS anycast address. We don't parse `crowdsourced_context` at all currently, so it doesn't affect anything today, but it's a good concrete example of why Week 6's "insufficient evidence, escalate to human" abstention design matters: even reputable threat-intel sources carry noisy, outdated, or simply incorrect tags, and an agent that treats every field in a raw API blob as ground truth will eventually confidently repeat something wrong. Filed as a note for when Week 5 decides how much of the raw payload the agent gets to see versus just the normalized `IPReputation`.

## State at end of Week 2 (updated)
- 63/63 tests passing.
- Live-verified against both real APIs, correct on both a known-clean and a known-malicious IP.
- `data/enrichment_cache.sqlite3` is gitignored — it's a runtime artifact, not a fixture.

## Next session (Week 3)
- Correlation: entity-based clustering of `case-001`'s 8 alerts (and confirming `case-002`/`case-003` stay separate) into cases, using a rolling time window and shared entities (host/user/IP) as the join keys.
