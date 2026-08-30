# Data notes — Week 1

## Dataset choice for v0.1

The pipeline ships with a **hand-authored synthetic sample set**: 10 generic-SIEM-style alerts (`data/raw_samples/sigma_synthetic.json`) and 6 EDR-style alerts (`data/raw_samples/edr_synthetic.json`), 16 total.

### Why synthetic-and-hand-crafted, not a public dataset, for Week 1

Options considered:

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| CICIDS2017/2018 | Real, widely cited, academic pedigree | Flow-level (packet features), not alert-shaped — would need a whole detection layer built first just to get something resembling a SIEM alert | Deferred |
| Splunk BOTS (Boss of the SOC) | Real, alert-and-case shaped, designed for SOC investigation practice | Large, licensing/access friction, ground truth not cleanly machine-readable per alert | Deferred |
| OTRF Security-Datasets (Mordor) + Sigma rules | Real attack simulations (Sysmon/Windows logs), ATT&CK-mapped, strong credibility for a PhD-facing writeup | Needs a Sigma rule engine (pySigma or similar) wired up just to *produce* alert-shaped records from raw logs — that's a whole extra subsystem before we can even test the normalizer | **Planned upgrade, not Week 1** |
| Hand-authored synthetic | Full control over schema coverage and edge cases, zero licensing questions, fast, lets us test normalization logic against deliberately messy/heterogeneous formats on day one | Not "real" data, smaller scale, could look thin in a portfolio if left as the *final* dataset | **Chosen for Week 1** |

The reasoning: Week 1's actual job is to prove out the `Alert` schema and the per-source normalization pattern — not to prove the detection logic is realistic. Hand-authoring the raw samples means we can deliberately engineer the kind of messiness real normalizers have to handle (a numeric severity score in one source vs. a level string in another, a nested vs. flat network block, a domain-qualified username vs. a bare one) and verify the normalizer handles all of it, with tests, before spending a week wiring up a Sigma engine we don't strictly need yet.

**This is a placeholder, not a final decision.** Before Week 8's evaluation section, we should swap in (or add alongside) a Mordor+Sigma-derived set for credibility — flagged explicitly in the build plan as a stretch item, and noted here so it doesn't get quietly forgotten.

### Dataset shape

16 alerts, one coherent multi-stage intrusion chain plus a couple of standalone incidents and a set of genuinely-benign-but-suspicious-looking alerts:

- **`case-001`** (host `WKS-EU-0231`, user `jsmith`): encoded PowerShell → DGA DNS beaconing → SMB lateral movement → scheduled-task persistence → LSASS credential dumping → reverse shell → archive staging → large outbound transfer. This is the one to use for correlation testing in Week 3 — it's designed to *not* trivially cluster by a single shared field alone (it spans multiple rule types and both sample sources).
- **`case-002`**: an unrelated external port scan.
- **`case-003`**: an unrelated malicious Office-macro incident on a different host/user.
- Five benign alerts, three of which are *deliberately* the "looks suspicious but isn't" kind (new-country VPN login that was legitimate travel, an unsigned installer that was legitimate internal tooling, a mistyped-password lockout) — these exist specifically to stress-test whether the agent (from Week 4 onward) can avoid over-triggering on surface-level suspicion alone.

### Ground truth

Lives in `eval/labels.json`, keyed by `source_alert_id` — **not** by the alert schema's own `alert_id`, which is a randomly generated UUID assigned at normalization time and isn't stable across re-runs. Labels are never loaded by the operational pipeline (ingest → correlate → agent), only by `eval/` code. See the docstring at the top of `src/soc_copilot/ingest/schema.py` for why this separation matters: real-world alerts never arrive with an answer key attached, and if labels leaked into the schema the agent could end up trivially "cheating."

## Schema design (`src/soc_copilot/ingest/schema.py`)

`Alert` is a small, opinionated subset of a real alert record, loosely inspired by OCSF entity naming. Key decisions:

- **Every field downstream code relies on is optional except the handful that are truly universal** (id, source, rule name, timestamp, severity, description). A DNS alert has no file hash; a file-drop alert may have no port. Code that reads `alert.src_ip` must handle `None` — this is enforced by having real alerts in the sample set that omit different fields, and tests that exercise the missing-field paths.
- **`raw` is always kept.** Normalization projects fields *out* of the original record, it never discards it. This matters twice: for debugging a wrong mapping, and for later stages (e.g. if the agent needs to inspect something the schema didn't anticipate).
- **`severity` reflects the *source tool's* assessment**, not the agent's. Later (Week 4 onward) the agent produces its own severity/confidence independently, and the two are allowed to disagree — a source alert marked "high" that the agent downgrades to "informational, confirmed benign" is a useful and expected outcome, not a bug.
- **Validation is deliberately light at this layer.** The sha256 and IP-shape validators exist to catch normalizer bugs early and loudly (and did — see the Week 1 devlog for the malformed sample hash they actually caught), not to do full RFC-correct parsing. A stricter IP parse happens at the enrichment stage in Week 2, where a malformed address would otherwise cause a wasted or failing API call.
