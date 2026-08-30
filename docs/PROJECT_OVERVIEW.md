# AI-Powered SOC Copilot — Project Overview

## 1. What it is

A locally-run, tool-calling LLM agent that plays the role of a **Tier-1 SOC analyst**. It takes in raw security alerts (from a SIEM/EDR or a sample dataset), figures out which ones actually matter, pulls in outside context to back up its reasoning, and hands a human analyst a structured, explainable triage verdict instead of a wall of raw logs.

Concretely, the pipeline is:

```
Alert(s) in  →  Normalize  →  Correlate (cluster related alerts)
             →  Agent loop: LLM decides which tools to call
                   ├─ enrich_ip(ip)          → AbuseIPDB / VirusTotal
                   ├─ enrich_hash(sha256)    → VirusTotal
                   ├─ search_mitre(query)    → local ATT&CK RAG index
                   ├─ search_past_cases(q)   → local incident RAG index
                   └─ get_asset_context(host)→ your asset inventory (mocked)
             →  Structured verdict: severity, confidence, MITRE mapping,
                recommended action, full reasoning trace with citations
             →  Analyst reviews, accepts/overrides → feedback logged
```

## 2. The problem it addresses

SOC teams are drowning in alerts, and most of them are noise:

- Alert fatigue is the single most cited SOC pain point — analysts routinely triage hundreds to thousands of alerts a day, and a large majority turn out to be benign or duplicate.
- Tier-1 work is repetitive by design: "is this IP known-bad, has this hash been seen before, does this match a known technique" — exactly the kind of multi-step lookup-and-summarize task an LLM with tool access is good at.
- Traditional automation (SOAR playbooks, static correlation rules) is brittle: it only handles cases someone anticipated in advance, and it produces no natural-language reasoning a human can audit.
- Classic ML classifiers (the pre-LLM approach) are black boxes — they output a score, not a justification, which makes analysts distrust and route around them.

The gap an LLM agent fills: **explainable, tool-grounded first-pass triage.** Every claim the agent makes ("this IP has 14 malicious detections on VirusTotal") is backed by an actual tool call the analyst can inspect — not a hallucinated guess and not an opaque score.

## 3. What it aims to provide

- **Noise reduction**: auto-close or down-rank alerts that are clearly benign, with a documented reason, so analysts spend time on the alerts that matter.
- **Investigation acceleration**: for alerts worth escalating, produce in seconds the enrichment and correlation work that currently takes a human analyst 10–20 minutes of manual pivoting across tools.
- **Explainability by construction**: because the agent's job is to call tools and summarize, not to emit a bare classification, every output is a reasoning trace with citations — this is the main way this project should differentiate itself from a "trust me, the model said so" toy.
- **A feedback loop**: analysts accept/override the agent's verdicts; that log becomes both an evaluation dataset (precision/recall against human ground truth) and, later, material for prompt/RAG refinement.

## 4. Why this is useful / whether it's necessary

It's not solving a problem nobody has — alert triage automation is one of the best-funded categories in security right now (see the landscape note below), which cuts two ways: it proves the pain is real and monetizable, but it also means the "necessity" case is really about *your* differentiated angle, not about inventing a new problem.

Your specific edge here, given your background:

- **Domain credibility.** You've managed a SOC. You know what "acceptable false positive rate" actually means to an analyst, what a real triage workflow looks like, and where automated tools usually fail in practice (alert schemas that don't match, enrichment APIs rate-limiting under load, playbooks that assume clean data). Most people building AI-SOC demos have neither.
- **Zero-Trust / IAM synergy with ZeTA.** Your ZeTA engine does continuous attribute-based access evaluation. A SOC copilot that *also* understands identity/access context (privileged account behaving anomalously, access pattern outside its normal ABAC policy) is a natural extension — it gives you a coherent research narrative across two projects: "continuous trust evaluation" on the access-control side, "continuous risk evaluation" on the detection side. That's a strong thread for a PhD proposal or a portfolio interview.
- **Verifiability as the actual contribution.** Anyone can wrap an LLM around alerts. The interesting engineering and (if you want it) research question is: *how do you make an LLM-based triage agent's output trustworthy enough for an analyst to actually act on it* — grounding, citation, calibrated confidence, refusal-to-decide when evidence is thin, and a measurable false-negative rate on real attack data. That's the part worth writing up.

## 5. Why it's interesting

- It sits exactly on the "agentic AI" wave (tool-calling, RAG, multi-step reasoning) applied to a domain — cybersecurity — where mistakes are expensive and explainability is non-negotiable, which is a much harder and more interesting problem than a generic chatbot.
- It forces you to engineer around real constraints: rate-limited third-party APIs, imperfect ground truth, adversarial inputs (an attacker who knows a triage LLM is reading the alert text), and the tension between autonomy and safety (should the agent ever be allowed to auto-close, or only recommend?).
- It produces very demoable artifacts: a before/after on a labeled alert set, a live investigation walkthrough, a written eval methodology — all things that read well in a portfolio, a startup pitch, or a PhD research statement.

## 6. Who is interested

- **SOC teams / MSSPs** — direct users; the buyer pain (analyst shortage, MTTR, alert fatigue) is well documented and is the reason this category attracted funding.
- **Security vendors** — SIEM/EDR/SOAR vendors are all racing to bolt an "AI analyst" onto their platform; a working open reference implementation is a credible talking point in interviews with these companies.
- **Investors / accelerators** — this is currently one of the most actively funded sub-categories in security (see landscape note).
- **PhD committees / DAAD reviewers** — a working system plus a rigorous evaluation write-up (false positive/negative rates, ablations on RAG vs. no-RAG, human-in-the-loop override rates) is exactly the kind of applied-systems contribution that pairs well with your ZT-ABAC manuscript and strengthens a "trustworthy autonomous security systems" research narrative.

## 7. Competitive landscape (context, not a moat)

As of mid-2026 this space is crowded and well capitalized: independent "AI SOC analyst" products (Dropzone AI, Prophet Security, Radiant Security, Simbian), platform-native copilots from the majors (CrowdStrike Charlotte AI, Microsoft Security Copilot, SentinelOne Purple AI, Google SecOps/Gemini), and hyperautomation plays (Torq HyperSOC). Buyer guides from mid-2026 describe the category as crowded to the point of confusion: many products use near-identical marketing language despite meaningfully different architectures, so evaluators are told to look past the marketing and check what's actually automated versus what still requires human sign-off. A recurring critique is that most of these tools enrich and triage individual alerts well, but don't retain institutional memory of how a specific SOC investigates, don't reuse reasoning from past incidents, and don't own a full response end-to-end — a reasonable niche for a smaller, opinionated, RAG-over-your-own-past-cases design to target instead of trying to out-automate the incumbents. The strongest current buyer-guide advice is to treat autonomy level as the top evaluation axis and to require any containment action to sit behind human approval, with a reversible action model and full audit trail — which lines up well with the recommend-don't-auto-execute posture this build plan takes.

**Practical takeaway for you:** don't try to compete on breadth of integrations (you can't, and you don't need to for a portfolio project). Compete on depth of explainability and rigor of evaluation on a fixed, honestly-reported dataset — that's a message a PhD committee and a technical interviewer both respond to, and it's realistic for one person to build in 8 weeks.

## 8. Scope decisions for this build (stated so we don't relitigate them weekly)

- **Data**: start with a public, labeled dataset rather than a live SIEM feed — cleaner ground truth, no data-access hurdles, reproducible for anyone reading your repo. Candidates: a subset of CICIDS2017/2018 style flow-labeled alerts, or hand-crafted Sigma-rule-generated synthetic alerts mapped to MITRE ATT&CK. We'll pick this concretely in Week 1.
- **Enrichment APIs**: VirusTotal (free tier, 4 req/min) and AbuseIPDB (free tier, 1000 req/day) — both are usable without paid access, which matters for a personal project.
- **LLM**: Claude via the Anthropic API, using native tool use (function calling). This is also a chance to get hands-on with the same agent-architecture skills (tool use, structured output, agent loops) that the AI-SOC vendors above are built on.
- **Stack**: Python (FastAPI backend, Pydantic for structured output, a lightweight vector DB — Chroma to start). Python instead of your ZeTA Node/TypeScript stack because the LLM-agent/RAG/eval tooling ecosystem is overwhelmingly Python-first; this is also a chance to broaden your stack for the portfolio rather than repeat it. Flag it now if you'd rather stay in TypeScript — easy to swap before Week 1 work starts.
- **Autonomy posture**: the agent recommends, it never auto-executes containment actions. This mirrors current buyer-guide best practice and keeps the project's threat model sane (an LLM should not be closing a real firewall port).
