> **Note:** live agent runs are currently blocked (see `devlog/0009-pausing-live-agent-verification.md`).
> Every piece of evidence in this report is real project data -- the case is from actually running
> `correlate()`, enrichment figures are real live results (VirusTotal/AbuseIPDB from
> `devlog/0002-week2-enrichment.md`, or a real `found: false` VirusTotal response where applicable), asset
> context is the real `data/asset_inventory.json` entry, and any MITRE match is the real Week 5 TF-IDF
> retriever's actual output for that exact query -- not cherry-picked. Only the verdict itself (severity,
> confidence, reasoning, recommended action) is hand-authored, standing in for what a live model would
> produce, so the *report format* can be reviewed now.

---

# Investigation Report — correlated-case-example

**1 alert(s)**, 2026-08-20T11:02:03+00:00 to 2026-08-20T11:02:03+00:00 · investigated in 1 iteration(s)

- **Hosts**: WKS-EU-0450
- **Users**: bpatel

## Verdict

**INFORMATIONAL** · confidence 25/100 — evidence marked **insufficient**

**Recommended action**: recommend escalate analyst

The only concrete signal is that the binary is unsigned and ran from a Downloads/Temp directory, which is common for both legitimate installers and malware droppers -- not distinguishing on its own. VirusTotal has no record of this file hash at all (found=false), which is genuinely ambiguous: it could mean the file is new/rare (consistent with either a fresh legitimate tool or unseen malware), not evidence in either direction. The asset is a standard Finance workstation with no elevated privileges, which caps the plausible impact but doesn't resolve whether this is malicious. There is no network, persistence, or lateral-movement signal in this alert to corroborate a malicious read, but there is also no user or business context confirming this was an expected/approved installation. Recommending human review rather than a confident call either way.

## Evidence gathered

- **enrich_hash**(sha256=b1115f55f0c9deb2ac758653b576d0d61b5e02f595a0adea54c6193a9a9b1264): not found in VirusTotal
- **get_asset_context**(hostname=WKS-EU-0450): medium-criticality, owner=bpatel
