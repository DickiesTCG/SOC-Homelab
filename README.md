# SOC Homelab — Samuel Dickson

Hands-on blue-team projects: investigating network traffic and security logs, detecting attacker behaviour, and writing it up the way a SOC analyst would.

**Background:** MSc Cyber Security (Distinction), Bournemouth University · Cisco Certified CyberOps Associate (CBROPS)
**LinkedIn:** https://www.linkedin.com/in/samuel-d-b47839117

## Tools

Wireshark · Splunk (SPL) · Sysmon · Windows Event Logs · Kali Linux · VirusTotal · AbuseIPDB · CyberChef · MITRE ATT&CK

## Projects

| # | Project | Focus | Status |
|---|---------|-------|--------|
| 01 | [Malware Traffic Investigation](01-pcap-investigation/report.md) | Wireshark pcap analysis, host identification, IOC extraction | Complete |
| 02 | Brute-force logon detection | Splunk, Windows Event ID 4625/4624 | Planned |
| 03 | Obfuscated PowerShell detection | Sysmon, PowerShell script block logging | Planned |
| 04 | Scheduled-task persistence | Event ID 4698, Sysmon, MITRE T1053.005 | Planned |

## How each project is written up

Every report follows the same structure (see [templates/report-template.md](templates/report-template.md)):
Summary → Environment → Investigation → Timeline → Indicators of Compromise → MITRE ATT&CK mapping → Recommendations → What I learned.

## Safety note

Malicious pcaps and samples are **not** stored in this repository. All indicators are defanged (e.g. `hxxp://example[.]com`, `203.0.113[.]5`). Practice data comes from public training sources, credited in each report.
