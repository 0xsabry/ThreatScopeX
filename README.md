<p align="center">
  <img src="https://img.shields.io/badge/ThreatScope-DFIR-00d4ff?style=for-the-badge&logo=shield&logoColor=white" alt="ThreatScope"/>
</p>

<h1 align="center">🛡️ ThreatScope</h1>

<p align="center">
  <strong>Advanced DFIR & Threat Detection Platform</strong><br>
  <em>Open-source forensic analysis tool for SOC analysts, incident responders, and threat hunters.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/SigmaHQ-Rule%20Support-blue?style=flat-square" alt="Sigma Rules"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-141%20Techniques-red?style=flat-square" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/Detection%20Rules-57%20Categories-purple?style=flat-square" alt="Detection Rules"/>
  <img src="https://img.shields.io/badge/Modules-6-ff8c00?style=flat-square" alt="Modules"/>
  <img src="https://img.shields.io/badge/Author-0xSABRY-ff1744?style=flat-square" alt="Author"/>
</p>

---

## 🚀 What is ThreatScope?

ThreatScope is a **DFIR and threat detection platform** for SOC analysts, incident responders, and threat hunters. It combines Sigma rules, behavioral chain detection, AI-assisted analysis, and multi-platform log parsing into one tool — plus **6 newer modules** for advanced investigations: causal graph analysis, deep forensic artifact parsing, hypothesis-driven AI investigation, auto-deobfuscation, dynamic rule generation, and purple team MITRE verification.

> **Version note.** There is no released version newer than the `v3.0.0` tag, and `config.py` still reports `VERSION = "3.0.0"` — that is the version the running web application reports. The only release tag in this repository is `v3.0.0` (5 Mar 2026). The features described below as "V3" and the six newer modules were merged after that tag (commits `b787df1` and `89e0e3f`, Aug 2026) with no new tag and no version bump, so this README does **not** present the current code as an official "V3.5" release. The label "V3.5" survives only in commit messages and in some code comments. The six newer modules are standalone Python modules (`core/graph_engine.py`, `parsers/forensic_parsers.py`, `ai/agentic_core.py`, `core/deobfuscator.py`, `core/rule_gen.py`, `core/atomic_verifier.py`); they are **not** wired into the web dashboard (`app.py`) or the CLI (`cli.py`).

### 🆕 Newer modules (added after the v3.0.0 tag)

- 🔀 **Causal Graph & Process Lineage** — Builds directional process graphs from Sysmon/Security/auditd logs with automated Root Cause Analysis (RCA) backtracking and D3.js/Cytoscape.js export
- 🧩 **Deep Forensics Artifact Parsers** — Prefetch, $MFT, Shimcache, and Amcache parsers for Windows DFIR deep-dives with timestomping detection
- 🤖 **Hypothesis-Driven AI Copilot** — Autonomous investigation agent that generates, scores, and refines hypotheses with graded evidence collection
- 🔓 **Auto-Deobfuscation Engine** — Multi-layer recursive deobfuscation for PowerShell, Bash, and generic payloads with embedded C2 indicator extraction
- 📝 **Dynamic Rule Generator** — Auto-generates valid Sigma YAML and YARA signatures from deobfuscated payloads and behavioral patterns
- 🟣 **Purple Team MITRE Verifier** — Validates detection coverage against Atomic Red Team tests, builds ATT&CK Navigator layers, and identifies detection gaps

### Core features

- 🐧 **Full Linux Log Support** — Dedicated parsers for syslog, auth.log, journald, Apache/Nginx, and firewall logs
- 📡 **Live Log Monitoring** — Real-time WebSocket-based streaming with instant detection
- 🛡️ **44 Built-in YARA Rules** — Malware signatures, webshells, exploit tools, suspicious documents, Linux threats (counted: 44 `rule` definitions across the 5 files in `yara_rules/`)
- 🎯 **141 MITRE ATT&CK Techniques** — Technique descriptions in `intel/apt_mapper.py`; 14 tactics defined in `config.py` (see the MITRE section below for the tactic-mapping limit)
- ⚔️ **57 Detection Categories** — 27 original patterns plus 30 extended patterns (counted in `core/analyzer.py`, `BUILTIN_PATTERNS`)
- 🔐 **Security Hardened** — CSP headers, rate limiting, CSRF protection, input validation, audit logging
- 🕵️ **20 APT Groups** — Including Volt Typhoon, Scattered Spider, LockBit, ALPHV/BlackCat (counted in `intel/apt_mapper.py`, `APT_GROUPS`)
- 🔗 **30 Correlation Rules** — For Linux, cloud, and advanced attack chains (counted in `core/correlation.py`, `CORR-001`–`CORR-030`)
- ⛓️ **15 Behavioral Chains** — Multi-stage patterns for Linux and cloud attack sequences (counted in `core/behavioral_chain.py`, `BC-001`–`BC-015`)

### What ThreatScope does

- SigmaHQ rule support — sync Sigma rules from SigmaHQ and parse them (see below)
- YARA rules engine — 44 built-in rules
- Behavioral chain detection — 15 chains
- Multi-platform log parsing (Windows, Linux, macOS, cloud)
- Linux log parsing — 5 dedicated parsers
- Live log monitoring (WebSocket)
- Causal process graph & root cause analysis
- Deep forensics (Prefetch/MFT/Shimcache/Amcache)
- Hypothesis-driven AI investigation
- Auto-deobfuscation (PowerShell/Bash/generic)
- Dynamic Sigma & YARA rule generation
- Purple team MITRE verification (signature matching only — no live test execution)
- AI Copilot & narrative engine (requires an OpenAI API key; heuristic fallback without one)
- APT group attribution (20 groups)
- Threat intel enrichment (VirusTotal/AbuseIPDB/OTX — API keys required)
- Modern web dashboard
- 141 MITRE ATT&CK technique descriptions
- Security hardening (CSP/rate limiting/audit)
- False positive suppression
- Training mode for analysts
- Multi-format export (JSON/CSV/STIX/PDF/DOCX)

---

## ✨ Key Features

### 🔀 Causal Graph & Process Lineage (newer module)
- **Process Tree Construction** — Builds PPID→PID→Child graphs from Sysmon EventID 1, Security 4688, and auditd
- **Root Cause Analysis** — Automated backtracking to identify initial compromise process
- **Network Overlay** — Maps network connections (Sysmon 3) to process nodes
- **File Modification Tracking** — Links file operations (Sysmon 11/15) to responsible processes
- **Multi-Format Export** — D3.js force-directed, Cytoscape.js, GraphML, DOT, and JSON
- **Anomaly Detection** — Identifies suspicious process chains, orphan processes, and injection patterns
- **NetworkX Integration** — Optional advanced graph analysis with centrality and community detection

### 🧩 Deep Forensics Parsers (newer module)
- **Prefetch Parser** — Execution evidence with run counts, last execution timestamps, and referenced files
- **$MFT / UsnJrnl Parser** — File system timeline reconstruction with timestomping detection (MACB analysis)
- **Shimcache Parser** — AppCompatCache historical execution evidence with path extraction
- **Amcache Parser** — SHA1 hashes, install metadata, and publisher information for binaries
- **Normalized Output** — All parsers produce ThreatFinding-compatible output

### 🤖 Hypothesis-Driven AI Copilot (newer module)
- **Autonomous Investigation** — Multi-phase workflow: Triage → Hypothesis → Evidence → Analysis → Conclusion
- **Hypothesis Engine** — Generates ranked investigative hypotheses (AI-powered or heuristic fallback)
- **Evidence Collector** — Systematically gathers and grades evidence (Strong/Moderate/Weak/Contradictory)
- **Confidence Scoring** — Auto-computed hypothesis confidence from weighted evidence
- **Investigation Reports** — Structured reports with executive summary and recommended actions
- **Interactive Q&A** — Drill-down conversations grounded in investigation data

### 🔓 Auto-Deobfuscation Engine (newer module)
- **PowerShell Deobfuscation** — Base64, backtick escapes, format strings (-f), XOR payloads, char() arrays, environment variable replacement
- **Bash Deobfuscation** — Command concatenation, hex encoding, base64 pipes, $() substitution, eval chains
- **Generic Deobfuscation** — URL encoding, HTML entities, Unicode escapes
- **Recursive Processing** — Multi-layer deobfuscation with configurable depth limits
- **C2 Extraction** — Automatically extracts IPs, domains, URLs from deobfuscated payloads
- **Deobfuscation Pipeline** — Chain multiple deobfuscators with detailed step-by-step trace

### 📝 Dynamic Rule Generator (newer module)
- **Sigma Rule Generation** — Auto-generates valid SigmaHQ-format YAML rules with field selections and conditions
- **YARA Rule Generation** — Produces YARA signatures with string/hex/regex patterns from payloads
- **MITRE ATT&CK Mapping** — Auto-maps generated rules to techniques and tactics
- **Finding-Based Generation** — Creates detection rules directly from analysis findings
- **Behavioral Pattern Rules** — Generates rules from behavioral chain detections
- **Metadata Enrichment** — Includes author, date, severity, description, and references

### 🟣 Purple Team MITRE Verifier (newer module)
- **Atomic Red Team Integration** — Loads and parses Atomic Red Team YAML test catalogs
- **Simulation Evaluation** — Matches test signatures against Sigma rules and built-in patterns (no live execution)
- **Coverage Matrix** — Builds technique × data source × status coverage heatmaps
- **ATT&CK Navigator Export** — Generates Navigator-compatible JSON layers
- **Gap Analysis** — Identifies detection gaps with prioritized remediation recommendations
- **Maturity Scoring** — Per-tactic maturity scoring for compliance and reporting
- **Built-in Test Stubs** — 20 pre-loaded tests for critical techniques when no external tests available

### 🔍 Detection Power
- **57 Built-in Detection Categories** — Advanced regex patterns covering cloud, Linux, network, and application attacks (counted in `core/analyzer.py`)
- **SigmaHQ Integration** — Sync Sigma rules from the SigmaHQ repository and parse them with condition evaluation (AND/OR/NOT, selections, value modifiers). The number of synced rules depends on the upstream corpus at sync time; only 1 example rule is bundled in `sigma_rules/`
- **YARA Scanning** — 44 built-in rules for malware, webshells, exploit tools, and suspicious documents (requires the optional `yara-python` package)
- **Behavioral Chain Detection** — 15 multi-stage attack patterns with time-window correlation
- **30 Correlation Rules** — Kill chain analysis and score boosting

### 🐧 Linux Log Support
- **Syslog Parser** — RFC 3164/5424 with facility/severity extraction
- **Auth Log Parser** — SSH login, sudo, PAM, account management events
- **Journald Parser** — systemd journal JSON exports with full metadata
- **Apache/Nginx Parser** — Access and error logs with suspicious request flagging
- **Firewall Parser** — iptables/nftables/ufw with action and protocol extraction

### 📡 Live Monitoring
- **Real-time Log Tailing** — Tail live log files with instant detection
- **Multi-file Monitoring** — Monitor multiple files simultaneously
- **Live Alert Stream** — Real-time alert cards with severity color-coding
- **Statistics Dashboard** — Events/sec, alerts, critical findings counters

### 🌐 Multi-Platform Parsers
- Windows EVTX & Sysmon
- Linux syslog, auth.log, journald, firewall
- Apache/Nginx access & error logs
- macOS Unified Logs
- AWS CloudTrail
- Azure Activity Logs
- GCP Cloud Audit Logs
- Generic text/syslog

### 🧠 AI Analysis Core
- **Attack Narrative Engine** — Generates professional incident reports from findings
- **Analyst Copilot** — Chat interface for Q&A grounded in session data
- **Training Mode** — Socratic educational approach for junior analysts
- **Agentic Copilot** — Autonomous hypothesis-driven investigation (newer module)

### 📡 Threat Intelligence
- VirusTotal, AbuseIPDB, AlienVault OTX API integration
- APT Group Attribution (20 groups: APT28, APT29, Lazarus, Volt Typhoon, Scattered Spider, etc.)
- CVE/NVD Feed with exploit checks
- Cached lookups with rate limiting

### 🎨 Modern Web UI
- Premium dark-themed cybersecurity aesthetic
- Interactive dashboards with severity charts
- Attack timeline visualization
- MITRE ATT&CK heatmap
- AI Copilot chat interface
- Live monitoring dashboard

### 🔐 Security Hardening
- Content Security Policy (CSP) headers
- X-Frame-Options, X-Content-Type-Options, HSTS
- In-memory rate limiting per IP with auto-blocking
- Input validation and path traversal prevention
- File upload magic byte validation
- Audit logging with IP anonymization

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/0xsabry/ThreatScopeX.git
cd ThreatScopeX

# Install dependencies
pip install -r requirements.txt

# Optional: Install AI and reporting features
pip install reportlab python-docx yara-python

# Optional: Install graph engine (newer modules)
pip install networkx
```

### Launch Web Dashboard

```bash
# Start the web interface
python app.py

# Or via CLI
python cli.py web --host 127.0.0.1 --port 5000
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

### CLI Analysis

```bash
# Analyze a Windows event log
python cli.py analyze path/to/Security.evtx -r

# Analyze a Linux auth.log
python cli.py analyze /var/log/auth.log -r

# Analyze with JSON export
python cli.py analyze path/to/access.log -o report.json -f json

# Analyze with STIX 2.1 export
python cli.py analyze path/to/events.json -o stix_bundle.json -f stix

# Sync Sigma rules from SigmaHQ
python cli.py sync
```

### Newer modules usage (Python API)

> These six modules are standalone Python modules. They are **not** wired into the web dashboard (`app.py`) or the CLI (`cli.py`); use them by importing them as shown below.

```python
# ── Process Graph & Root Cause Analysis ──
from core.graph_engine import ProcessGraph, RootCauseAnalyzer
graph = ProcessGraph()
graph.ingest_events(parsed_events)
rca = RootCauseAnalyzer(graph)
root_cause = rca.analyze(suspicious_pid=1234)
graph.export_d3_json("process_graph.json")

# ── Deep Forensics Parsing ──
from parsers.forensic_parsers import PrefetchParser, ShimcacheParser
pf = PrefetchParser()
findings = pf.parse_prefetch_csv("prefetch_timeline.csv")

# ── Auto-Deobfuscation ──
from core.deobfuscator import DeobfuscationPipeline
pipeline = DeobfuscationPipeline()
result = pipeline.process(obfuscated_payload)
print(result["final_output"])    # Clean payload
print(result["c2_indicators"])   # Extracted IPs/domains

# ── Dynamic Rule Generation ──
from core.rule_gen import SigmaRuleGenerator, YaraRuleGenerator
sigma_gen = SigmaRuleGenerator()
rule = sigma_gen.from_finding(finding_dict)
sigma_gen.save_rule(rule, "rules/custom_detection.yml")

# ── Purple Team MITRE Verification ──
from core.atomic_verifier import MITREVerifier
verifier = MITREVerifier()
verifier.load_atomics("atomic-red-team/atomics/")
report = verifier.run_full_assessment(sigma_engine=engine)
verifier.export_report("coverage.json", fmt="navigator")

# ── Hypothesis-Driven AI Investigation ──
from ai.agentic_core import AgenticCopilot
copilot = AgenticCopilot()
report = copilot.investigate(analysis_results)
print(report["executive_summary"])
copilot.ask("What evidence supports credential theft?")
```

### Live Monitoring

```bash
# Start web UI then navigate to /live-monitor
python app.py
# Open http://127.0.0.1:5000/live-monitor

# Or use the API:
curl -X POST http://127.0.0.1:5000/api/live/start \
  -H "Content-Type: application/json" \
  -d '{"path": "/var/log/auth.log"}'
```

### API Configuration

Set these environment variables for full functionality:

```bash
# AI Features
export OPENAI_API_KEY="your_key"

# Threat Intelligence
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"

# Security (optional)
export FLASK_SECRET_KEY="your_secret_key"
```

---

## 📁 Project Structure

```
ThreatScopeX/
├── app.py                      # Flask web application (security-hardened)
├── cli.py                      # Enhanced CLI interface
├── config.py                   # Global configuration
├── requirements.txt            # Dependencies
├── core/
│   ├── analyzer.py             # Main analysis orchestrator (57 patterns)
│   ├── sigma_engine.py         # Full Sigma rule parser
│   ├── sigma_sync.py           # SigmaHQ auto-sync
│   ├── behavioral_chain.py     # 15 multi-stage attack chains
│   ├── yara_engine.py          # YARA scanning engine
│   ├── ioc_extractor.py        # IOC extraction engine
│   ├── correlation.py          # 30 correlation rules
│   ├── false_positive.py       # FP suppression engine
│   ├── realtime_monitor.py     # File change monitoring
│   ├── live_monitor.py         # Live log tailing & detection
│   ├── security.py             # Security hardening module
│   ├── graph_engine.py         # Newer module: causal process graph & RCA
│   ├── deobfuscator.py         # Newer module: auto-deobfuscation engine
│   ├── rule_gen.py             # Newer module: dynamic Sigma/YARA generation
│   └── atomic_verifier.py      # Newer module: purple team MITRE verifier
├── parsers/
│   ├── log_parsers.py          # Multi-platform log parsers + auto-detection
│   ├── linux_parsers.py        # Dedicated Linux log parsers
│   └── forensic_parsers.py     # Newer module: deep forensics artifact parsers
├── intel/
│   ├── enrichment.py           # VT/AbuseIPDB/OTX enrichment
│   └── apt_mapper.py           # 20 APT groups + 141 MITRE techniques
├── ai/
│   ├── ai_core.py              # Narrative, Copilot, Training
│   └── agentic_core.py         # Newer module: hypothesis-driven AI investigation
├── export/
│   └── exporters.py            # JSON/CSV/STIX/PDF/DOCX
├── yara_rules/
│   ├── malware_signatures.yar  # Cobalt Strike, Mimikatz, ransomware, RATs
│   ├── webshells.yar           # PHP/ASP/JSP webshells
│   ├── exploit_tools.yar       # Privesc, credential dump, lateral movement tools
│   ├── suspicious_documents.yar# Malicious macros, PE in docs, PDF exploits
│   └── linux_threats.yar       # Rootkits, crypto miners, Linux backdoors
├── templates/                  # Jinja2 HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── analysis.html
│   ├── timeline.html
│   ├── mitre.html
│   ├── intel.html
│   ├── copilot.html
│   ├── rules.html
│   ├── settings.html
│   └── live_monitor.html       # Real-time monitoring UI
└── static/
    ├── css/style.css           # Premium dark theme
    └── js/app.js               # Frontend logic
```

---

## 🎯 MITRE ATT&CK Coverage

ThreatScope maps findings to **141 MITRE ATT&CK technique descriptions** (`intel/apt_mapper.py`, `MITRE_TECHNIQUE_DESCRIPTIONS`) and provides:
- Interactive heatmap visualization
- APT group attribution (20 groups)
- Kill chain coverage analysis
- Technique-to-tactic mapping
- Sub-technique resolution
- ATT&CK Navigator layer export from purple team verification

Note on tactics: 14 tactics are defined (`config.py`, `MITRE_TACTICS`). The built-in technique-to-tactic map (`core/atomic_verifier.py`, `TECHNIQUE_TACTIC_MAP`) covers 92 techniques across **12** tactics — Resource Development (TA0042) and Reconnaissance (TA0043) have no mapped techniques in that map, so "coverage across all 14 tactics" is not claimed here.

---

## 🛡️ Built-in Detection Categories (57)

Counted in `core/analyzer.py` (`BUILTIN_PATTERNS`): 57 top-level patterns, each with its own category — 27 original plus 30 extended.

### Original Categories (27)
1. Brute Force & Authentication Attacks
2. Credential Dumping (Mimikatz, LSASS)
3. Privilege Escalation (UAC Bypass, Token Manipulation)
4. Lateral Movement (PsExec, WMI, SMB)
5. Data Exfiltration
6. Persistence Mechanisms
7. Command & Control (Cobalt Strike, Empire)
8. Ransomware Indicators
9. Log Tampering & Anti-Forensics
10. Reverse Shells
11. SQL Injection
12. PowerShell Abuse
13. AV/Security Tool Tampering
14. Kerberoasting
15. Golden/Silver Ticket
16. Active Directory Reconnaissance
17. Phishing & Social Engineering
18. Network Discovery
19. WMI Abuse
20. Scheduled Task Persistence
21. Off-Hours Access
22. Bulk Download
23. Container Escape
24. ARP Poisoning
25. MFA Fatigue Attacks
26. JWT Token Abuse
27. AI Prompt Injection

### Extended Categories (30)
28. Linux SSH Brute Force
29. Linux Rootkit Indicators
30. Linux Cron Persistence
31. Linux Privilege Escalation
32. Cryptojacking
33. Supply Chain Attack
34. Cloud IAM Abuse
35. Cloud Storage Exfiltration
36. API BOLA/IDOR
37. DNS Tunneling
38. DGA Detection
39. WAF Bypass
40. SSRF Attacks
41. XXE Injection
42. Deserialization Attacks
43. Memory Injection
44. Boot Persistence
45. Firmware Attacks
46. Keylogger Activity
47. Clipboard Hijacking
48. Screen Capture
49. Crypto Wallet Theft
50. WiFi Attacks
51. USB Device Abuse
52. Email Compromise
53. Zero-Day Indicators
54. Fileless Malware
55. Active Directory DCSync
56. Cloud Logging Tampering
57. Linux Shell Escape

---

## 📊 Export Formats

| Format | Description |
|--------|-------------|
| JSON | Full analysis results with all findings and metadata |
| CSV | Flat findings table for spreadsheet analysis |
| STIX 2.1 | Standard threat intelligence sharing format |
| PDF | Professional executive report with charts |
| DOCX | Editable Word document for incident reports |
| ATT&CK Navigator | MITRE ATT&CK Navigator layer JSON (from the purple team verifier module) |

---

## 🕵️ APT Group Database (20 Groups)

| Group | Country | Aliases |
|-------|---------|---------| 
| APT28 | Russia | Fancy Bear, Sofacy, STRONTIUM |
| APT29 | Russia | Cozy Bear, NOBELIUM |
| APT41 | China | Winnti, BARIUM, Double Dragon |
| Lazarus | North Korea | HIDDEN COBRA, Zinc |
| APT1 | China | Comment Crew, PLA Unit 61398 |
| FIN7 | Russia | Carbanak, Carbon Spider |
| Sandworm | Russia | Voodoo Bear, IRIDIUM |
| Turla | Russia | Snake, Venomous Bear |
| APT32 | Vietnam | OceanLotus, Canvas Cyclone |
| MuddyWater | Iran | MERCURY, Static Kitten |
| **Kimsuky** | North Korea | Velvet Chollima, Thallium |
| **Gamaredon** | Russia | Primitive Bear, Shuckworm |
| **Charming Kitten** | Iran | APT35, Mint Sandstorm |
| **Hafnium** | China | Silk Typhoon |
| **Darkside** | Russia | BlackMatter |
| **REvil** | Russia | Sodinokibi, GoldSouthfield |
| **Volt Typhoon** | China | Bronze Silhouette |
| **Scattered Spider** | International | UNC3944, Roasted 0ktapus |
| **LockBit** | Russia | LockBit 3.0, LockBitSupp |
| **ALPHV/BlackCat** | Russia | BlackCat, Noberus |

*Bold = additions after the original 10 groups*

---

## ⚠️ Limitations — read before use

- **Rule-based detections need analyst validation.** Findings are pattern matches (regex, Sigma, YARA, correlation), not confirmed incidents. Treat every finding as a lead to investigate, not as proof of compromise.
- **AI features need an OpenAI API key.** Set `OPENAI_API_KEY`; without it the AI copilot and narrative engine fall back to a heuristic response, not real AI analysis.
- **Threat intel enrichment needs API keys.** VirusTotal, AbuseIPDB, and AlienVault OTX lookups require `VT_API_KEY`, `ABUSEIPDB_API_KEY`, and `OTX_API_KEY`. Without keys, enrichment is skipped.
- **Purple team verification matches signatures; it does not execute tests.** The MITRE verifier (`core/atomic_verifier.py`) matches Atomic Red Team test definitions against Sigma rules and built-in patterns. It does not run payloads or commands on any host, and its coverage score is a matching score, not a tested-detection result. The 20 built-in test stubs are definitions, not executed tests.
- **Live monitoring tails local log files; there is no agent.** Live monitoring watches files on the machine running ThreatScope (file tailing / watchdog or polling). It does not deploy agents to remote hosts.
- **Sigma sync depends on the upstream corpus.** Syncing clones the SigmaHQ repository; the number of rules obtained depends on that repository at sync time. Only 1 example rule is bundled in `sigma_rules/`.
- **YARA scanning needs `yara-python`.** The YARA engine is optional; without the package installed, YARA scanning is unavailable.
- **Two detection engines live in this repo — do not mix their counts.** The web application uses `core/analyzer.py` (57 patterns). The separate legacy desktop GUI `ThreatscopeX.py` (version 1.0) has its own `PATTERNS` dictionary with 308 regex rules across 25 categories. The 308 figure belongs to the legacy GUI only.
- **Six newer modules are not integrated.** The graph, forensic-parser, agentic-AI, deobfuscation, rule-generation, and MITRE-verifier modules exist as importable Python code and are documented above, but they are not wired into the web dashboard or CLI.
- **No validation run is bundled.** This repository ships no test suite; the counts in this README were verified by counting source definitions (see the version note above), not by executing the application.

## 📝 License

MIT License — see [LICENSE](LICENSE)

---

## 👨‍💻 Author

**Mohamed Sabry Hamdan (0xSABRY)**
- Cybersecurity Analyst | SOC | Incident Response | DFIR | Detection
- Open to suitable opportunities in Egypt and international remote roles that permit Egypt-based candidates
- [GitHub](https://github.com/0xsabry)

---

<p align="center">
  <strong>⭐ Star this repo if ThreatScope helps your investigations! ⭐</strong>
</p>
