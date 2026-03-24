# 🔐 SSH Brute-Force Detection with Claude AI + Splunk

> **Automated SSH log analysis using Claude AI (via claude.ai) to detect brute-force attacks and unauthorized access on Linux servers.**

---

## 📌 Project Overview

This project demonstrates how **Claude AI** was used to fully automate the detection of SSH-based threats by querying a Splunk SIEM, correlating events, and surfacing actionable security findings — with zero manual SPL writing.

**What was detected:**
- ✅ All authorized SSH logins
- 🚨 Successful logins preceded by multiple failed attempts (brute-force indicators)
- 🔎 Connections without authentication
- 👤 High-risk accounts (`root`, `admin`) being targeted

---

## 🤖 How Claude AI Automated This

Claude AI was connected to Splunk via an **MCP (Model Context Protocol)** server and performed the following autonomously:

| Step | Action | Claude's Role |
|------|--------|---------------|
| 1 | Discover available Splunk indexes & sourcetypes | Ran `get_indexes_and_sourcetypes` |
| 2 | Search `ssh_logs_new.json` across all time | Generated & executed SPL query |
| 3 | Filter authorized logins | Parsed `auth_success=true` events |
| 4 | Correlate failures → success per IP/user | Multi-step SPL with `stats` + `mvfind` |
| 5 | Classify risk levels (High/Medium/Low) | Applied threshold logic |
| 6 | Present interactive results table | Rendered visual dashboard |

**No manual SPL was written. Claude generated, executed, and interpreted all queries.**

---

## 🚨 Key Findings

From `ssh_logs_new.json` (host: `LinuxServer`, date: `2025-04-24`):

### Authorized Logins
- **26 successful SSH logins** across 15 unique usernames
- Notable: `root` logged in successfully from an external IP

### Brute-Force Detections
- **50 source IPs** matched the pattern: *multiple failures → eventual success*
- Highest attempt count: **792 attempts** (`83.195.24.226` → `admin`)
- `root` account compromised from 4 distinct IPs

### Risk Distribution
| Risk Level | Threshold | Count |
|------------|-----------|-------|
| 🔴 High    | 500+ attempts | 13 IPs |
| 🟡 Medium  | 300–499 attempts | 22 IPs |
| 🟢 Low     | < 300 attempts | 15 IPs |

---

## 📁 Repository Structure

```
ssh-detection-project/
├── README.md                        # This file
├── splunk_queries/
│   ├── authorized_logins.spl        # Find all successful SSH logins
│   ├── brute_force_detection.spl    # Detect success-after-failure pattern
│   └── full_event_summary.spl       # Complete SSH event breakdown
├── scripts/
│   ├── analyze_ssh_logs.py          # Python post-processor for Splunk results
│   └── risk_classifier.py           # Classifies IPs by risk level
├── sample_data/
│   └── ssh_logs_sample.json         # Sample log format (anonymized)
├── docs/
│   └── detection_methodology.md     # How the detection logic works
└── results/
    └── findings_2025-04-24.md       # Full findings from this investigation
```

---

## 🛠️ Setup & Usage

### Prerequisites
- Splunk instance with SSH log data ingested
- [Claude AI](https://claude.ai) with MCP Splunk server configured
- Python 3.8+ (for standalone scripts)

### Splunk Log Ingestion
Ensure your Linux hosts forward SSH logs to Splunk:
```bash
# On target Linux host — configure Universal Forwarder to monitor:
# Debian/Ubuntu:  /var/log/auth.log
# RHEL/CentOS:    /var/log/secure
```

Set sourcetype to `linux_secure` or ingest JSON-formatted logs as shown in `sample_data/`.

### Running the Splunk Queries
Copy queries from `splunk_queries/` and run them in Splunk Search:
```spl
# Quick start — find all brute-force successes:
source="ssh_logs_new.json" | spath | eval src_ip='id.orig_h' 
| stats values(event_type) as events, sum(auth_attempts) as total_attempts by src_ip, username 
| where mvfind(events, "Multiple Failed") >= 0 AND mvfind(events, "Successful") >= 0 
| sort - total_attempts
```

### Running Python Scripts
```bash
pip install -r requirements.txt
python scripts/analyze_ssh_logs.py --input sample_data/ssh_logs_sample.json
```

---

## 🧠 Claude AI Integration

Claude was connected to Splunk using the **Splunk MCP Server**. This enabled Claude to:
- Call `search_splunk` with natural-language-driven SPL
- Call `get_indexes_and_sourcetypes` to explore available data
- Iteratively refine queries based on empty results
- Correlate multi-event patterns across sessions

**Example prompt used:**
> *"Search for any successful logins after multiple failures and create a table for the same"*

Claude autonomously translated this into a multi-step Splunk correlation query and returned a risk-ranked, interactive results table.

---

## 📊 Sample Log Format

Logs follow the [Zeek](https://zeek.org/) SSH log format (JSON):

```json
{
  "ts": "2025-04-24T10:20:09.522008Z",
  "uid": "SH8652402",
  "id.orig_h": "116.149.83.216",
  "id.orig_p": 15298,
  "id.resp_h": "204.226.108.67",
  "id.resp_p": 22,
  "proto": "tcp",
  "auth_success": true,
  "auth_attempts": 3,
  "event_type": "Successful SSH Login",
  "username": "john.doe"
}
```

---

## 🔒 Defensive Recommendations

Based on the findings, the following mitigations are recommended:

1. **Block all 50 flagged IPs** at the perimeter firewall
2. **Disable root SSH login**: Set `PermitRootLogin no` in `/etc/ssh/sshd_config`
3. **Enforce MFA** for all SSH access, especially privileged accounts
4. **Deploy fail2ban** to auto-ban IPs after N failed attempts:
   ```bash
   sudo apt install fail2ban
   # Default: bans after 5 failures for 10 minutes
   ```
5. **Rotate credentials** for all affected accounts (`root`, `admin`, `sysadmin`, `alice`, `john.doe`, etc.)
6. **Switch to key-based auth only**: Disable password authentication
   ```
   PasswordAuthentication no
   ```
7. **Set up Splunk alerts** using the queries in `splunk_queries/` for real-time detection

---

## 📜 License

MIT License — free to use, modify, and share.

---

## 🙏 Credits

- **Detection automation**: [Claude AI](https://claude.ai) by Anthropic
- **SIEM platform**: [Splunk](https://www.splunk.com/)
- **Log format**: [Zeek Network Security Monitor](https://zeek.org/)
