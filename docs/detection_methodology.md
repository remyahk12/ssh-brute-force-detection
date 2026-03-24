# Detection Methodology

## Overview

This document describes the detection logic used to identify SSH brute-force attacks via Splunk, automated by Claude AI.

---

## Log Format

Logs are in **Zeek SSH log format** (JSON), containing the following key fields:

| Field | Description |
|-------|-------------|
| `ts` | Timestamp (ISO 8601 UTC) |
| `id.orig_h` | Source IP address |
| `id.orig_p` | Source port |
| `id.resp_h` | Destination IP address |
| `id.resp_p` | Destination port (22 for SSH) |
| `auth_success` | `true` / `false` / `null` |
| `auth_attempts` | Number of authentication attempts |
| `event_type` | Categorized event label |
| `username` | Username used in the session |

### Event Types Observed

| Event Type | Meaning |
|-----------|---------|
| `Successful SSH Login` | `auth_success = true` |
| `Failed SSH Login` | `auth_success = false`, low attempt count |
| `Multiple Failed Authentication Attempts` | `auth_success = false`, high attempt count |
| `Connection Without Authentication` | `auth_success = null`, `auth_attempts = 0` |

---

## Detection 1: Authorized Logins

**Goal:** Find all legitimately authenticated sessions.

**Logic:**
```
auth_success = true
```

**Risk indicators within authorized logins:**
- `root` account logging in remotely
- Same username from multiple source IPs
- Service accounts (`svc_*`) with high attempt counts before success

---

## Detection 2: Brute-Force (Success After Failure)

**Goal:** Identify IPs that persisted through authentication failures and eventually succeeded.

**Logic (per `src_ip` + `username` pair):**
1. Collect all `event_type` values
2. Check if set contains any failure event AND a success event
3. Sum total `auth_attempts` across all sessions

**SPL implementation:**
```spl
| stats values(event_type) as events, sum(auth_attempts) as total_attempts by src_ip, username
| where mvfind(events, "Multiple Failed") >= 0 AND mvfind(events, "Successful") >= 0
```

**Why this matters:**
A single IP cycling through failed attempts and ultimately succeeding strongly indicates:
- Password spraying
- Credential stuffing
- Manual brute-force attack

---

## Risk Scoring

| Risk Level | Criteria | Recommended Action |
|------------|----------|--------------------|
| 🔴 High | 500+ total attempts | Immediate block + credential reset |
| 🟡 Medium | 300–499 total attempts | Block + investigate |
| 🟢 Low | < 300 total attempts | Monitor + alert |

---

## Claude AI's Role

Claude AI acted as an intelligent analyst:

1. **Explored** the Splunk environment autonomously (indexes, sourcetypes)
2. **Formulated** SPL queries from natural language instructions
3. **Iterated** when initial queries returned no results (adjusted time range, broadened search)
4. **Correlated** multi-event patterns across sessions
5. **Classified** findings by risk level
6. **Presented** an interactive, filterable results dashboard

This demonstrates that modern AI assistants can serve as force multipliers for security analysts — compressing hours of SIEM work into seconds.
