#!/usr/bin/env python3
"""
analyze_ssh_logs.py
-------------------
Standalone Python post-processor for Splunk SSH log exports.
Replicates the brute-force detection logic Claude AI used via Splunk MCP.

Usage:
    python analyze_ssh_logs.py --input ../sample_data/ssh_logs_sample.json
    python analyze_ssh_logs.py --input logs.json --output results.csv
"""

import json
import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime


RISK_THRESHOLDS = {
    "High": 500,
    "Medium": 300,
}

BRUTE_FORCE_EVENT_TYPES = {
    "Multiple Failed Authentication Attempts",
    "Failed SSH Login",
}
SUCCESS_EVENT_TYPE = "Successful SSH Login"


def load_logs(filepath: str) -> list[dict]:
    """Load JSON log file — supports both JSON array and newline-delimited JSON."""
    logs = []
    with open(filepath, "r") as f:
        content = f.read().strip()
        if content.startswith("["):
            logs = json.loads(content)
        else:
            for line in content.splitlines():
                line = line.strip()
                if line:
                    logs.append(json.loads(line))
    return logs


def classify_risk(total_attempts: int) -> str:
    if total_attempts >= RISK_THRESHOLDS["High"]:
        return "High"
    elif total_attempts >= RISK_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


def detect_brute_force(logs: list[dict]) -> list[dict]:
    """
    Detect IPs that had multiple failed auth attempts AND a successful login.
    Mirrors the Splunk SPL logic Claude generated:
        mvfind(events, "Multiple Failed") >= 0 AND mvfind(events, "Successful") >= 0
    """
    # Group by (src_ip, username)
    groups = defaultdict(lambda: {"event_types": set(), "total_attempts": 0, "destinations": set()})

    for log in logs:
        src_ip = log.get("id.orig_h", "unknown")
        username = log.get("username", "unknown")
        event_type = log.get("event_type", "")
        attempts = log.get("auth_attempts", 0) or 0
        dst_ip = log.get("id.resp_h", "")

        key = (src_ip, username)
        groups[key]["event_types"].add(event_type)
        groups[key]["total_attempts"] += attempts
        if dst_ip:
            groups[key]["destinations"].add(dst_ip)

    results = []
    for (src_ip, username), data in groups.items():
        has_failure = bool(data["event_types"] & BRUTE_FORCE_EVENT_TYPES)
        has_success = SUCCESS_EVENT_TYPE in data["event_types"]

        if has_failure and has_success:
            results.append({
                "src_ip": src_ip,
                "username": username,
                "total_attempts": data["total_attempts"],
                "risk_level": classify_risk(data["total_attempts"]),
                "destinations": ", ".join(sorted(data["destinations"])),
                "event_types": ", ".join(sorted(data["event_types"])),
            })

    results.sort(key=lambda x: x["total_attempts"], reverse=True)
    return results


def detect_authorized_logins(logs: list[dict]) -> list[dict]:
    """Extract all successful SSH login events."""
    return [
        {
            "timestamp": log.get("ts", ""),
            "username": log.get("username", ""),
            "src_ip": log.get("id.orig_h", ""),
            "dst_ip": log.get("id.resp_h", ""),
            "auth_attempts": log.get("auth_attempts", 0),
        }
        for log in logs
        if log.get("auth_success") is True
    ]


def print_table(rows: list[dict], title: str):
    if not rows:
        print(f"\n[{title}] No results found.\n")
        return
    print(f"\n{'='*70}")
    print(f"  {title}  ({len(rows)} entries)")
    print(f"{'='*70}")
    headers = list(rows[0].keys())
    col_widths = {h: max(len(h), max(len(str(r.get(h, ""))) for r in rows)) for h in headers}
    header_line = "  ".join(h.ljust(col_widths[h]) for h in headers)
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        print("  ".join(str(row.get(h, "")).ljust(col_widths[h]) for h in headers))
    print()


def write_csv(rows: list[dict], filepath: str):
    if not rows:
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"Results written to: {filepath}")


def main():
    parser = argparse.ArgumentParser(description="SSH Brute-Force Detector (Claude AI / Splunk replication)")
    parser.add_argument("--input", required=True, help="Path to JSON log file")
    parser.add_argument("--output", help="Optional CSV output file for brute-force results")
    args = parser.parse_args()

    print(f"\n🔍 SSH Log Analysis — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Input: {args.input}")

    logs = load_logs(args.input)
    print(f"   Loaded {len(logs)} log entries\n")

    # --- Authorized logins ---
    auth_logins = detect_authorized_logins(logs)
    print_table(auth_logins[:10], "Authorized SSH Logins (top 10)")

    # --- Brute-force detections ---
    bf_results = detect_brute_force(logs)
    print_table(bf_results, "Brute-Force Detections (Success After Multiple Failures)")

    # --- Risk summary ---
    high = sum(1 for r in bf_results if r["risk_level"] == "High")
    med = sum(1 for r in bf_results if r["risk_level"] == "Medium")
    low = sum(1 for r in bf_results if r["risk_level"] == "Low")
    print(f"Risk Summary:  🔴 High: {high}   🟡 Medium: {med}   🟢 Low: {low}")

    if args.output:
        write_csv(bf_results, args.output)


if __name__ == "__main__":
    main()
