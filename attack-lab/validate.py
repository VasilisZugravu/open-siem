#!/usr/bin/env python3
"""Attack lab validation helper — polls /api/alerts after each scenario."""

import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCENARIOS = [
    {"num": "01", "name": "SSH Brute Force",    "folder": "01-ssh-bruteforce",     "ext": "sh",  "vm": "Linux",   "rule": "RULE-001", "technique": "T1110"},
    {"num": "02", "name": "Sudo Shadow Edit",   "folder": "02-sudo-shadow-edit",   "ext": "sh",  "vm": "Linux",   "rule": "RULE-002", "technique": "T1548.003"},
    {"num": "03", "name": "New Local User",     "folder": "03-useradd",            "ext": "sh",  "vm": "Linux",   "rule": "RULE-003", "technique": "T1136.001"},
    {"num": "04", "name": "Encoded PowerShell", "folder": "04-encoded-powershell", "ext": "ps1", "vm": "Windows", "rule": "RULE-004", "technique": "T1059.001"},
    {"num": "05", "name": "Office Spawns Shell","folder": "05-office-spawns-shell","ext": "ps1", "vm": "Windows", "rule": "RULE-005", "technique": "T1059"},
    {"num": "06", "name": "Scheduled Task",     "folder": "06-scheduled-task",     "ext": "ps1", "vm": "Windows", "rule": "RULE-006", "technique": "T1053.005"},
    {"num": "07", "name": "LSASS Memory Dump",  "folder": "07-procdump-lsass",     "ext": "ps1", "vm": "Windows", "rule": "RULE-007", "technique": "T1003.001"},
    {"num": "08", "name": "C2 Port Connection", "folder": "08-c2-port",            "ext": "ps1", "vm": "Windows", "rule": "RULE-008", "technique": "T1071"},
    {"num": "09", "name": "Brute Then Persist", "folder": "09-brute-then-persist", "ext": "sh",  "vm": "Linux",   "rule": "RULE-009", "technique": "T1136.001"},
    {"num": "10", "name": "LSASS Dump via comsvcs.dll", "folder": "10-lsass-comsvcs-dump", "ext": "ps1", "vm": "Windows", "rule": "RULE-010", "technique": "T1003.001"},
    {"num": "11", "name": "Encoded PowerShell Evasion", "folder": "11-encoded-powershell-evasion", "ext": "ps1", "vm": "Windows", "rule": "RULE-011", "technique": "T1059.001"},
    {"num": "12", "name": "certutil Decode",    "folder": "12-certutil-decode",     "ext": "ps1", "vm": "Windows", "rule": "RULE-012", "technique": "T1140"},
]

POLL_INTERVAL = 5
TIMEOUT = 60


def _poll_alert(siem_url, rule_id, since_iso, api_key=None, timeout=TIMEOUT):
    """Poll /api/alerts until an alert is found or timeout expires. Returns alert dict or None."""
    params = urllib.parse.urlencode({"rule_id": rule_id, "since": since_iso})
    url = f"{siem_url}/api/alerts?{params}"
    headers = {"X-Api-Key": api_key} if api_key else {}
    deadline = time.time() + timeout
    while True:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                alerts = json.loads(resp.read())
                if alerts:
                    return alerts[0]
        except (urllib.error.URLError, OSError):
            pass
        if time.time() >= deadline:
            return None
        time.sleep(POLL_INTERVAL)


def _read_previous_results(path):
    """Parse an existing COVERAGE.md's table into {scenario_num: result_str}, so a
    single-scenario run can preserve the other rows instead of wiping them back
    to the placeholder."""
    previous = {}
    if not os.path.exists(path):
        return previous
    with open(path, encoding="utf-8") as f:
        for line in f:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) != 6 or not cells[0].isdigit():
                continue
            previous[cells[0]] = cells[5]
    return previous


def _write_coverage_md(results, path):
    """Write COVERAGE.md. results: list of (scenario_dict, result_str) for all 8 scenarios."""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    lines = [
        "# Attack Lab Coverage",
        "",
        f"Last validated: {ts}",
        "",
        "| # | Scenario | VM | ATT&CK | Rule | Result |",
        "|---|----------|-----|--------|------|--------|",
    ]
    for s, result in results:
        lines.append(
            f"| {s['num']} | {s['name']} | {s['vm']} | {s['technique']} | {s['rule']} | {result} |"
        )
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _run_scenario(siem_url, scenario, api_key=None):
    """Prompt user to run script on VM, poll for alert. Returns '✅' or '❌'."""
    script = f"attack-lab/{scenario['folder']}/run.{scenario['ext']}"
    print(f"\n▶  Scenario {scenario['num']} — {scenario['name']} ({scenario['technique']})")
    print(f"   VM: {scenario['vm']}   Script: {script}")
    since_iso = datetime.datetime.utcnow().isoformat()
    input("   Press Enter when the script has been run on the VM...")
    print(f"   Polling {scenario['rule']}...", end="", flush=True)
    alert = _poll_alert(siem_url, scenario["rule"], since_iso, api_key=api_key)
    if alert:
        print(f" ✅  (alert id={alert['id']})")
        return "✅"
    print(f" ❌  (no alert within {TIMEOUT}s)")
    return "❌"


def main():
    parser = argparse.ArgumentParser(description="Validate attack lab scenarios against the SIEM.")
    parser.add_argument("--siem", default="http://localhost:5000", help="SIEM base URL")
    parser.add_argument("--scenario", metavar="NUM", help="Run only this scenario number, e.g. 01")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("INGEST_API_KEY"),
        help="X-Api-Key for /api/alerts (defaults to INGEST_API_KEY env var)",
    )
    args = parser.parse_args()

    to_run = SCENARIOS
    if args.scenario:
        to_run = [s for s in SCENARIOS if s["num"] == args.scenario]
        if not to_run:
            print(f"Unknown scenario: {args.scenario}", file=sys.stderr)
            sys.exit(1)

    coverage_path = "attack-lab/COVERAGE.md"
    previous = _read_previous_results(coverage_path)
    results = {s["num"]: (s, previous.get(s["num"], "⏳")) for s in SCENARIOS}
    for s in to_run:
        results[s["num"]] = (s, _run_scenario(args.siem, s, api_key=args.api_key))

    _write_coverage_md([results[n] for n in sorted(results)], coverage_path)
    print(f"\nCoverage table written to {coverage_path}")


if __name__ == "__main__":
    main()
