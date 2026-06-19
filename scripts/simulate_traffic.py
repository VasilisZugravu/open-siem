"""Continuously stream a realistic mix of benign and attack events into /ingest.

Unlike seed_demo_data.py (a one-shot demo loader), this script runs forever (or for
--duration seconds), POSTing a few events per tick: mostly harmless background noise,
with an occasional attack scenario mixed in. Useful for watching the dashboard update
live instead of staring at a static snapshot.
"""
import argparse
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

BASE_URL = "http://localhost:5000"
# Same env var the live forwarders read (forwarders/*.py) — lets this script
# authenticate against a SIEM that requires INGEST_API_KEY, same as them.
API_KEY = os.environ.get("SIEM_API_KEY") or os.environ.get("INGEST_API_KEY", "")

HOSTS = ["linux-vm", "win-vm", "db-01", "web-02"]
LINUX_USERS = ["alice", "bob", "carol"]
WINDOWS_USERS = ["win-vm\\dave", "win-vm\\erin"]
BENIGN_IPS = ["10.0.0.{}".format(n) for n in range(2, 30)]
ATTACKER_IPS = ["45.155.205.233", "198.51.100.23", "203.0.113.50"]


def _now_iso(offset_seconds=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


# ---------------------------------------------------------------------------
# Benign traffic: should never match any rule in rules/*.yml
# ---------------------------------------------------------------------------

def build_benign_events():
    """One tick's worth of harmless background noise."""
    host = random.choice(HOSTS)
    events = []

    if host.startswith("linux") or host.startswith("db") or host.startswith("web"):
        events.append({
            "timestamp": _now_iso(),
            "host": host,
            "event_type": "auth_success",
            "user": random.choice(LINUX_USERS),
            "src_ip": random.choice(BENIGN_IPS),
            "details": {"service": "sshd"},
            "raw": "Accepted password",
        })
        events.append({
            "timestamp": _now_iso(),
            "host": host,
            "event_type": "command_execution",
            "user": random.choice(LINUX_USERS),
            "command_line": random.choice(["ls -la", "whoami", "df -h", "cat /etc/hosts"]),
            "details": {},
            "raw": "routine command",
        })
    else:
        events.append({
            "timestamp": _now_iso(),
            "host": host,
            "event_type": "process_creation",
            "user": random.choice(WINDOWS_USERS),
            "process_name": random.choice(["chrome.exe", "explorer.exe", "outlook.exe"]),
            "command_line": "",
            "details": {"parent_process": "explorer.exe"},
            "raw": "Sysmon Event ID 1: Process Create",
        })

    events.append({
        "timestamp": _now_iso(),
        "host": host,
        "event_type": "network_connection",
        "user": random.choice(LINUX_USERS + WINDOWS_USERS),
        "process_name": "chrome.exe",
        "dest_ip": "93.184.216.34",
        "details": {"dest_port": random.choice([443, 80])},
        "raw": "Sysmon Event ID 3: Network Connection",
    })
    return events


# ---------------------------------------------------------------------------
# Attack scenarios: each mirrors a signature from scripts/seed_demo_data.py /
# rules/*.yml, built fresh (current timestamps) so aggregation/sequence windows work.
# ---------------------------------------------------------------------------

def attack_ssh_bruteforce():
    """RULE-001 (T1110): 6 failed SSH logins from one IP within 60s."""
    now = datetime.now(timezone.utc)
    ip = random.choice(ATTACKER_IPS)
    return [
        {
            "timestamp": (now - timedelta(seconds=(5 - i) * 5)).isoformat(),
            "host": "linux-vm",
            "event_type": "auth_failure",
            "user": "root",
            "src_ip": ip,
            "details": {"service": "sshd"},
            "raw": f"Failed password for root from {ip} port 51234 ssh2",
        }
        for i in range(6)
    ]


def attack_sudo_shadow_edit():
    """RULE-002 (T1548.003): sudo visudo / shadow file edit."""
    return [{
        "timestamp": _now_iso(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": random.choice(LINUX_USERS),
        "command_line": random.choice(["sudo visudo", "sudo vi /etc/shadow"]),
        "details": {},
        "raw": "privilege escalation attempt",
    }]


def attack_useradd():
    """RULE-003 (T1136.001): new local user via useradd."""
    return [{
        "timestamp": _now_iso(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": random.choice(LINUX_USERS),
        "command_line": f"useradd -m backdoor{random.randint(1, 999)}",
        "details": {},
        "raw": "useradd persistence",
    }]


def attack_encoded_powershell():
    """RULE-004 (T1059.001): powershell.exe -enc ..."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
        "details": {"parent_process": "explorer.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


def attack_office_spawns_shell():
    """RULE-005 (T1059): Word/Excel spawns cmd.exe/powershell.exe."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": random.choice(["cmd.exe", "powershell.exe"]),
        "command_line": "cmd.exe /c whoami",
        "details": {"parent_process": random.choice(["winword.exe", "excel.exe"])},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


def attack_scheduled_task():
    """RULE-006 (T1053.005): schtasks.exe /create."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "schtasks.exe",
        "command_line": "schtasks.exe /create /tn Updater /tr evil.exe /sc daily",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


def attack_lsass_dump():
    """RULE-007 (T1003.001): procdump targeting lsass."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "procdump.exe",
        "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


def attack_c2_port():
    """RULE-008 (T1071): outbound connection to C2 port 4444/4445."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "network_connection",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "powershell.exe",
        "dest_ip": random.choice(ATTACKER_IPS),
        "details": {"dest_port": random.choice([4444, 4445])},
        "raw": "Sysmon Event ID 3: Network Connection",
    }]


def attack_brute_then_persist():
    """RULE-009 (T1136.001): auth_success followed by useradd on same host within 10 min."""
    now = datetime.now(timezone.utc)
    ip = random.choice(ATTACKER_IPS)
    return [
        {
            "timestamp": now.isoformat(),
            "host": "linux-vm",
            "event_type": "auth_success",
            "user": "attacker",
            "src_ip": ip,
            "details": {"service": "sshd"},
            "raw": f"Accepted password for attacker from {ip} port 51234 ssh2",
        },
        {
            "timestamp": (now - timedelta(seconds=5)).isoformat(),
            "host": "linux-vm",
            "event_type": "command_execution",
            "user": "attacker",
            "command_line": f"useradd -m backdoor{random.randint(1, 999)}",
            "details": {},
            "raw": "post-compromise persistence",
        },
    ]


def attack_lsass_comsvcs_dump():
    """RULE-010 (T1003.001): rundll32 comsvcs.dll MiniDump LOLBin."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "rundll32.exe",
        "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 out.dmp full",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


def attack_encoded_powershell_evasion():
    """RULE-011 (T1059.001): case/long-form -EncodedCommand evasion of RULE-004."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "PowerShell.EXE",
        "command_line": "PowerShell.EXE -EnCoDedCommand SGVsbG8gV29ybGQ=",
        "details": {"parent_process": "explorer.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


def attack_certutil_decode():
    """RULE-012 (T1140): certutil.exe -decode LOLBin."""
    return [{
        "timestamp": _now_iso(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": random.choice(WINDOWS_USERS),
        "process_name": "certutil.exe",
        "command_line": "certutil.exe -decode payload.b64 payload.exe",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    }]


ATTACK_SCENARIOS = [
    attack_ssh_bruteforce,
    attack_sudo_shadow_edit,
    attack_useradd,
    attack_encoded_powershell,
    attack_office_spawns_shell,
    attack_scheduled_task,
    attack_lsass_dump,
    attack_c2_port,
    attack_brute_then_persist,
    attack_lsass_comsvcs_dump,
    attack_encoded_powershell_evasion,
    attack_certutil_decode,
]


def build_tick_events(attack_prob):
    """One tick's worth of events: always some benign noise, sometimes an attack too."""
    events = build_benign_events()
    if random.random() < attack_prob:
        scenario = random.choice(ATTACK_SCENARIOS)
        events.extend(scenario())
    return events


def post_events(base_url, events):
    headers = {"X-Api-Key": API_KEY} if API_KEY else {}
    for event in events:
        response = requests.post(f"{base_url}/ingest", json=event, headers=headers)
        response.raise_for_status()
        print(f"ingested {event['event_type']} on {event['host']} -> id={response.json()['id']}")


def main():
    parser = argparse.ArgumentParser(description="Stream live benign + attack traffic into the SIEM.")
    parser.add_argument("--interval", type=float, default=3, help="seconds between ticks (default 3)")
    parser.add_argument("--attack-prob", type=float, default=0.3, help="probability of an attack per tick (default 0.3)")
    parser.add_argument("--duration", type=float, default=0, help="seconds to run; 0 = run forever (default 0)")
    parser.add_argument("--url", default=BASE_URL, help=f"SIEM base URL (default {BASE_URL})")
    args = parser.parse_args()

    start = time.monotonic()
    try:
        while True:
            events = build_tick_events(args.attack_prob)
            post_events(args.url, events)
            if args.duration and (time.monotonic() - start) >= args.duration:
                break
            time.sleep(args.interval)
    except requests.exceptions.RequestException as e:
        print(f"Error: could not reach {args.url} ({e}). Is the app running? Try `python run.py` first.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
