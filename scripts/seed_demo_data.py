import os
from datetime import datetime, timedelta

import requests

BASE_URL = "http://localhost:5000"
# Same env var the live forwarders read (forwarders/*.py) — lets this script
# authenticate against a SIEM that requires INGEST_API_KEY, same as them.
API_KEY = os.environ.get("SIEM_API_KEY") or os.environ.get("INGEST_API_KEY", "")


def post_event(base_url, event):
    headers = {"X-Api-Key": API_KEY} if API_KEY else {}
    response = requests.post(f"{base_url}/ingest", json=event, headers=headers)
    response.raise_for_status()
    return response.json()["id"]


def build_demo_events():
    """Build 18 synthetic events covering all 12 detection rules."""
    now = datetime.utcnow()
    events = []

    # Scenario 1 (RULE-001, T1110): 6 failed SSH logins from one IP within 60s
    for i in range(6):
        events.append({
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            "host": "linux-vm",
            "event_type": "auth_failure",
            "user": "root",
            "src_ip": "45.155.205.233",
            "details": {"service": "sshd"},
            "raw": "Failed password for root from 45.155.205.233 port 51234 ssh2",
        })

    # Scenario 2 (RULE-002, T1548.003): sudo visudo
    events.append({
        "timestamp": now.isoformat(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": "alice",
        "command_line": "sudo visudo",
        "details": {},
        "raw": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/visudo",
    })

    # Scenario 3 (RULE-003, T1136.001): useradd
    events.append({
        "timestamp": now.isoformat(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": "alice",
        "command_line": "useradd -m backdoor",
        "details": {},
        "raw": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor",
    })

    # Scenario 4 (RULE-004, T1059.001): encoded PowerShell
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
        "details": {"parent_process": "explorer.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 5 (RULE-005, T1059): Word spawns cmd.exe
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "details": {"parent_process": "winword.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 6 (RULE-006, T1053.005): scheduled task created
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "schtasks.exe",
        "command_line": "schtasks.exe /create /tn Updater /tr evil.exe /sc daily",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 7 (RULE-007, T1003.001): procdump targeting lsass
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "procdump.exe",
        "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 8 (RULE-008, T1071): outbound connection to C2 port 4444
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "network_connection",
        "user": "win-vm\\bob",
        "process_name": "powershell.exe",
        "dest_ip": "198.51.100.23",
        "details": {"dest_port": 4444},
        "raw": "Sysmon Event ID 3: Network Connection",
    })

    # Scenario 9 (RULE-009, T1136.001): auth_success followed by useradd on same host within 10 min
    events.append({
        "timestamp": now.isoformat(),
        "host": "linux-vm",
        "event_type": "auth_success",
        "user": "attacker",
        "src_ip": "45.155.205.233",
        "details": {"service": "sshd"},
        "raw": "Accepted password for attacker from 45.155.205.233 port 51234 ssh2",
    })
    events.append({
        "timestamp": (now + timedelta(seconds=10)).isoformat(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": "attacker",
        "command_line": "useradd -m backdoor2",
        "details": {},
        "raw": "attacker : TTY=pts/1 ; PWD=/home/attacker ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor2",
    })

    # Scenario 10 (RULE-010, T1003.001): LSASS dump via comsvcs.dll (rundll32 LOLBin)
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "rundll32.exe",
        "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 out.dmp full",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 11 (RULE-011, T1059.001): encoded PowerShell, case/long-form evasion of RULE-004
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "PowerShell.EXE",
        "command_line": "PowerShell.EXE -EnCoDedCommand SGVsbG8gV29ybGQ=",
        "details": {"parent_process": "explorer.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 12 (RULE-012, T1140): certutil used to decode a staged payload
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "certutil.exe",
        "command_line": "certutil.exe -decode payload.b64 payload.exe",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    return events


def seed_demo_admin():
    """Ensure a demo admin account exists so the live demo has working
    credentials without a manual `flask create-admin` step.

    ADMIN_PASSWORD must be set in the environment — this script will exit
    rather than create an account with a known default password.
    ADMIN_USERNAME defaults to 'admin' if not set.
    """
    import sys
    import os
    from app import create_app
    from app.cli import ensure_admin

    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        print(
            "ADMIN_PASSWORD is not set. Set it in the environment to seed a demo admin, "
            "or this script will exit to avoid creating an account with a known password."
        )
        sys.exit(1)
    # Don't start a second background scheduler thread — the live server
    # (or another seed run) already has one running against this DB.
    app = create_app({"START_SCHEDULER": False})
    with app.app_context():
        ensure_admin(username, password)
    print(f"Seeded admin user '{username}'.")


def main():
    import sys

    seed_demo_admin()

    events = build_demo_events()
    try:
        for event in events:
            event_id = post_event(BASE_URL, event)
            print(f"ingested {event['event_type']} on {event['host']} -> id={event_id}")
    except requests.exceptions.RequestException as e:
        print(f"Error: could not reach {BASE_URL} ({e}). Is the app running? Try `python run.py` first.")
        sys.exit(1)


if __name__ == "__main__":
    main()
