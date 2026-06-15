from datetime import datetime, timedelta

BASE_URL = "http://localhost:5000"


def build_demo_events():
    """Build 13 synthetic events covering all 8 attack lab scenarios / detection rules."""
    now = datetime.utcnow()
    events = []

    # Scenario 1 (RULE-001, T1110): 6 failed SSH logins from one IP within 60s
    for i in range(6):
        events.append({
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            "host": "linux-vm",
            "event_type": "auth_failure",
            "user": "root",
            "src_ip": "203.0.113.50",
            "details": {"service": "sshd"},
            "raw": "Failed password for root from 203.0.113.50 port 51234 ssh2",
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

    return events


def main():
    import requests

    events = build_demo_events()
    for event in events:
        response = requests.post(f"{BASE_URL}/ingest", json=event)
        response.raise_for_status()
        print(f"ingested {event['event_type']} on {event['host']} -> id={response.json()['id']}")


if __name__ == "__main__":
    main()
