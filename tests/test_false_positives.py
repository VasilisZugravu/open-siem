"""
False-positive (true-negative) tests: assert that benign events do NOT trigger alerts.
Each test seeds one or more benign events, runs the relevant detection function,
and asserts Alert.query.count() == 0.
"""
from datetime import datetime, timedelta

from app.db import db
from app.models import Event, Alert
from app.detection.engine import (
    evaluate_single_event_rules,
    evaluate_aggregation_rules,
    evaluate_sequence_rules,
)

# ---------------------------------------------------------------------------
# Rule dicts (inline — no YAML loading)
# ---------------------------------------------------------------------------

_RULE_001 = {
    "id": "RULE-001", "title": "SSH Brute Force", "severity": "medium",
    "attack_technique": "T1110", "attack_tactic": "Credential Access",
    "detection": {
        "event_type": "auth_failure",
        "conditions": {"service": "sshd"},
        "aggregation": {"group_by": "src_ip", "threshold": 5, "timeframe_seconds": 60},
    },
}
_RULE_002 = {
    "id": "RULE-002", "title": "Sudo Shadow Edit", "severity": "high",
    "attack_technique": "T1548.003", "attack_tactic": "Privilege Escalation",
    "detection": {"event_type": "command_execution", "conditions": {"command_line": {"regex": "(shadow|visudo)"}}},
}
_RULE_003 = {
    "id": "RULE-003", "title": "New Local User", "severity": "medium",
    "attack_technique": "T1136.001", "attack_tactic": "Persistence",
    "detection": {"event_type": "command_execution", "conditions": {"command_line": {"contains": "useradd"}}},
}
_RULE_004 = {
    "id": "RULE-004", "title": "Encoded PowerShell", "severity": "high",
    "attack_technique": "T1059.001", "attack_tactic": "Execution",
    "detection": {"event_type": "process_creation", "conditions": {"process_name": "powershell.exe", "command_line": {"contains": "-enc"}}},
}
_RULE_005 = {
    "id": "RULE-005", "title": "Office Spawns Shell", "severity": "high",
    "attack_technique": "T1059", "attack_tactic": "Execution",
    "detection": {"event_type": "process_creation", "conditions": {"process_name": {"in": ["cmd.exe", "powershell.exe"]}, "parent_process": {"in": ["winword.exe", "excel.exe"]}}},
}
_RULE_006 = {
    "id": "RULE-006", "title": "Scheduled Task Created", "severity": "medium",
    "attack_technique": "T1053.005", "attack_tactic": "Persistence",
    "detection": {"event_type": "process_creation", "conditions": {"process_name": "schtasks.exe", "command_line": {"contains": "/create"}}},
}
_RULE_007 = {
    "id": "RULE-007", "title": "LSASS Memory Dump", "severity": "high",
    "attack_technique": "T1003.001", "attack_tactic": "Credential Access",
    "detection": {"event_type": "process_creation", "conditions": {"command_line": {"contains": "lsass"}}},
}
_RULE_008 = {
    "id": "RULE-008", "title": "C2 Port Connection", "severity": "high",
    "attack_technique": "T1071", "attack_tactic": "Command and Control",
    "detection": {"event_type": "network_connection", "conditions": {"dest_port": {"in": [4444, 4445]}}},
}
_RULE_009 = {
    "id": "RULE-009", "title": "Brute Then Persist", "severity": "critical",
    "attack_technique": "T1136.001", "attack_tactic": "Persistence",
    "detection": {
        "sequence": [
            {"event_type": "auth_success", "conditions": {}},
            {"event_type": "command_execution", "conditions": {"command_line": {"contains": "useradd"}}},
        ],
        "correlate_by": "host",
        "timeframe_seconds": 600,
    },
}
_RULE_010 = {
    "id": "RULE-010", "title": "LSASS Dump via comsvcs.dll", "severity": "high",
    "attack_technique": "T1003.001", "attack_tactic": "Credential Access",
    "detection": {
        "event_type": "process_creation",
        "conditions": {
            "process_name": "rundll32.exe",
            "command_line": {"regex": "(?i)comsvcs\\.dll.*minidump"},
        },
    },
}
_RULE_011 = {
    "id": "RULE-011", "title": "Encoded PowerShell (Case/Long-Form Evasion)", "severity": "high",
    "attack_technique": "T1059.001", "attack_tactic": "Execution",
    "detection": {
        "event_type": "process_creation",
        "conditions": {
            "process_name": {"regex": "(?i)^powershell\\.exe$"},
            "command_line": {"regex": "(?i)-enc"},
        },
    },
}
_RULE_012 = {
    "id": "RULE-012", "title": "certutil Used to Decode a File", "severity": "medium",
    "attack_technique": "T1140", "attack_tactic": "Defense Evasion",
    "detection": {
        "event_type": "process_creation",
        "conditions": {
            "process_name": "certutil.exe",
            "command_line": {"regex": "(?i)-decode"},
        },
    },
}

# Fixed base time used by sequence tests
_BASE = datetime(2026, 1, 1, 12, 0, 0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_fp_rule001_below_threshold(app):
    """4 auth_failure events from same src_ip — threshold is 5, no alert expected."""
    now = datetime.utcnow()
    for i in range(4):
        db.session.add(Event(
            timestamp=now + timedelta(seconds=i),
            host="linux-vm",
            event_type="auth_failure",
            src_ip="1.2.3.4",
            details={"service": "sshd"},
        ))
    db.session.commit()

    evaluate_aggregation_rules([_RULE_001], now=datetime.utcnow())

    assert Alert.query.count() == 0


def test_fp_rule002_benign_command(app):
    """command_execution 'apt update' — does not match shadow/visudo regex."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="linux-vm",
        event_type="command_execution",
        command_line="apt update",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_002])

    assert Alert.query.count() == 0


def test_fp_rule003_benign_command(app):
    """command_execution 'systemctl status sshd' — no 'useradd' present."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="linux-vm",
        event_type="command_execution",
        command_line="systemctl status sshd",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_003])

    assert Alert.query.count() == 0


def test_fp_rule004_powershell_no_enc(app):
    """powershell.exe running Get-Process — no '-enc' flag, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe Get-Process",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_004])

    assert Alert.query.count() == 0


def test_fp_rule005_cmd_from_explorer(app):
    """cmd.exe spawned by explorer.exe — parent is not winword/excel, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="cmd.exe",
        details={"parent_process": "explorer.exe"},
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_005])

    assert Alert.query.count() == 0


def test_fp_rule006_schtasks_query(app):
    """schtasks.exe /query — uses /query not /create, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="schtasks.exe",
        command_line="schtasks.exe /query",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_006])

    assert Alert.query.count() == 0


def test_fp_rule007_no_lsass_in_cmdline(app):
    """tasklist.exe /v — 'lsass' not in command line, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="tasklist.exe",
        command_line="tasklist.exe /v",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_007])

    assert Alert.query.count() == 0


def test_fp_rule008_normal_https_port(app):
    """network_connection to dest_port 443 — not 4444/4445, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="network_connection",
        details={"dest_port": 443},
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_008])

    assert Alert.query.count() == 0


def test_fp_rule009_different_hosts(app):
    """auth_success on host-a, useradd command on host-b — different hosts, sequence must not fire."""
    db.session.add(Event(
        timestamp=_BASE,
        host="host-a",
        event_type="auth_success",
    ))
    db.session.add(Event(
        timestamp=_BASE + timedelta(seconds=30),
        host="host-b",
        event_type="command_execution",
        command_line="useradd -m baduser",
    ))
    db.session.commit()

    evaluate_sequence_rules([_RULE_009], now=_BASE + timedelta(seconds=60))

    assert Alert.query.count() == 0


def test_fp_rule010_comsvcs_without_minidump(app):
    """rundll32.exe loads comsvcs.dll for an unrelated export (no 'minidump'), no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="rundll32.exe",
        command_line="rundll32.exe comsvcs.dll, ResolveTrustee",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_010])

    assert Alert.query.count() == 0


def test_fp_rule011_normal_case_no_enc_flag(app):
    """powershell.exe running a plain script with no -enc flag in any case, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -File deploy.ps1",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_011])

    assert Alert.query.count() == 0


def test_fp_rule012_certutil_hashfile(app):
    """certutil.exe -hashfile is routine certificate tooling, not -decode, no alert."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="certutil.exe",
        command_line="certutil.exe -hashfile report.pdf SHA256",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_012])

    assert Alert.query.count() == 0


# ---------------------------------------------------------------------------
# Detection-in-depth: alternate-technique-path / evasion coverage
#
# Each pair below replays the same adversary goal two ways: one that the
# original rule was written to catch, and one crafted to slip past it. The
# new rule (010/011) closes exactly that gap.
# ---------------------------------------------------------------------------

def test_evasion_lsass_comsvcs_bypasses_rule007(app):
    """comsvcs.dll MiniDump targets a PID, not the string 'lsass' — RULE-007 misses it."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 out.dmp full",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_007])

    assert Alert.query.count() == 0


def test_evasion_lsass_comsvcs_caught_by_rule010(app):
    """The same comsvcs.dll MiniDump command line that bypasses RULE-007 fires RULE-010."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 out.dmp full",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_010])

    assert Alert.query.count() == 1


def test_evasion_encoded_powershell_case_bypasses_rule004(app):
    """Randomized-case '-EnCoDedCommand' and 'PowerShell.EXE' bypass RULE-004's exact-case match."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="PowerShell.EXE",
        command_line="PowerShell.EXE -EnCoDedCommand JABzAD0AbgBlAHcA...",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_004])

    assert Alert.query.count() == 0


def test_evasion_encoded_powershell_case_caught_by_rule011(app):
    """The same case-randomized command line that bypasses RULE-004 fires RULE-011."""
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="PowerShell.EXE",
        command_line="PowerShell.EXE -EnCoDedCommand JABzAD0AbgBlAHcA...",
    ))
    db.session.commit()

    evaluate_single_event_rules([_RULE_011])

    assert Alert.query.count() == 1
