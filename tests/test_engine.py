from datetime import datetime
from app.db import db
from app.models import Event, Alert
from app.detection.engine import evaluate_single_event_rules, event_to_dict

ENCODED_POWERSHELL_RULE = {
    "id": "RULE-004",
    "title": "Encoded PowerShell Command",
    "severity": "high",
    "attack_technique": "T1059.001",
    "attack_tactic": "Execution",
    "detection": {
        "event_type": "process_creation",
        "conditions": {
            "process_name": "powershell.exe",
            "command_line": {"contains": "-enc"},
        },
    },
}


def test_single_event_rule_creates_alert(app):
    event = Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="win-vm",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc abc123",
    )
    db.session.add(event)
    db.session.commit()

    evaluate_single_event_rules([ENCODED_POWERSHELL_RULE])

    alerts = Alert.query.all()
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-004"
    assert alerts[0].triggering_event_ids == [event.id]


def test_single_event_rule_no_match_no_alert(app):
    event = Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="win-vm",
        event_type="process_creation",
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
    )
    db.session.add(event)
    db.session.commit()

    evaluate_single_event_rules([ENCODED_POWERSHELL_RULE])

    assert Alert.query.count() == 0


def test_single_event_rule_does_not_reprocess_old_events(app):
    event = Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="win-vm",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc abc123",
    )
    db.session.add(event)
    db.session.commit()

    evaluate_single_event_rules([ENCODED_POWERSHELL_RULE])
    evaluate_single_event_rules([ENCODED_POWERSHELL_RULE])

    assert Alert.query.count() == 1


def test_event_to_dict_merges_details():
    event = Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="linux-vm",
        event_type="auth_failure",
        src_ip="203.0.113.50",
        details={"service": "sshd", "port": 22},
    )

    result = event_to_dict(event)
    assert result["src_ip"] == "203.0.113.50"
    assert result["service"] == "sshd"
    assert result["port"] == 22
