from datetime import datetime, timedelta
from app.db import db
from app.models import Event, Alert
from app.detection.engine import evaluate_single_event_rules, evaluate_aggregation_rules, event_to_dict

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


SSH_BRUTE_FORCE_RULE = {
    "id": "RULE-001",
    "title": "SSH Brute Force",
    "severity": "medium",
    "attack_technique": "T1110",
    "attack_tactic": "Credential Access",
    "detection": {
        "event_type": "auth_failure",
        "conditions": {"service": "sshd"},
        "aggregation": {"group_by": "src_ip", "threshold": 5, "timeframe_seconds": 60},
    },
}


def _add_failed_logins(count, src_ip="203.0.113.50", host="linux-vm", base_time=None):
    base_time = base_time or datetime.utcnow()
    for i in range(count):
        db.session.add(Event(
            timestamp=base_time + timedelta(seconds=i),
            host=host,
            event_type="auth_failure",
            src_ip=src_ip,
            details={"service": "sshd"},
        ))
    db.session.commit()


def test_aggregation_rule_fires_when_threshold_reached(app):
    _add_failed_logins(5)

    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE])

    alerts = Alert.query.all()
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-001"
    assert alerts[0].details["src_ip"] == "203.0.113.50"
    assert alerts[0].details["count"] == 5


def test_aggregation_rule_does_not_fire_below_threshold(app):
    _add_failed_logins(4)

    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE])

    assert Alert.query.count() == 0


def test_aggregation_rule_has_cooldown(app):
    _add_failed_logins(5)

    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE])
    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE])

    assert Alert.query.count() == 1


def test_aggregation_rule_groups_by_field_separately(app):
    _add_failed_logins(5, src_ip="203.0.113.50")
    _add_failed_logins(5, src_ip="198.51.100.7")

    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE])

    alerts = Alert.query.all()
    src_ips = {a.details["src_ip"] for a in alerts}
    assert src_ips == {"203.0.113.50", "198.51.100.7"}
