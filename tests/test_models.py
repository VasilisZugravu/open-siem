from datetime import datetime
from app.db import db
from app.models import Event, Alert


def test_create_and_query_event(app):
    event = Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="linux-vm",
        event_type="auth_failure",
        user="root",
        src_ip="203.0.113.50",
        details={"service": "sshd"},
        raw="Failed password for root from 203.0.113.50",
    )
    db.session.add(event)
    db.session.commit()

    fetched = Event.query.first()
    assert fetched.host == "linux-vm"
    assert fetched.event_type == "auth_failure"
    assert fetched.details == {"service": "sshd"}


def test_create_and_query_alert(app):
    alert = Alert(
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        triggering_event_ids=[1, 2, 3],
        details={"src_ip": "203.0.113.50", "count": 5},
    )
    db.session.add(alert)
    db.session.commit()

    fetched = Alert.query.first()
    assert fetched.status == "new"
    assert fetched.triggering_event_ids == [1, 2, 3]
    assert fetched.details["count"] == 5
