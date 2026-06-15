from datetime import datetime
from app.db import db
from app.models import Alert


def test_alert_feed_with_no_alerts(client):
    response = client.get("/")
    assert response.status_code == 200


def test_alert_feed_shows_alerts(client):
    db.session.add(Alert(
        created_at=datetime(2026, 6, 15, 10, 0, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[1, 2, 3],
        details={"src_ip": "203.0.113.50", "count": 5},
    ))
    db.session.commit()

    response = client.get("/")

    assert response.status_code == 200
    assert b"SSH Brute Force" in response.data
    assert b"T1110" in response.data


def test_alert_feed_includes_chart_data(client):
    db.session.add(Alert(
        created_at=datetime(2026, 6, 15, 10, 0, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[1, 2, 3],
        details={},
    ))
    db.session.commit()

    response = client.get("/")

    assert b"hourlyChart" in response.data
    assert b"severityChart" in response.data
    assert b"medium" in response.data
