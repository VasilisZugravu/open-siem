from datetime import datetime
from app.db import db
from app.models import Alert, Event


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


def test_alert_detail_shows_triggering_events(client):
    event = Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="linux-vm",
        event_type="auth_failure",
        src_ip="203.0.113.50",
        raw="Failed password for root from 203.0.113.50",
    )
    db.session.add(event)
    db.session.commit()

    alert = Alert(
        created_at=datetime(2026, 6, 15, 10, 1, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[event.id],
        details={"src_ip": "203.0.113.50", "count": 5},
    )
    db.session.add(alert)
    db.session.commit()

    response = client.get(f"/alerts/{alert.id}")

    assert response.status_code == 200
    assert b"SSH Brute Force" in response.data
    assert b"203.0.113.50" in response.data


def test_alert_detail_404_for_missing_alert(client):
    response = client.get("/alerts/999")
    assert response.status_code == 404


def test_update_alert_status(client):
    alert = Alert(
        created_at=datetime(2026, 6, 15, 10, 1, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[],
        details={},
    )
    db.session.add(alert)
    db.session.commit()

    response = client.post(f"/alerts/{alert.id}/status", data={"status": "closed_tp"})

    assert response.status_code == 302
    assert Alert.query.get(alert.id).status == "closed_tp"


def test_update_alert_status_missing_status_field(client):
    alert = Alert(
        created_at=datetime(2026, 6, 15, 10, 1, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[],
        details={},
    )
    db.session.add(alert)
    db.session.commit()

    response = client.post(f"/alerts/{alert.id}/status", data={})

    assert response.status_code == 302
    assert Alert.query.get(alert.id).status == "new"


def test_update_alert_status_invalid_value(client):
    alert = Alert(
        created_at=datetime(2026, 6, 15, 10, 1, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[],
        details={},
    )
    db.session.add(alert)
    db.session.commit()

    response = client.post(f"/alerts/{alert.id}/status", data={"status": "deleted"})

    assert response.status_code == 302
    assert Alert.query.get(alert.id).status == "new"
