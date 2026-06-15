import json
from datetime import datetime
from app.db import db
from app.models import Alert


def _make_alert(**kwargs):
    defaults = dict(
        created_at=datetime(2026, 6, 16, 10, 0, 0),
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
    defaults.update(kwargs)
    a = Alert(**defaults)
    db.session.add(a)
    db.session.commit()
    return a


def test_api_alerts_returns_all(client):
    _make_alert()
    _make_alert(rule_id="RULE-004", title="Encoded PowerShell")
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 2


def test_api_alerts_filters_by_rule_id(client):
    _make_alert(rule_id="RULE-001")
    _make_alert(rule_id="RULE-004", title="Encoded PowerShell")
    response = client.get("/api/alerts?rule_id=RULE-001")
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["rule_id"] == "RULE-001"


def test_api_alerts_filters_by_since(client):
    _make_alert(created_at=datetime(2026, 6, 16, 9, 0, 0))
    _make_alert(created_at=datetime(2026, 6, 16, 11, 0, 0))
    response = client.get("/api/alerts?since=2026-06-16T10:00:00")
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["created_at"] == "2026-06-16T11:00:00"


def test_api_alerts_returns_correct_fields(client):
    _make_alert()
    response = client.get("/api/alerts")
    data = json.loads(response.data)
    assert set(data[0].keys()) == {"id", "rule_id", "title", "severity", "created_at", "host"}
