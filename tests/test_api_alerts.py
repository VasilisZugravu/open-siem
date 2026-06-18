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


def test_api_alerts_invalid_since_returns_400(client):
    response = client.get("/api/alerts?since=not-a-date")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


# ── T2: /api/alerts rate limiter ─────────────────────────────────────────────

def test_api_alerts_rate_limit_blocks_at_limit(app, client, monkeypatch):
    """/api/alerts must return 429 when the per-IP counter reaches API_ALERTS_MAX_REQUESTS."""
    from app.dashboard import routes as dashboard_routes

    clock = {"t": 0.0}
    monkeypatch.setattr(dashboard_routes.time, "monotonic", lambda: clock["t"])

    app.extensions["api_alerts_rate"] = {
        "127.0.0.1": (dashboard_routes.API_ALERTS_MAX_REQUESTS, 0.0)
    }
    resp = client.get("/api/alerts")
    assert resp.status_code == 429
    assert "rate limit" in resp.get_json()["error"]


def test_api_alerts_rate_limit_resets_after_window(app, client, monkeypatch):
    """After the rate window expires the IP is unthrottled."""
    from app.dashboard import routes as dashboard_routes

    clock = {"t": 0.0}
    monkeypatch.setattr(dashboard_routes.time, "monotonic", lambda: clock["t"])

    app.extensions["api_alerts_rate"] = {
        "127.0.0.1": (dashboard_routes.API_ALERTS_MAX_REQUESTS, 0.0)
    }
    assert client.get("/api/alerts").status_code == 429
    clock["t"] = dashboard_routes.API_ALERTS_WINDOW_SECONDS + 1
    assert client.get("/api/alerts").status_code == 200
