from datetime import datetime
import pytest
from app.db import db
from app.feeds import feed_manager
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


def test_heatmap_lists_rules_grouped_by_tactic(client):
    response = client.get("/heatmap")

    assert response.status_code == 200
    assert b"Credential Access" in response.data
    assert b"T1110" in response.data
    assert b"covered" in response.data


def test_heatmap_marks_fired_techniques(client):
    db.session.add(Alert(
        created_at=datetime(2026, 6, 15, 10, 0, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[],
        details={},
    ))
    db.session.commit()

    response = client.get("/heatmap")

    assert response.status_code == 200
    assert b"fired" in response.data


def test_event_explorer_lists_events(client):
    db.session.add(Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="linux-vm",
        event_type="auth_failure",
        src_ip="203.0.113.50",
        raw="Failed password for root from 203.0.113.50",
    ))
    db.session.commit()

    response = client.get("/events")

    assert response.status_code == 200
    assert b"auth_failure" in response.data
    assert b"203.0.113.50" in response.data


def test_event_explorer_filters_by_host(client):
    db.session.add(Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="linux-vm",
        event_type="auth_failure",
    ))
    db.session.add(Event(
        timestamp=datetime(2026, 6, 15, 10, 1, 0),
        host="win-vm",
        event_type="process_creation",
    ))
    db.session.commit()

    response = client.get("/events?host=win-vm")

    assert response.status_code == 200
    assert b"process_creation" in response.data
    assert b"auth_failure" not in response.data


def test_event_explorer_filters_by_search(client):
    db.session.add(Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="win-vm",
        event_type="process_creation",
        command_line="powershell.exe -enc abc123",
    ))
    db.session.add(Event(
        timestamp=datetime(2026, 6, 15, 10, 1, 0),
        host="win-vm",
        event_type="process_creation",
        command_line="cmd.exe /c dir",
    ))
    db.session.commit()

    response = client.get("/events?search=-enc")

    assert response.status_code == 200
    assert b"-enc" in response.data
    assert b"/c dir" not in response.data


class _FakeFeedProcess:
    def __init__(self):
        self._terminated = False

    def poll(self):
        return None if not self._terminated else 0

    def terminate(self):
        self._terminated = True


@pytest.fixture(autouse=True)
def _isolated_feed_manager(monkeypatch):
    """Feed routes use the app.feeds singleton; fake Popen and reset its state
    around each test so feed control tests don't spawn real processes or leak
    state into other tests in the same session."""
    monkeypatch.setattr("app.feeds.subprocess.Popen", lambda *a, **k: _FakeFeedProcess())
    feed_manager.stop_all()
    yield
    feed_manager.stop_all()


def test_alert_feed_shows_feed_control_panel(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"Machine Monitor" in response.data
    assert b"Real Incident Logs" in response.data
    assert b"Synthetic Traffic" in response.data
    assert b"Stopped" in response.data


def test_start_feed(client):
    response = client.post("/feeds/machine/start")

    assert response.status_code == 302
    assert feed_manager.is_running("machine")


def test_stop_feed(client):
    client.post("/feeds/machine/start")
    response = client.post("/feeds/machine/stop")

    assert response.status_code == 302
    assert not feed_manager.is_running("machine")


def test_start_unknown_feed_flashes_error(client):
    response = client.post("/feeds/nonexistent/start", follow_redirects=True)

    assert response.status_code == 200
    assert b"Unknown feed" in response.data


def test_feed_panel_reflects_running_state(client):
    client.post("/feeds/incidents/start")
    response = client.get("/")

    assert response.status_code == 200
    assert b"Running" in response.data
