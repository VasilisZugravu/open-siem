from datetime import datetime, timedelta

from app.db import db
from app.models import Alert
from app.scheduler import run_one_cycle


# ── RULE-007: single-event path (process_creation command_line contains "lsass") ──

def test_single_event_triggers_lsass_alert(app):
    client = app.test_client()
    resp = client.post("/ingest", json={
        "timestamp": datetime.utcnow().isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "command_line": "C:\\procdump.exe -ma lsass.exe out.dmp",
    })
    assert resp.status_code == 201
    event_id = resp.get_json()["id"]

    run_one_cycle(app)

    db.session.expire_all()
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-007"
    assert alert.attack_technique == "T1003.001"
    assert alert.triggering_event_ids == [event_id]


# ── RULE-001: aggregation path (5 SSH auth failures from same IP within 60s) ──
# Timestamps must be near utcnow() — the engine filters to now - 60s window.
# Do NOT use a fixed past date or events will silently fall outside the window.

def test_five_ssh_failures_triggers_brute_force_alert(app):
    client = app.test_client()
    now = datetime.utcnow()
    for i in range(5):
        resp = client.post("/ingest", json={
            "timestamp": (now + timedelta(seconds=i)).isoformat(),
            "host": "linux-vm",
            "event_type": "auth_failure",
            "src_ip": "203.0.113.1",
            "details": {"service": "sshd"},
        })
        assert resp.status_code == 201

    run_one_cycle(app)

    db.session.expire_all()
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-001"
    assert alert.attack_technique == "T1110"


# ── RULE-001 negative: 4 failures (below threshold=5) must not fire ──
# Distinct from test_engine.py's unit test: proves the full HTTP→DB→engine
# chain does not false-fire, not just the engine's threshold math.

def test_four_ssh_failures_does_not_trigger_alert(app):
    client = app.test_client()
    now = datetime.utcnow()
    for i in range(4):
        client.post("/ingest", json={
            "timestamp": (now + timedelta(seconds=i)).isoformat(),
            "host": "linux-vm",
            "event_type": "auth_failure",
            "src_ip": "203.0.113.2",
            "details": {"service": "sshd"},
        })

    run_one_cycle(app)

    db.session.expire_all()
    assert Alert.query.count() == 0
