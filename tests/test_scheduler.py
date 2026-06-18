from datetime import datetime
import yaml
from app.db import db
from app.models import Event, Alert
from app.scheduler import run_one_cycle


def test_run_one_cycle_with_no_rules_does_not_error(app):
    run_one_cycle(app)
    assert Alert.query.count() == 0


def test_run_one_cycle_loads_rules_and_creates_alerts(app, monkeypatch, tmp_path):
    rule_data = {
        "id": "RULE-099",           # must match RULE-\d{3} for Pydantic validation
        "title": "Test Rule",
        "description": "Scheduler integration test rule.",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "test_event",
            "conditions": {"process_name": "evil.exe"},
        },
        "tags": [],
    }
    (tmp_path / "test_rule.yml").write_text(yaml.dump(rule_data))
    monkeypatch.setattr("app.scheduler.RULES_DIR", str(tmp_path))

    db.session.add(Event(
        timestamp=datetime(2026, 6, 15, 10, 0, 0),
        host="win-vm",
        event_type="test_event",
        process_name="evil.exe",
    ))
    db.session.commit()

    run_one_cycle(app)

    assert Alert.query.count() == 1
    assert Alert.query.first().rule_id == "RULE-099"
