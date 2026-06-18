from datetime import datetime, timedelta

import yaml

from app.db import db
from app.models import Alert, Event
from app.detection.engine import evaluate_sequence_rules
from app.scheduler import run_one_cycle


# ── Shared fixtures ───────────────────────────────────────────────────────────

_BASE = datetime(2026, 1, 1, 12, 0, 0)  # fixed base time for deterministic tests

_RULE = {
    "id": "RULE-TEST-SEQ",
    "title": "Test Sequence Rule",
    "severity": "high",
    "attack_technique": "T9999",
    "attack_tactic": "Testing",
    "detection": {
        "sequence": [
            {"event_type": "step_one", "conditions": {}},
            {"event_type": "step_two", "conditions": {}},
        ],
        "correlate_by": "host",
        "timeframe_seconds": 600,
    },
}


def _event(host, event_type, ts):
    """Create, add, and commit a single Event; return it."""
    e = Event(timestamp=ts, host=host, event_type=event_type)
    db.session.add(e)
    db.session.commit()
    return e


# ── Unit tests: evaluate_sequence_rules() ────────────────────────────────────

def test_sequence_fires_alert_when_both_steps_on_same_host(app):
    e1 = _event("host-a", "step_one", _BASE)
    e2 = _event("host-a", "step_two", _BASE + timedelta(seconds=30))
    now = _BASE + timedelta(seconds=60)

    evaluate_sequence_rules([_RULE], now=now)

    db.session.expire_all()
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-TEST-SEQ"
    assert e1.id in alert.triggering_event_ids
    assert e2.id in alert.triggering_event_ids
    assert alert.details["host"] == "host-a"
    assert alert.details["step1_event"] == e1.id
    assert alert.details["step2_event"] == e2.id


def test_sequence_fires_when_step2_shares_step1_exact_timestamp(app):
    """Second-granularity timestamps (common with forwarders/replayed logs) can
    put both steps at the exact same instant — the strict '>' ordering used to
    exclude this, dropping a real correlated pair."""
    e1 = _event("host-a", "step_one", _BASE)
    e2 = _event("host-a", "step_two", _BASE)
    now = _BASE + timedelta(seconds=60)

    evaluate_sequence_rules([_RULE], now=now)

    db.session.expire_all()
    alerts = Alert.query.all()
    assert len(alerts) == 1
    assert e1.id in alerts[0].triggering_event_ids
    assert e2.id in alerts[0].triggering_event_ids


def test_sequence_no_alert_when_step2_before_step1(app):
    # step_two arrives BEFORE step_one — ordering must be enforced
    _event("host-a", "step_two", _BASE)
    _event("host-a", "step_one", _BASE + timedelta(seconds=10))
    now = _BASE + timedelta(seconds=60)

    evaluate_sequence_rules([_RULE], now=now)

    db.session.expire_all()
    assert Alert.query.count() == 0


def test_sequence_no_alert_when_step2_outside_window(app):
    # step_one at _BASE, step_two at _BASE + 601s (just outside 600s window)
    _event("host-a", "step_one", _BASE)
    _event("host-a", "step_two", _BASE + timedelta(seconds=601))
    # now is set so step_one IS within the initial query window (now - 600s = _BASE)
    now = _BASE + timedelta(seconds=601)

    evaluate_sequence_rules([_RULE], now=now)

    db.session.expire_all()
    assert Alert.query.count() == 0


def test_sequence_no_alert_when_different_hosts(app):
    _event("host-a", "step_one", _BASE)
    _event("host-b", "step_two", _BASE + timedelta(seconds=30))
    now = _BASE + timedelta(seconds=60)

    evaluate_sequence_rules([_RULE], now=now)

    db.session.expire_all()
    assert Alert.query.count() == 0


def test_sequence_cooldown_prevents_second_alert_in_same_window(app):
    # First pair fires an alert
    _event("host-a", "step_one", _BASE)
    _event("host-a", "step_two", _BASE + timedelta(seconds=10))
    now = _BASE + timedelta(seconds=60)
    evaluate_sequence_rules([_RULE], now=now)

    # Second pair on the same host, still within window — must NOT fire again
    _event("host-a", "step_one", _BASE + timedelta(seconds=100))
    _event("host-a", "step_two", _BASE + timedelta(seconds=110))
    now2 = _BASE + timedelta(seconds=120)
    evaluate_sequence_rules([_RULE], now=now2)

    db.session.expire_all()
    assert Alert.query.count() == 1


def test_sequence_skips_events_missing_correlate_by_field(app):
    """If the correlate_by field is absent on a step-1 event (corr_val=None),
    it must not be matched against other events that also lack the field —
    otherwise unrelated events get linked into a bogus alert."""
    rule_by_user = {
        "id": "RULE-TEST-SEQ-USER",
        "title": "Test Sequence Rule by user",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "sequence": [
                {"event_type": "step_one", "conditions": {}},
                {"event_type": "step_two", "conditions": {}},
            ],
            "correlate_by": "user",
            "timeframe_seconds": 600,
        },
    }
    # Neither event sets `user`, so correlate_by resolves to None on both.
    _event("host-a", "step_one", _BASE)
    _event("host-a", "step_two", _BASE + timedelta(seconds=30))
    now = _BASE + timedelta(seconds=60)

    evaluate_sequence_rules([rule_by_user], now=now)

    db.session.expire_all()
    assert Alert.query.count() == 0


# ── M3/L4: sequence-step determinism ─────────────────────────────────────────

def test_sequence_step2_selection_is_deterministic_on_equal_timestamps(app):
    """M3/L4: When multiple step-2 candidates share an identical timestamp,
    the one with the lowest id must always be selected (stable sort by id).
    Without the id tiebreak in order_by(), the pick is non-deterministic across
    DB engines."""
    _event("host-a", "step_one", _BASE)

    # Two step-2 candidates with exactly the same timestamp
    e2_a = _event("host-a", "step_two", _BASE + timedelta(seconds=5))
    _event("host-a", "step_two", _BASE + timedelta(seconds=5))

    now = _BASE + timedelta(seconds=60)
    evaluate_sequence_rules([_RULE], now=now)

    db.session.expire_all()
    alerts = Alert.query.all()
    assert len(alerts) == 1
    # The lower-id candidate must be picked regardless of DB ordering
    assert alerts[0].details["step2_event"] == e2_a.id


# ── Integration test: end-to-end via run_one_cycle ───────────────────────────

def test_sequence_rule_fires_via_run_one_cycle(app, monkeypatch, tmp_path):
    rule_data = {
        "id": "RULE-009",
        "title": "Brute Force Followed by Account Creation",
        "description": "SSH success followed by useradd on the same host.",
        "severity": "critical",
        "attack_technique": "T1136.001",
        "attack_tactic": "Persistence",
        "detection": {
            "sequence": [
                {"event_type": "auth_success", "conditions": {}},
                {"event_type": "command_execution", "conditions": {"command_line": {"contains": "useradd"}}},
            ],
            "correlate_by": "host",
            "timeframe_seconds": 600,
        },
        "tags": [],
    }
    (tmp_path / "rule009.yml").write_text(yaml.dump(rule_data))
    monkeypatch.setattr("app.scheduler.RULES_DIR", str(tmp_path))

    _event("linux-vm", "auth_success", datetime.utcnow() - timedelta(seconds=30))
    e = Event(
        timestamp=datetime.utcnow(),
        host="linux-vm",
        event_type="command_execution",
        command_line="useradd -m backdoor",
    )
    db.session.add(e)
    db.session.commit()

    run_one_cycle(app)

    db.session.expire_all()
    assert Alert.query.count() == 1
    assert Alert.query.first().rule_id == "RULE-009"
