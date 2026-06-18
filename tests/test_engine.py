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


def test_single_event_rule_does_not_fire_duplicate_if_open_alert_exists(app):
    """Status-gate: skip firing if a 'new' alert already exists for same rule+host."""
    from datetime import datetime
    from app.db import db
    from app.models import Alert, Event
    from app.detection.engine import evaluate_single_event_rules

    rule = {
        "id": "RULE-DUP",
        "title": "Dup Test",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "lsass_access",
            "conditions": {},
        },
    }

    # Seed an existing open alert for same rule+host
    existing = Alert(
        rule_id="RULE-DUP", title="Dup Test", severity="high",
        attack_technique="T9999", attack_tactic="Testing",
        host="win-vm", status="new",
        triggering_event_ids=[], details={},
    )
    db.session.add(existing)
    db.session.commit()

    # Seed a matching event
    e = Event(timestamp=datetime.utcnow(), host="win-vm", event_type="lsass_access")
    db.session.add(e)
    db.session.commit()

    evaluate_single_event_rules([rule])

    db.session.expire_all()
    assert Alert.query.count() == 1  # no new alert created


def test_single_event_rule_fires_again_after_cooldown_elapses_even_if_alert_still_open(app):
    """Dedup must be time-bounded: an un-triaged ('new') alert should not
    suppress detections forever once the cooldown window has passed."""
    from datetime import datetime, timedelta
    from app.db import db
    from app.models import Alert, Event
    from app.detection.engine import evaluate_single_event_rules

    rule = {
        "id": "RULE-DUP3",
        "title": "Dup Test 3",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "lsass_access",
            "conditions": {},
        },
    }

    old_alert = Alert(
        rule_id="RULE-DUP3", title="Dup Test 3", severity="high",
        attack_technique="T9999", attack_tactic="Testing",
        host="win-vm", status="new",
        triggering_event_ids=[], details={},
        created_at=datetime.utcnow() - timedelta(hours=2),
    )
    db.session.add(old_alert)
    db.session.commit()

    e = Event(timestamp=datetime.utcnow(), host="win-vm", event_type="lsass_access")
    db.session.add(e)
    db.session.commit()

    evaluate_single_event_rules([rule])

    db.session.expire_all()
    assert Alert.query.count() == 2  # cooldown elapsed, so a new alert fires


def test_single_event_rule_fires_for_different_entity_despite_open_alert(app):
    """Dedup should key on the triggering entity (e.g. src_ip), not just
    rule+host — a different attacker on the same host must still alert."""
    from datetime import datetime
    from app.db import db
    from app.models import Alert, Event
    from app.detection.engine import evaluate_single_event_rules

    rule = {
        "id": "RULE-DUP4",
        "title": "Dup Test 4",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "network_connection",
            "conditions": {},
        },
    }

    existing = Alert(
        rule_id="RULE-DUP4", title="Dup Test 4", severity="high",
        attack_technique="T9999", attack_tactic="Testing",
        host="win-vm", status="new",
        triggering_event_ids=[], details={"src_ip": "1.1.1.1"},
    )
    db.session.add(existing)
    db.session.commit()

    e = Event(
        timestamp=datetime.utcnow(), host="win-vm",
        event_type="network_connection", src_ip="2.2.2.2",
    )
    db.session.add(e)
    db.session.commit()

    evaluate_single_event_rules([rule])

    db.session.expire_all()
    assert Alert.query.count() == 2  # different src_ip, must not be suppressed


def test_aggregation_rule_cooldown_outlasts_detection_window(app):
    """The cooldown that prevents re-firing must outlast the detection window
    itself — otherwise a continuous attack re-alerts every window."""
    from datetime import timedelta

    base = datetime.utcnow()
    _add_failed_logins(5, base_time=base)
    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE], now=base + timedelta(seconds=5))
    assert Alert.query.count() == 1

    # 70s later: outside the 60s detection window, but the attack is ongoing.
    _add_failed_logins(5, base_time=base + timedelta(seconds=70))
    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE], now=base + timedelta(seconds=75))
    assert Alert.query.count() == 1  # still suppressed by the longer cooldown


def test_aggregation_rule_skips_events_with_missing_group_by_field(app):
    """Events missing the group_by field (group_value=None) must not be
    bucketed together into a bogus alert."""
    from datetime import timedelta

    base = datetime.utcnow()
    for i in range(5):
        db.session.add(Event(
            timestamp=base + timedelta(seconds=i),
            host="linux-vm",
            event_type="auth_failure",
            details={"service": "sshd"},  # no src_ip
        ))
    db.session.commit()

    evaluate_aggregation_rules([SSH_BRUTE_FORCE_RULE], now=base + timedelta(seconds=5))

    assert Alert.query.count() == 0


# ── H3: error-isolation regression tests ─────────────────────────────────────

def test_bad_rule_does_not_prevent_good_rule_from_firing(app):
    """H3: A rule with an unknown operator must not abort the whole detection
    cycle — the valid rule that follows it must still produce an alert."""
    bad_rule = {
        "id": "RULE-BAD-OP",
        "title": "Bad Operator Rule",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "process_creation",
            "conditions": {"command_line": {"unknown_op": "boom"}},
        },
    }
    good_rule = {
        "id": "RULE-GOOD-OP",
        "title": "Good Rule",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "process_creation",
            "conditions": {"process_name": "powershell.exe"},
        },
    }
    db.session.add(Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -nop",
    ))
    db.session.commit()

    evaluate_single_event_rules([bad_rule, good_rule])

    assert Alert.query.count() == 1
    assert Alert.query.first().rule_id == "RULE-GOOD-OP"


# ── H1/L2: watermark-lookback regression test ─────────────────────────────────

def test_watermark_lookback_catches_late_committing_event(app):
    """H1/L2: An event whose ID lies below the current high-water mark (simulating
    a late-committing concurrent writer) must still be picked up by the lookback
    window and produce an alert."""
    from app.models import EngineState
    from app.detection.engine import _WATERMARK_LOOKBACK

    # Insert a matching event (SQLite assigns id sequentially, e.g. 1)
    event = Event(
        timestamp=datetime.utcnow(),
        host="win-vm",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc abc",
    )
    db.session.add(event)
    db.session.commit()

    # Simulate: a concurrent writer already advanced the watermark well past this
    # event's id, but not so far that the lookback window can't reach it.
    gap = _WATERMARK_LOOKBACK // 2  # e.g. 25 — within the lookback window
    advanced = event.id + gap
    state = db.session.get(EngineState, 1)
    if state is None:
        state = EngineState(id=1, last_processed_event_id=advanced)
        db.session.add(state)
    else:
        state.last_processed_event_id = advanced
    db.session.commit()

    evaluate_single_event_rules([ENCODED_POWERSHELL_RULE])

    # Lookback must have re-examined the event and fired an alert
    assert Alert.query.count() == 1


def test_single_event_rule_fires_again_after_alert_closed(app):
    """Status-gate allows re-firing once the existing alert is closed."""
    from datetime import datetime
    from app.db import db
    from app.models import Alert, Event
    from app.detection.engine import evaluate_single_event_rules

    rule = {
        "id": "RULE-DUP2",
        "title": "Dup Test 2",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "lsass_access",
            "conditions": {},
        },
    }

    # Existing alert is closed_tp — gate should not block
    closed = Alert(
        rule_id="RULE-DUP2", title="Dup Test 2", severity="high",
        attack_technique="T9999", attack_tactic="Testing",
        host="win-vm", status="closed_tp",
        triggering_event_ids=[], details={},
    )
    db.session.add(closed)
    db.session.commit()

    e = Event(timestamp=datetime.utcnow(), host="win-vm", event_type="lsass_access")
    db.session.add(e)
    db.session.commit()

    evaluate_single_event_rules([rule])

    db.session.expire_all()
    assert Alert.query.count() == 2  # new alert fired despite closed existing
