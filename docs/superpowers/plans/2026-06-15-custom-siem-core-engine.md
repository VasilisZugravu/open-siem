# Custom SIEM Core Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working, self-contained SIEM: ingest normalized security events, evaluate them against custom YAML-defined detection rules (tagged with MITRE ATT&CK techniques), and present alerts/events on a Flask dashboard with charts and an ATT&CK coverage heatmap.

**Architecture:** A single Flask app (`app/`) with SQLAlchemy models for `events`, `alerts`, and `engine_state`, stored in SQLite for tests/dev and Postgres in Docker. A background thread runs a detection loop every 30s, evaluating YAML rule files from `rules/` against new events. Dashboard routes render Jinja2 templates with Bootstrap (CDN) and Chart.js (CDN) — no frontend build step.

**Tech Stack:** Python, Flask, Flask-SQLAlchemy, PyYAML, pytest, SQLite (tests) / PostgreSQL (Docker), Bootstrap + Chart.js via CDN.

This is the **first of two plans**. This plan delivers a fully working SIEM testable via a synthetic data seed script (no VMs needed). A second plan adds the log forwarders and attack-lab scripts that feed it real telemetry.

---

## Task 1: Project Setup & Flask App Skeleton

**Files:**
- Create: `requirements.txt`
- Create: `.gitignore`
- Create: `app/__init__.py`
- Create: `app/db.py`
- Create: `run.py`
- Test: `tests/conftest.py`, `tests/test_app.py`

- [ ] **Step 1: Create `requirements.txt`**

```
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
psycopg2-binary==2.9.9
PyYAML==6.0.1
pytest==8.2.0
requests==2.31.0
```

- [ ] **Step 2: Create `.gitignore`**

```
__pycache__/
*.pyc
*.db
.env
venv/
```

- [ ] **Step 3: Write the failing test**

Create `tests/conftest.py`:

```python
import pytest
from app import create_app
from app.db import db


@pytest.fixture
def app():
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
    })
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    return app.test_client()
```

Create `tests/test_app.py`:

```python
def test_app_is_created(app):
    assert app is not None
    assert app.config["TESTING"] is True


def test_db_is_initialized(app):
    from app.db import db
    assert db.engine is not None
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest tests/test_app.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app'`

- [ ] **Step 5: Create `app/db.py`**

```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
```

- [ ] **Step 6: Create `app/__init__.py`**

```python
import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    return app
```

- [ ] **Step 7: Create `run.py`**

```python
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/test_app.py -v`
Expected: 2 passed

- [ ] **Step 9: Commit**

```bash
git add requirements.txt .gitignore app/ run.py tests/
git commit -m "feat: add Flask app skeleton with SQLAlchemy"
```

---

## Task 2: Database Models (Event, Alert)

**Files:**
- Create: `app/models.py`
- Modify: `app/__init__.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_models.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.models'`

- [ ] **Step 3: Create `app/models.py`**

```python
from datetime import datetime
from app.db import db


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    host = db.Column(db.String(64), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    user = db.Column(db.String(128), nullable=True)
    src_ip = db.Column(db.String(45), nullable=True)
    dest_ip = db.Column(db.String(45), nullable=True)
    process_name = db.Column(db.String(256), nullable=True)
    command_line = db.Column(db.Text, nullable=True)
    details = db.Column(db.JSON, nullable=True)
    raw = db.Column(db.Text, nullable=True)


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    rule_id = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    attack_technique = db.Column(db.String(32), nullable=False)
    attack_tactic = db.Column(db.String(64), nullable=False)
    host = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="new")
    triggering_event_ids = db.Column(db.JSON, nullable=False)
    details = db.Column(db.JSON, nullable=True)
```

- [ ] **Step 4: Register models so `create_all()` sees them**

Modify `app/__init__.py` — add the import before `db.create_all()`:

```python
import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    db.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy

    with app.app_context():
        db.create_all()

    return app
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add app/models.py app/__init__.py tests/test_models.py
git commit -m "feat: add Event and Alert models"
```

---

## Task 3: Condition Operators

**Files:**
- Create: `app/detection/__init__.py`
- Create: `app/detection/operators.py`
- Test: `tests/test_operators.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_operators.py`:

```python
from app.detection.operators import match_condition, match_conditions


def test_equals_match():
    assert match_condition("powershell.exe", "powershell.exe") is True
    assert match_condition("cmd.exe", "powershell.exe") is False


def test_contains_match():
    assert match_condition("powershell.exe -enc abc", {"contains": "-enc"}) is True
    assert match_condition("powershell.exe -nop", {"contains": "-enc"}) is False
    assert match_condition(None, {"contains": "-enc"}) is False


def test_regex_match():
    assert match_condition("/usr/sbin/visudo", {"regex": "(shadow|visudo)"}) is True
    assert match_condition("/bin/ls", {"regex": "(shadow|visudo)"}) is False


def test_in_match():
    assert match_condition("cmd.exe", {"in": ["cmd.exe", "powershell.exe"]}) is True
    assert match_condition("bash", {"in": ["cmd.exe", "powershell.exe"]}) is False


def test_match_conditions_all_must_match():
    event = {"process_name": "powershell.exe", "command_line": "powershell.exe -enc abc"}
    conditions = {"process_name": "powershell.exe", "command_line": {"contains": "-enc"}}
    assert match_conditions(event, conditions) is True


def test_match_conditions_fails_if_one_condition_fails():
    event = {"process_name": "powershell.exe", "command_line": "powershell.exe -nop"}
    conditions = {"process_name": "powershell.exe", "command_line": {"contains": "-enc"}}
    assert match_conditions(event, conditions) is False


def test_match_conditions_missing_field_is_no_match():
    event = {"process_name": "powershell.exe"}
    conditions = {"command_line": {"contains": "-enc"}}
    assert match_conditions(event, conditions) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_operators.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.detection'`

- [ ] **Step 3: Create `app/detection/__init__.py`**

```python
import os

RULES_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "rules")
)
```

- [ ] **Step 4: Create `app/detection/operators.py`**

```python
import re


def op_equals(value, expected):
    return value == expected


def op_contains(value, expected):
    if value is None:
        return False
    return expected in value


def op_regex(value, pattern):
    if value is None:
        return False
    return re.search(pattern, value) is not None


def op_in(value, options):
    return value in options


def match_condition(value, condition):
    """A condition is either a literal (equals) or a dict with one operator key."""
    if isinstance(condition, dict):
        if "contains" in condition:
            return op_contains(value, condition["contains"])
        if "regex" in condition:
            return op_regex(value, condition["regex"])
        if "in" in condition:
            return op_in(value, condition["in"])
        raise ValueError(f"Unknown operator in condition: {condition}")
    return op_equals(value, condition)


def match_conditions(event_dict, conditions):
    """conditions: dict of field_name -> condition. event_dict: dict of field values."""
    for field, condition in conditions.items():
        if not match_condition(event_dict.get(field), condition):
            return False
    return True
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_operators.py -v`
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
git add app/detection/ tests/test_operators.py
git commit -m "feat: add detection rule condition operators"
```

---

## Task 4: Rules Loader

**Files:**
- Create: `app/detection/rules_loader.py`
- Test: `tests/test_rules_loader.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_rules_loader.py`:

```python
import yaml
from app.detection.rules_loader import load_rule_file, load_rules


def test_load_rule_file_valid(tmp_path):
    rule_data = {
        "id": "RULE-TEST",
        "title": "Test Rule",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"event_type": "test_event", "conditions": {"foo": "bar"}},
    }
    rule_file = tmp_path / "test_rule.yml"
    rule_file.write_text(yaml.dump(rule_data))

    rule = load_rule_file(str(rule_file))
    assert rule["id"] == "RULE-TEST"
    assert rule["detection"]["event_type"] == "test_event"


def test_load_rule_file_missing_field(tmp_path):
    rule_data = {"id": "RULE-TEST", "title": "Test Rule"}
    rule_file = tmp_path / "bad_rule.yml"
    rule_file.write_text(yaml.dump(rule_data))

    try:
        load_rule_file(str(rule_file))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "severity" in str(e)


def test_load_rule_file_missing_event_type(tmp_path):
    rule_data = {
        "id": "RULE-TEST",
        "title": "Test Rule",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"conditions": {"foo": "bar"}},
    }
    rule_file = tmp_path / "bad_rule.yml"
    rule_file.write_text(yaml.dump(rule_data))

    try:
        load_rule_file(str(rule_file))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "event_type" in str(e)


def test_load_rules_from_directory(tmp_path):
    rule_data = {
        "id": "RULE-A",
        "title": "Rule A",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"event_type": "test_event"},
    }
    (tmp_path / "rule_a.yml").write_text(yaml.dump(rule_data))
    (tmp_path / "notes.txt").write_text("not a rule")

    rules = load_rules(str(tmp_path))
    assert len(rules) == 1
    assert rules[0]["id"] == "RULE-A"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_rules_loader.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.detection.rules_loader'`

- [ ] **Step 3: Create `app/detection/rules_loader.py`**

```python
import os
import yaml

REQUIRED_FIELDS = ["id", "title", "severity", "attack_technique", "attack_tactic", "detection"]


def load_rule_file(path):
    with open(path) as f:
        rule = yaml.safe_load(f)

    for field in REQUIRED_FIELDS:
        if field not in rule:
            raise ValueError(f"Rule {path} missing required field: {field}")

    if "event_type" not in rule["detection"]:
        raise ValueError(f"Rule {path} detection block missing event_type")

    return rule


def load_rules(rules_dir):
    rules = []
    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith((".yml", ".yaml")):
            rules.append(load_rule_file(os.path.join(rules_dir, filename)))
    return rules
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_rules_loader.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add app/detection/rules_loader.py tests/test_rules_loader.py
git commit -m "feat: add YAML rule loader with validation"
```

---

## Task 5: Detection Engine — Single-Event Rules

**Files:**
- Modify: `app/models.py`
- Create: `app/detection/engine.py`
- Test: `tests/test_engine.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_engine.py`:

```python
from datetime import datetime
from app.db import db
from app.models import Event, Alert
from app.detection.engine import evaluate_single_event_rules, event_to_dict

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_engine.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.detection.engine'`

- [ ] **Step 3: Add `EngineState` model**

Modify `app/models.py` — add this class at the end of the file:

```python
class EngineState(db.Model):
    __tablename__ = "engine_state"

    id = db.Column(db.Integer, primary_key=True)
    last_processed_event_id = db.Column(db.Integer, nullable=False, default=0)
```

- [ ] **Step 4: Create `app/detection/engine.py`**

```python
from datetime import datetime, timedelta
from app.db import db
from app.models import Event, Alert, EngineState
from app.detection.operators import match_conditions


def event_to_dict(event):
    """Flatten an Event into a dict for rule matching, merging `details` fields
    (e.g. service, port, parent_process) alongside the normalized columns."""
    base = {
        "event_type": event.event_type,
        "host": event.host,
        "user": event.user,
        "src_ip": event.src_ip,
        "dest_ip": event.dest_ip,
        "process_name": event.process_name,
        "command_line": event.command_line,
    }
    if event.details:
        for key, value in event.details.items():
            if base.get(key) is None:
                base[key] = value
    return base


def _get_engine_state():
    state = EngineState.query.get(1)
    if state is None:
        state = EngineState(id=1, last_processed_event_id=0)
        db.session.add(state)
        db.session.commit()
    return state


def evaluate_single_event_rules(rules):
    """Check events added since the last cycle against rules with no aggregation block.
    Each matching event creates exactly one alert."""
    state = _get_engine_state()
    new_events = (
        Event.query.filter(Event.id > state.last_processed_event_id)
        .order_by(Event.id)
        .all()
    )

    max_id = state.last_processed_event_id

    for event in new_events:
        max_id = max(max_id, event.id)
        event_dict = event_to_dict(event)

        for rule in rules:
            detection = rule["detection"]
            if "aggregation" in detection:
                continue
            if event_dict["event_type"] != detection["event_type"]:
                continue
            if not match_conditions(event_dict, detection.get("conditions", {})):
                continue

            db.session.add(Alert(
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                attack_technique=rule["attack_technique"],
                attack_tactic=rule["attack_tactic"],
                host=event.host,
                status="new",
                triggering_event_ids=[event.id],
                details={},
            ))

    state.last_processed_event_id = max_id
    db.session.commit()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_engine.py -v`
Expected: 4 passed

- [ ] **Step 6: Commit**

```bash
git add app/models.py app/detection/engine.py tests/test_engine.py
git commit -m "feat: add single-event rule evaluation"
```

---

## Task 6: Detection Engine — Aggregation Rules

**Files:**
- Modify: `app/detection/engine.py`
- Modify: `tests/test_engine.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_engine.py`:

```python
from datetime import timedelta
from app.detection.engine import evaluate_aggregation_rules

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_engine.py -v`
Expected: FAIL with `ImportError: cannot import name 'evaluate_aggregation_rules'`

- [ ] **Step 3: Add aggregation evaluation and the combined cycle runner**

Append to `app/detection/engine.py`:

```python
def evaluate_aggregation_rules(rules, now=None):
    """Check rules with an aggregation block: group recent matching events by
    `group_by` and fire an alert for any group that reaches `threshold` within
    `timeframe_seconds`. A cooldown (the same timeframe) prevents re-firing for
    a group that already has a recent alert."""
    now = now or datetime.utcnow()

    for rule in rules:
        detection = rule["detection"]
        if "aggregation" not in detection:
            continue

        agg = detection["aggregation"]
        window_start = now - timedelta(seconds=agg["timeframe_seconds"])

        candidates = Event.query.filter(
            Event.event_type == detection["event_type"],
            Event.timestamp >= window_start,
        ).all()

        conditions = detection.get("conditions", {})
        matching = [e for e in candidates if match_conditions(event_to_dict(e), conditions)]

        groups = {}
        for event in matching:
            group_value = event_to_dict(event).get(agg["group_by"])
            groups.setdefault(group_value, []).append(event)

        recent_alerts = Alert.query.filter(
            Alert.rule_id == rule["id"],
            Alert.created_at >= window_start,
        ).all()
        already_alerted = {a.details.get(agg["group_by"]) for a in recent_alerts}

        for group_value, events in groups.items():
            if len(events) < agg["threshold"]:
                continue
            if group_value in already_alerted:
                continue

            db.session.add(Alert(
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                attack_technique=rule["attack_technique"],
                attack_tactic=rule["attack_tactic"],
                host=events[-1].host,
                status="new",
                triggering_event_ids=[e.id for e in events],
                details={agg["group_by"]: group_value, "count": len(events)},
            ))

    db.session.commit()


def run_detection_cycle(rules):
    """Run one full detection pass: single-event rules, then aggregation rules."""
    evaluate_single_event_rules(rules)
    evaluate_aggregation_rules(rules)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_engine.py -v`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git add app/detection/engine.py tests/test_engine.py
git commit -m "feat: add aggregation rule evaluation and detection cycle runner"
```

---

## Task 7: Background Detection Loop

**Files:**
- Create: `app/scheduler.py`
- Modify: `app/__init__.py`
- Test: `tests/test_scheduler.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_scheduler.py`:

```python
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
        "id": "RULE-TEST",
        "title": "Test Rule",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {
            "event_type": "test_event",
            "conditions": {"process_name": "evil.exe"},
        },
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
    assert Alert.query.first().rule_id == "RULE-TEST"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scheduler.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.scheduler'`

- [ ] **Step 3: Create `app/scheduler.py`**

```python
import threading
import time
from app.detection import RULES_DIR
from app.detection.engine import run_detection_cycle
from app.detection.rules_loader import load_rules


def run_one_cycle(app):
    """Load rules from RULES_DIR and run one detection cycle within the app's context."""
    with app.app_context():
        rules = load_rules(RULES_DIR)
        run_detection_cycle(rules)


def start_background_loop(app, interval=30):
    """Start a daemon thread that calls run_one_cycle every `interval` seconds."""
    def _loop():
        while True:
            run_one_cycle(app)
            time.sleep(interval)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    return thread
```

- [ ] **Step 4: Start the loop from `create_app` (skipped during tests)**

Modify `app/__init__.py`:

```python
import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    db.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy

    with app.app_context():
        db.create_all()

    if not app.config.get("TESTING"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_scheduler.py -v`
Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add app/scheduler.py app/__init__.py tests/test_scheduler.py
git commit -m "feat: add background detection loop"
```

---

## Task 8: Ingestion API

**Files:**
- Create: `app/ingest.py`
- Modify: `app/__init__.py`
- Test: `tests/test_ingest.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ingest.py`:

```python
from app.models import Event


def test_ingest_valid_event(client):
    response = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
        "src_ip": "203.0.113.50",
        "details": {"service": "sshd"},
    })

    assert response.status_code == 201
    assert "id" in response.get_json()

    event = Event.query.first()
    assert event.host == "linux-vm"
    assert event.event_type == "auth_failure"
    assert event.details == {"service": "sshd"}


def test_ingest_missing_required_field(client):
    response = client.post("/ingest", json={
        "host": "linux-vm",
        "event_type": "auth_failure",
    })

    assert response.status_code == 400
    assert "timestamp" in response.get_json()["error"]


def test_ingest_invalid_json(client):
    response = client.post("/ingest", data="not json", content_type="application/json")

    assert response.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ingest.py -v`
Expected: FAIL with 404 (no `/ingest` route registered)

- [ ] **Step 3: Create `app/ingest.py`**

```python
from datetime import datetime
from flask import Blueprint, request, jsonify
from app.db import db
from app.models import Event

ingest_bp = Blueprint("ingest", __name__)

REQUIRED_FIELDS = ["timestamp", "host", "event_type"]


@ingest_bp.route("/ingest", methods=["POST"])
def ingest_event():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid JSON body"}), 400

    for field in REQUIRED_FIELDS:
        if field not in data:
            return jsonify({"error": f"missing required field: {field}"}), 400

    event = Event(
        timestamp=datetime.fromisoformat(data["timestamp"]),
        host=data["host"],
        event_type=data["event_type"],
        user=data.get("user"),
        src_ip=data.get("src_ip"),
        dest_ip=data.get("dest_ip"),
        process_name=data.get("process_name"),
        command_line=data.get("command_line"),
        details=data.get("details"),
        raw=data.get("raw"),
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({"id": event.id}), 201
```

- [ ] **Step 4: Register the blueprint**

Modify `app/__init__.py` — add the import and registration before the `with app.app_context():` block:

```python
import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    db.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.ingest import ingest_bp
    app.register_blueprint(ingest_bp)

    with app.app_context():
        db.create_all()

    if not app.config.get("TESTING"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_ingest.py -v`
Expected: 3 passed

- [ ] **Step 6: Commit**

```bash
git add app/ingest.py app/__init__.py tests/test_ingest.py
git commit -m "feat: add /ingest endpoint for log forwarders"
```

---

## Task 9: The 8 Detection Rules

**Files:**
- Create: `rules/linux_ssh_bruteforce.yml`
- Create: `rules/linux_sudo_shadow_edit.yml`
- Create: `rules/linux_useradd.yml`
- Create: `rules/windows_encoded_powershell.yml`
- Create: `rules/windows_office_spawns_shell.yml`
- Create: `rules/windows_scheduled_task.yml`
- Create: `rules/windows_lsass_dump.yml`
- Create: `rules/windows_c2_port.yml`
- Test: `tests/test_rules_content.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_rules_content.py`:

```python
from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules


def test_all_eight_rules_load():
    rules = load_rules(RULES_DIR)
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {
        "RULE-001", "RULE-002", "RULE-003", "RULE-004",
        "RULE-005", "RULE-006", "RULE-007", "RULE-008",
    }


def test_rule_attack_techniques_are_unique():
    rules = load_rules(RULES_DIR)
    techniques = [r["attack_technique"] for r in rules]
    assert len(techniques) == len(set(techniques))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_rules_content.py -v`
Expected: FAIL — `rules/` directory does not exist or is empty

- [ ] **Step 3: Create the 8 rule files**

Create `rules/linux_ssh_bruteforce.yml`:

```yaml
id: RULE-001
title: SSH Brute Force
description: Multiple failed SSH logins from the same source IP within 60 seconds
severity: medium
attack_technique: T1110
attack_tactic: Credential Access
detection:
  event_type: auth_failure
  conditions:
    service: sshd
  aggregation:
    group_by: src_ip
    threshold: 5
    timeframe_seconds: 60
tags: [linux, authentication]
```

Create `rules/linux_sudo_shadow_edit.yml`:

```yaml
id: RULE-002
title: Sudo Used to Edit Shadow File or Run visudo
description: A user invoked sudo to edit /etc/shadow or run visudo, a common privilege escalation step
severity: high
attack_technique: T1548.003
attack_tactic: Privilege Escalation
detection:
  event_type: command_execution
  conditions:
    command_line:
      regex: "(shadow|visudo)"
tags: [linux, privilege-escalation]
```

Create `rules/linux_useradd.yml`:

```yaml
id: RULE-003
title: New Local User Account Created
description: A new local user account was created via useradd, a common persistence technique
severity: medium
attack_technique: T1136.001
attack_tactic: Persistence
detection:
  event_type: command_execution
  conditions:
    command_line:
      contains: "useradd"
tags: [linux, persistence]
```

Create `rules/windows_encoded_powershell.yml`:

```yaml
id: RULE-004
title: Encoded PowerShell Command
description: PowerShell was executed with a base64-encoded (-enc) command, a common obfuscation technique
severity: high
attack_technique: T1059.001
attack_tactic: Execution
detection:
  event_type: process_creation
  conditions:
    process_name: powershell.exe
    command_line:
      contains: "-enc"
tags: [windows, execution]
```

Create `rules/windows_office_spawns_shell.yml`:

```yaml
id: RULE-005
title: Office Application Spawned a Shell
description: Word or Excel spawned cmd.exe or powershell.exe, a classic malicious-macro pattern
severity: high
attack_technique: T1059
attack_tactic: Execution
detection:
  event_type: process_creation
  conditions:
    process_name:
      in: ["cmd.exe", "powershell.exe"]
    parent_process:
      in: ["winword.exe", "excel.exe"]
tags: [windows, execution, phishing]
```

Create `rules/windows_scheduled_task.yml`:

```yaml
id: RULE-006
title: Scheduled Task Created
description: A scheduled task was created via schtasks.exe, often used for persistence
severity: medium
attack_technique: T1053.005
attack_tactic: Persistence
detection:
  event_type: process_creation
  conditions:
    process_name: schtasks.exe
    command_line:
      contains: "/create"
tags: [windows, persistence]
```

Create `rules/windows_lsass_dump.yml`:

```yaml
id: RULE-007
title: Possible LSASS Memory Dump
description: A process command line referenced lsass, consistent with credential dumping tools like procdump
severity: high
attack_technique: T1003.001
attack_tactic: Credential Access
detection:
  event_type: process_creation
  conditions:
    command_line:
      contains: "lsass"
tags: [windows, credential-access]
```

Create `rules/windows_c2_port.yml`:

```yaml
id: RULE-008
title: Outbound Connection to Known C2 Port
description: A process made an outbound network connection to a port commonly used by C2 frameworks (e.g. Metasploit default 4444)
severity: high
attack_technique: T1071
attack_tactic: Command and Control
detection:
  event_type: network_connection
  conditions:
    dest_port:
      in: [4444, 4445]
tags: [windows, c2]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_rules_content.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add rules/ tests/test_rules_content.py
git commit -m "feat: add the 8 ATT&CK-mapped detection rules"
```

---

## Task 10: Dashboard — Alert Feed (with charts)

**Files:**
- Create: `app/dashboard/__init__.py`
- Create: `app/dashboard/routes.py`
- Create: `app/dashboard/templates/base.html`
- Create: `app/dashboard/templates/alert_feed.html`
- Modify: `app/__init__.py`
- Test: `tests/test_dashboard.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_dashboard.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard.py -v`
Expected: FAIL with 404 (no `/` route registered — `create_app` has no dashboard blueprint yet)

- [ ] **Step 3: Create `app/dashboard/__init__.py`**

```python
```

(empty file — marks `app/dashboard` as a package)

- [ ] **Step 4: Create `app/dashboard/routes.py`**

```python
from datetime import datetime, timedelta
from flask import Blueprint, render_template
from app.models import Alert

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard_bp.route("/")
def alert_feed():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(50).all()

    since = datetime.utcnow() - timedelta(hours=24)
    recent_alerts = Alert.query.filter(Alert.created_at >= since).all()

    hourly_counts = {}
    for alert in recent_alerts:
        bucket = alert.created_at.strftime("%Y-%m-%d %H:00")
        hourly_counts[bucket] = hourly_counts.get(bucket, 0) + 1
    hourly_labels = sorted(hourly_counts.keys())
    hourly_values = [hourly_counts[label] for label in hourly_labels]

    severity_counts = {}
    for alert in Alert.query.all():
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    return render_template(
        "alert_feed.html",
        alerts=alerts,
        hourly_labels=hourly_labels,
        hourly_values=hourly_values,
        severity_labels=list(severity_counts.keys()),
        severity_values=list(severity_counts.values()),
    )
```

- [ ] **Step 5: Create `app/dashboard/templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>{% block title %}SIEM{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('dashboard.alert_feed') }}">Custom SIEM</a>
            <div>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.alert_feed') }}">Alerts</a>
            </div>
        </div>
    </nav>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
```

- [ ] **Step 6: Create `app/dashboard/templates/alert_feed.html`**

```html
{% extends "base.html" %}
{% block title %}Alert Feed{% endblock %}
{% block content %}
<div class="row mb-4">
    <div class="col-md-6">
        <canvas id="hourlyChart"></canvas>
    </div>
    <div class="col-md-6">
        <canvas id="severityChart"></canvas>
    </div>
</div>
<table class="table table-striped">
    <thead>
        <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Title</th>
            <th>ATT&amp;CK</th>
            <th>Host</th>
            <th>Status</th>
        </tr>
    </thead>
    <tbody>
        {% for alert in alerts %}
        <tr>
            <td>{{ alert.created_at.strftime("%Y-%m-%d %H:%M:%S") }}</td>
            <td>{{ alert.severity }}</td>
            <td>{{ alert.title }}</td>
            <td>{{ alert.attack_technique }}</td>
            <td>{{ alert.host }}</td>
            <td>{{ alert.status }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
{% block scripts %}
<script>
new Chart(document.getElementById('hourlyChart'), {
    type: 'bar',
    data: {
        labels: {{ hourly_labels | tojson }},
        datasets: [{ label: 'Alerts per hour', data: {{ hourly_values | tojson }} }]
    }
});
new Chart(document.getElementById('severityChart'), {
    type: 'doughnut',
    data: {
        labels: {{ severity_labels | tojson }},
        datasets: [{ label: 'Alerts by severity', data: {{ severity_values | tojson }} }]
    }
});
</script>
{% endblock %}
```

- [ ] **Step 7: Register the dashboard blueprint**

Modify `app/__init__.py` — add the import and registration alongside the ingest blueprint:

```python
import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    db.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.ingest import ingest_bp
    from app.dashboard.routes import dashboard_bp
    app.register_blueprint(ingest_bp)
    app.register_blueprint(dashboard_bp)

    with app.app_context():
        db.create_all()

    if not app.config.get("TESTING"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/test_dashboard.py -v`
Expected: 3 passed

- [ ] **Step 9: Commit**

```bash
git add app/dashboard/ app/__init__.py tests/test_dashboard.py
git commit -m "feat: add alert feed dashboard with overview charts"
```

---

## Task 11: Dashboard — Alert Detail + Status Update

**Files:**
- Modify: `app/dashboard/routes.py`
- Create: `app/dashboard/templates/alert_detail.html`
- Modify: `app/dashboard/templates/alert_feed.html`
- Modify: `tests/test_dashboard.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_dashboard.py`:

```python
from app.models import Event


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard.py -v`
Expected: FAIL with 404 (no `/alerts/<id>` route registered)

- [ ] **Step 3: Add alert detail and status update routes**

Modify `app/dashboard/routes.py` — update the imports at the top and add the two new routes at the end of the file:

```python
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for
from app.db import db
from app.models import Alert, Event

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")
```

Add at the end of the file:

```python
@dashboard_bp.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    events = []
    if alert.triggering_event_ids:
        events = Event.query.filter(Event.id.in_(alert.triggering_event_ids)).all()
    return render_template("alert_detail.html", alert=alert, events=events)


@dashboard_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    new_status = request.form.get("status")
    if new_status in ("new", "in_progress", "closed_tp", "closed_fp"):
        alert.status = new_status
        db.session.commit()
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))
```

- [ ] **Step 4: Create `app/dashboard/templates/alert_detail.html`**

```html
{% extends "base.html" %}
{% block title %}Alert Detail{% endblock %}
{% block content %}
<h2>{{ alert.title }}</h2>
<table class="table table-bordered w-auto">
    <tr><th>Severity</th><td>{{ alert.severity }}</td></tr>
    <tr><th>ATT&amp;CK Technique</th><td>{{ alert.attack_technique }}</td></tr>
    <tr><th>ATT&amp;CK Tactic</th><td>{{ alert.attack_tactic }}</td></tr>
    <tr><th>Host</th><td>{{ alert.host }}</td></tr>
    <tr><th>Created</th><td>{{ alert.created_at.strftime("%Y-%m-%d %H:%M:%S") }}</td></tr>
    <tr><th>Details</th><td>{{ alert.details }}</td></tr>
</table>

<form method="post" action="{{ url_for('dashboard.update_alert_status', alert_id=alert.id) }}" class="mb-4">
    <label for="status">Status:</label>
    <select name="status" id="status">
        {% for value, label in [("new", "New"), ("in_progress", "In Progress"), ("closed_tp", "Closed - True Positive"), ("closed_fp", "Closed - False Positive")] %}
        <option value="{{ value }}" {% if alert.status == value %}selected{% endif %}>{{ label }}</option>
        {% endfor %}
    </select>
    <button type="submit" class="btn btn-primary btn-sm">Update</button>
</form>

<h3>Triggering Events</h3>
<table class="table table-sm">
    <thead>
        <tr><th>Time</th><th>Event Type</th><th>User</th><th>Source IP</th><th>Raw</th></tr>
    </thead>
    <tbody>
        {% for event in events %}
        <tr>
            <td>{{ event.timestamp.strftime("%Y-%m-%d %H:%M:%S") }}</td>
            <td>{{ event.event_type }}</td>
            <td>{{ event.user or "" }}</td>
            <td>{{ event.src_ip or "" }}</td>
            <td><code>{{ event.raw or "" }}</code></td>
        </tr>
        {% endfor %}
    </tbody>
</table>
<a href="{{ url_for('dashboard.alert_feed') }}">&larr; Back to alerts</a>
{% endblock %}
```

- [ ] **Step 5: Link alert titles to the detail page**

Modify `app/dashboard/templates/alert_feed.html` — replace the title cell in the table body:

```html
            <td>{{ alert.title }}</td>
```

with:

```html
            <td><a href="{{ url_for('dashboard.alert_detail', alert_id=alert.id) }}">{{ alert.title }}</a></td>
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_dashboard.py -v`
Expected: 6 passed

- [ ] **Step 7: Commit**

```bash
git add app/dashboard/ tests/test_dashboard.py
git commit -m "feat: add alert detail view with triage status"
```

---

## Task 12: Dashboard — ATT&CK Coverage Heatmap

**Files:**
- Modify: `app/dashboard/routes.py`
- Create: `app/dashboard/templates/heatmap.html`
- Modify: `app/dashboard/templates/base.html`
- Modify: `tests/test_dashboard.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_dashboard.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard.py -v`
Expected: FAIL with 404 (no `/heatmap` route registered)

- [ ] **Step 3: Add the heatmap route**

Modify `app/dashboard/routes.py` — update the imports at the top:

```python
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for
from app.db import db
from app.models import Alert, Event
from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")
```

Add at the end of the file:

```python
@dashboard_bp.route("/heatmap")
def heatmap():
    rules = load_rules(RULES_DIR)
    fired_techniques = {
        row[0] for row in db.session.query(Alert.attack_technique).distinct().all()
    }

    rows = []
    for rule in rules:
        technique = rule["attack_technique"]
        rows.append({
            "tactic": rule["attack_tactic"],
            "technique": technique,
            "title": rule["title"],
            "status": "fired" if technique in fired_techniques else "covered",
        })
    rows.sort(key=lambda r: (r["tactic"], r["technique"]))

    return render_template("heatmap.html", rows=rows)
```

- [ ] **Step 4: Create `app/dashboard/templates/heatmap.html`**

```html
{% extends "base.html" %}
{% block title %}ATT&amp;CK Heatmap{% endblock %}
{% block content %}
<h2>ATT&amp;CK Coverage Heatmap</h2>
<p>
    <span class="badge bg-success">covered</span> = rule exists, hasn't fired &nbsp;
    <span class="badge bg-danger">fired</span> = rule exists and has triggered at least one alert
</p>
<table class="table table-bordered">
    <thead>
        <tr><th>Tactic</th><th>Technique</th><th>Rule</th><th>Status</th></tr>
    </thead>
    <tbody>
        {% for row in rows %}
        <tr class="{{ 'table-danger' if row.status == 'fired' else 'table-success' }}">
            <td>{{ row.tactic }}</td>
            <td>{{ row.technique }}</td>
            <td>{{ row.title }}</td>
            <td>{{ row.status }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
```

- [ ] **Step 5: Add the Heatmap link to the nav bar**

Modify `app/dashboard/templates/base.html` — replace the nav links block:

```html
            <div>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.alert_feed') }}">Alerts</a>
            </div>
```

with:

```html
            <div>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.alert_feed') }}">Alerts</a>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.heatmap') }}">ATT&amp;CK Heatmap</a>
            </div>
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_dashboard.py -v`
Expected: 8 passed

- [ ] **Step 7: Commit**

```bash
git add app/dashboard/ tests/test_dashboard.py
git commit -m "feat: add ATT&CK coverage heatmap"
```

---

## Task 13: Dashboard — Event Explorer

**Files:**
- Modify: `app/dashboard/routes.py`
- Create: `app/dashboard/templates/event_explorer.html`
- Modify: `app/dashboard/templates/base.html`
- Modify: `tests/test_dashboard.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_dashboard.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dashboard.py -v`
Expected: FAIL with 404 (no `/events` route registered)

- [ ] **Step 3: Add the event explorer route**

Add at the end of `app/dashboard/routes.py`:

```python
@dashboard_bp.route("/events")
def event_explorer():
    query = Event.query

    host = request.args.get("host")
    event_type = request.args.get("event_type")
    search = request.args.get("search")

    if host:
        query = query.filter(Event.host == host)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if search:
        query = query.filter(
            db.or_(
                Event.command_line.contains(search),
                Event.raw.contains(search),
            )
        )

    events = query.order_by(Event.timestamp.desc()).limit(100).all()
    hosts = sorted({row[0] for row in db.session.query(Event.host).distinct().all()})
    event_types = sorted({row[0] for row in db.session.query(Event.event_type).distinct().all()})

    return render_template(
        "event_explorer.html",
        events=events,
        hosts=hosts,
        event_types=event_types,
        selected_host=host or "",
        selected_event_type=event_type or "",
        search=search or "",
    )
```

- [ ] **Step 4: Create `app/dashboard/templates/event_explorer.html`**

```html
{% extends "base.html" %}
{% block title %}Event Explorer{% endblock %}
{% block content %}
<h2>Event Explorer</h2>
<form method="get" class="row g-2 mb-3">
    <div class="col-auto">
        <select name="host" class="form-select">
            <option value="">All hosts</option>
            {% for h in hosts %}
            <option value="{{ h }}" {% if h == selected_host %}selected{% endif %}>{{ h }}</option>
            {% endfor %}
        </select>
    </div>
    <div class="col-auto">
        <select name="event_type" class="form-select">
            <option value="">All event types</option>
            {% for et in event_types %}
            <option value="{{ et }}" {% if et == selected_event_type %}selected{% endif %}>{{ et }}</option>
            {% endfor %}
        </select>
    </div>
    <div class="col-auto">
        <input type="text" name="search" class="form-control" placeholder="Search command/raw" value="{{ search }}">
    </div>
    <div class="col-auto">
        <button type="submit" class="btn btn-primary">Filter</button>
    </div>
</form>
<table class="table table-sm table-striped">
    <thead>
        <tr><th>Time</th><th>Host</th><th>Event Type</th><th>User</th><th>Source IP</th><th>Process</th><th>Command Line</th></tr>
    </thead>
    <tbody>
        {% for event in events %}
        <tr>
            <td>{{ event.timestamp.strftime("%Y-%m-%d %H:%M:%S") }}</td>
            <td>{{ event.host }}</td>
            <td>{{ event.event_type }}</td>
            <td>{{ event.user or "" }}</td>
            <td>{{ event.src_ip or "" }}</td>
            <td>{{ event.process_name or "" }}</td>
            <td><code>{{ event.command_line or event.raw or "" }}</code></td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
```

- [ ] **Step 5: Add the Events link to the nav bar**

Modify `app/dashboard/templates/base.html` — replace the nav links block:

```html
            <div>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.alert_feed') }}">Alerts</a>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.heatmap') }}">ATT&amp;CK Heatmap</a>
            </div>
```

with:

```html
            <div>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.alert_feed') }}">Alerts</a>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.heatmap') }}">ATT&amp;CK Heatmap</a>
                <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.event_explorer') }}">Events</a>
            </div>
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_dashboard.py -v`
Expected: 11 passed

- [ ] **Step 7: Commit**

```bash
git add app/dashboard/ tests/test_dashboard.py
git commit -m "feat: add event explorer view"
```

---

## Task 14: Docker Compose, Demo Data Seed Script, and README

**Files:**
- Create: `scripts/__init__.py`
- Create: `scripts/seed_demo_data.py`
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `README.md`
- Test: `tests/test_seed_demo_data.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_seed_demo_data.py`:

```python
from scripts.seed_demo_data import build_demo_events


def test_build_demo_events_covers_all_scenarios():
    events = build_demo_events()

    assert len(events) == 13

    event_types = {e["event_type"] for e in events}
    assert event_types == {
        "auth_failure", "command_execution", "process_creation", "network_connection",
    }

    ssh_events = [e for e in events if e["event_type"] == "auth_failure"]
    assert len(ssh_events) == 6
    assert all(e["src_ip"] == "203.0.113.50" for e in ssh_events)

    command_lines = " ".join(e.get("command_line", "") for e in events)
    assert "visudo" in command_lines        # RULE-002
    assert "useradd" in command_lines       # RULE-003
    assert "-enc" in command_lines          # RULE-004
    assert "/create" in command_lines       # RULE-006
    assert "lsass" in command_lines         # RULE-007

    parent_processes = [e.get("details", {}).get("parent_process") for e in events]
    assert "winword.exe" in parent_processes  # RULE-005

    dest_ports = [e.get("details", {}).get("dest_port") for e in events]
    assert 4444 in dest_ports                 # RULE-008
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_seed_demo_data.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts'`

- [ ] **Step 3: Create `scripts/__init__.py`**

```python
```

(empty file — marks `scripts` as a package for test imports)

- [ ] **Step 4: Create `scripts/seed_demo_data.py`**

```python
from datetime import datetime, timedelta

BASE_URL = "http://localhost:5000"


def build_demo_events():
    """Build 13 synthetic events covering all 8 attack lab scenarios / detection rules."""
    now = datetime.utcnow()
    events = []

    # Scenario 1 (RULE-001, T1110): 6 failed SSH logins from one IP within 60s
    for i in range(6):
        events.append({
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            "host": "linux-vm",
            "event_type": "auth_failure",
            "user": "root",
            "src_ip": "203.0.113.50",
            "details": {"service": "sshd"},
            "raw": "Failed password for root from 203.0.113.50 port 51234 ssh2",
        })

    # Scenario 2 (RULE-002, T1548.003): sudo visudo
    events.append({
        "timestamp": now.isoformat(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": "alice",
        "command_line": "sudo visudo",
        "details": {},
        "raw": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/visudo",
    })

    # Scenario 3 (RULE-003, T1136.001): useradd
    events.append({
        "timestamp": now.isoformat(),
        "host": "linux-vm",
        "event_type": "command_execution",
        "user": "alice",
        "command_line": "useradd -m backdoor",
        "details": {},
        "raw": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor",
    })

    # Scenario 4 (RULE-004, T1059.001): encoded PowerShell
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
        "details": {"parent_process": "explorer.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 5 (RULE-005, T1059): Word spawns cmd.exe
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "details": {"parent_process": "winword.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 6 (RULE-006, T1053.005): scheduled task created
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "schtasks.exe",
        "command_line": "schtasks.exe /create /tn Updater /tr evil.exe /sc daily",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 7 (RULE-007, T1003.001): procdump targeting lsass
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "user": "win-vm\\bob",
        "process_name": "procdump.exe",
        "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
        "details": {"parent_process": "cmd.exe"},
        "raw": "Sysmon Event ID 1: Process Create",
    })

    # Scenario 8 (RULE-008, T1071): outbound connection to C2 port 4444
    events.append({
        "timestamp": now.isoformat(),
        "host": "win-vm",
        "event_type": "network_connection",
        "user": "win-vm\\bob",
        "process_name": "powershell.exe",
        "dest_ip": "198.51.100.23",
        "details": {"dest_port": 4444},
        "raw": "Sysmon Event ID 3: Network Connection",
    })

    return events


def main():
    import requests

    events = build_demo_events()
    for event in events:
        response = requests.post(f"{BASE_URL}/ingest", json=event)
        response.raise_for_status()
        print(f"ingested {event['event_type']} on {event['host']} -> id={response.json()['id']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_seed_demo_data.py -v`
Expected: 1 passed

- [ ] **Step 6: Create `Dockerfile`**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "run.py"]
```

- [ ] **Step 7: Create `docker-compose.yml`**

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: siem
      POSTGRES_DB: siem
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  app:
    build: .
    environment:
      DATABASE_URL: postgresql://siem:siem@db:5432/siem
    ports:
      - "5000:5000"
    depends_on:
      - db

volumes:
  pgdata:
```

- [ ] **Step 8: Create `README.md`**

```markdown
# Custom Detection-Focused SIEM

A self-built SIEM core for a SOC Analyst / Detection Engineer portfolio: ingest
normalized security events, evaluate them against custom YAML-defined detection
rules tagged with MITRE ATT&CK techniques, and review alerts/events on a Flask
dashboard with an ATT&CK coverage heatmap.

## Architecture

```
[Attack Lab: Windows VM (Sysmon) + Linux VM] --(attack scripts)-->
        |
        v
[Log Forwarders] --(POST normalized JSON)-->
        |
        v
   [Flask App]
     - /ingest endpoint (forwarders POST events here)
     - Detection Engine (background loop every ~30s, YAML rules, ATT&CK-tagged)
     - Dashboard UI (alert feed, alert detail, ATT&CK heatmap, event explorer, charts)
        |
        v
   [PostgreSQL] (events, alerts, engine_state tables)
```

## Running with Docker Compose

```bash
docker-compose up --build
```

This starts:
- `db` — PostgreSQL 16
- `app` — the Flask app at http://localhost:5000

Database tables are created automatically on first start.

## Running locally without Docker

```bash
pip install -r requirements.txt
python run.py
```

By default this uses a local SQLite database file (`siem.db`). Set the
`DATABASE_URL` environment variable to point at Postgres instead, e.g.:

```bash
export DATABASE_URL=postgresql://siem:siem@localhost:5432/siem
```

## Generating demo data

With the app running, POST 13 synthetic events covering all 8 attack lab
scenarios to `/ingest`:

```bash
python scripts/seed_demo_data.py
```

Within one detection cycle (~30 seconds) alerts for all 8 scenarios should
appear on the dashboard at http://localhost:5000.

## Dashboard

- `/` — Alert feed: overview charts (alerts per hour, alerts by severity) plus
  a table of recent alerts
- `/alerts/<id>` — Alert detail: rule metadata, triggering events, and a triage
  status dropdown (New / In Progress / Closed - True Positive / Closed - False Positive)
- `/heatmap` — ATT&CK coverage heatmap: every rule's tactic/technique, marked
  "fired" once it has produced at least one alert
- `/events` — Event explorer: filter raw ingested events by host, event type,
  or free-text search

## Detection coverage

| # | Scenario | Rule ID | ATT&CK Technique | Tactic | Rule Type |
|---|----------|---------|-------------------|--------|-----------|
| 1 | SSH brute force (6 failed logins from one IP within 60s) | RULE-001 | T1110 | Credential Access | Aggregation (5+ in 60s) |
| 2 | Sudo used to run visudo / edit /etc/shadow | RULE-002 | T1548.003 | Privilege Escalation | Single event |
| 3 | New local user account created (useradd) | RULE-003 | T1136.001 | Persistence | Single event |
| 4 | PowerShell executed with -enc (base64-encoded command) | RULE-004 | T1059.001 | Execution | Single event |
| 5 | Word spawns cmd.exe / powershell.exe | RULE-005 | T1059 | Execution | Single event |
| 6 | Scheduled task created via schtasks /create | RULE-006 | T1053.005 | Persistence | Single event |
| 7 | procdump targeting lsass.exe | RULE-007 | T1003.001 | Credential Access | Single event |
| 8 | Outbound connection to known C2 port (4444/4445) | RULE-008 | T1071 | Command and Control | Single event |

## Testing

```bash
pytest
```
```

- [ ] **Step 9: Run the full test suite to confirm nothing is broken**

Run: `pytest -v`
Expected: all tests pass (42 passed)

- [ ] **Step 10: Commit**

```bash
git add scripts/ Dockerfile docker-compose.yml README.md tests/test_seed_demo_data.py
git commit -m "feat: add Docker Compose setup, demo data seed script, and README"
```

---
