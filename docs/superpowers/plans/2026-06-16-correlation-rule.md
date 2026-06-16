# Correlation / Sequence Rule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sequence/correlation detection path to the engine and ship RULE-009 (SSH auth_success → useradd on same host within 10 min → critical alert, T1136.001 Persistence).

**Architecture:** Third engine function `evaluate_sequence_rules()` added to `app/detection/engine.py` alongside the existing two. Rules YAML uses a `sequence:` list instead of `event_type:` at the detection level. Rules loader updated to accept either. One new rule file. No schema or template changes — the alert detail page already renders multiple triggering events.

**Tech Stack:** Flask, SQLAlchemy, PyYAML, pytest, SQLite (tests)

---

## File Map

| File | Change |
|---|---|
| `app/detection/rules_loader.py` | Allow `sequence` in detection block as alternative to `event_type` |
| `rules/linux_brute_then_persist.yml` | CREATE — RULE-009 |
| `app/detection/engine.py` | Add `evaluate_sequence_rules(rules, now=None)` + call from `run_detection_cycle()` |
| `tests/test_rules_loader.py` | Append 2 new tests |
| `tests/test_sequence_rules.py` | CREATE — 6 tests |

---

## Task 1: Rules loader update + RULE-009 file

**Files:**
- Modify: `app/detection/rules_loader.py:15`
- Create: `rules/linux_brute_then_persist.yml`
- Modify: `tests/test_rules_loader.py`

- [ ] **Step 1: Append 2 failing tests to tests/test_rules_loader.py**

Open `tests/test_rules_loader.py` and append these two tests at the bottom of the file:

```python
def test_sequence_rule_loads_without_error(tmp_path):
    import yaml
    rule = {
        "id": "RULE-SEQ",
        "title": "Seq Rule",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "sequence": [
                {"event_type": "a", "conditions": {}},
                {"event_type": "b", "conditions": {}},
            ],
            "correlate_by": "host",
            "timeframe_seconds": 60,
        },
    }
    p = tmp_path / "seq_rule.yml"
    p.write_text(yaml.dump(rule))
    from app.detection.rules_loader import load_rule_file
    result = load_rule_file(str(p))
    assert result["id"] == "RULE-SEQ"


def test_rule_missing_both_event_type_and_sequence_raises(tmp_path):
    import yaml, pytest
    rule = {
        "id": "RULE-BAD",
        "title": "Bad",
        "severity": "low",
        "attack_technique": "T0000",
        "attack_tactic": "Testing",
        "detection": {"conditions": {}},
    }
    p = tmp_path / "bad_rule.yml"
    p.write_text(yaml.dump(rule))
    from app.detection.rules_loader import load_rule_file
    with pytest.raises(ValueError, match="event_type or sequence"):
        load_rule_file(str(p))
```

- [ ] **Step 2: Run the 2 new tests to confirm they fail**

```
venv/Scripts/python -m pytest tests/test_rules_loader.py::test_sequence_rule_loads_without_error tests/test_rules_loader.py::test_rule_missing_both_event_type_and_sequence_raises -v
```

Expected: both FAIL — the loader currently rejects any rule without `event_type`.

- [ ] **Step 3: Update the rules loader validation**

Open `app/detection/rules_loader.py`. Find line 15:

```python
    if "event_type" not in rule["detection"]:
        raise ValueError(f"Rule {path} detection block missing event_type")
```

Replace it with:

```python
    if "sequence" not in rule["detection"] and "event_type" not in rule["detection"]:
        raise ValueError(f"Rule {path} detection block missing event_type or sequence")
```

- [ ] **Step 4: Run the 2 loader tests to confirm they pass**

```
venv/Scripts/python -m pytest tests/test_rules_loader.py::test_sequence_rule_loads_without_error tests/test_rules_loader.py::test_rule_missing_both_event_type_and_sequence_raises -v
```

Expected: both PASS.

- [ ] **Step 5: Create rules/linux_brute_then_persist.yml**

Create this file:

```yaml
id: RULE-009
title: Brute Force Followed by Account Creation
description: >
  SSH login success followed by useradd on the same host within 10 minutes —
  pattern consistent with a brute-force compromise leading to persistence.
severity: critical
attack_technique: T1136.001
attack_tactic: Persistence
detection:
  sequence:
    - event_type: auth_success
      conditions: {}
    - event_type: useradd
      conditions: {}
  correlate_by: host
  timeframe_seconds: 600
tags: [linux, persistence]
```

- [ ] **Step 6: Run the full suite to confirm no regressions**

```
venv/Scripts/python -m pytest -v
```

Expected: all existing tests pass (currently 104).

- [ ] **Step 7: Commit**

```bash
git add app/detection/rules_loader.py rules/linux_brute_then_persist.yml tests/test_rules_loader.py
git commit -m "feat: allow sequence rules in loader, add RULE-009 linux_brute_then_persist"
```

---

## Task 2: evaluate_sequence_rules() (TDD)

**Files:**
- Create: `tests/test_sequence_rules.py`
- Modify: `app/detection/engine.py`

- [ ] **Step 1: Create tests/test_sequence_rules.py with all 6 tests**

```python
from datetime import datetime, timedelta

import pytest
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


# ── Integration test: end-to-end via run_one_cycle ───────────────────────────

def test_sequence_rule_fires_via_run_one_cycle(app, monkeypatch, tmp_path):
    rule_data = {
        "id": "RULE-009",
        "title": "Brute Force Followed by Account Creation",
        "severity": "critical",
        "attack_technique": "T1136.001",
        "attack_tactic": "Persistence",
        "detection": {
            "sequence": [
                {"event_type": "auth_success", "conditions": {}},
                {"event_type": "useradd", "conditions": {}},
            ],
            "correlate_by": "host",
            "timeframe_seconds": 600,
        },
    }
    (tmp_path / "rule009.yml").write_text(yaml.dump(rule_data))
    monkeypatch.setattr("app.scheduler.RULES_DIR", str(tmp_path))

    _event("linux-vm", "auth_success", datetime.utcnow() - timedelta(seconds=30))
    _event("linux-vm", "useradd",      datetime.utcnow())

    run_one_cycle(app)

    db.session.expire_all()
    assert Alert.query.count() == 1
    assert Alert.query.first().rule_id == "RULE-009"
```

- [ ] **Step 2: Run the 6 new tests to confirm they all fail**

```
venv/Scripts/python -m pytest tests/test_sequence_rules.py -v
```

Expected: all 6 FAIL with `ImportError` or `AttributeError` — `evaluate_sequence_rules` doesn't exist yet.

- [ ] **Step 3: Add evaluate_sequence_rules() to app/detection/engine.py**

Open `app/detection/engine.py`. Insert this function after `evaluate_aggregation_rules()` (around line 129), before `run_detection_cycle()`:

```python
def evaluate_sequence_rules(rules, now=None):
    """Fire an alert when a step-1 event is followed by a step-2 event on the same
    correlated field within timeframe_seconds. Only two-step sequences supported."""
    now = now or datetime.utcnow()

    for rule in rules:
        detection = rule["detection"]
        if "sequence" not in detection:
            continue

        steps = detection["sequence"]
        correlate_by = detection["correlate_by"]
        window = timedelta(seconds=detection["timeframe_seconds"])
        step1, step2 = steps[0], steps[1]

        candidates1 = (
            Event.query
            .filter(
                Event.event_type == step1["event_type"],
                Event.timestamp >= now - window,
            )
            .order_by(Event.timestamp)
            .all()
        )
        step1_matching = [
            e for e in candidates1
            if match_conditions(event_to_dict(e), step1.get("conditions", {}))
        ]

        recent_alerts = Alert.query.filter(
            Alert.rule_id == rule["id"],
            Alert.created_at >= now - window,
        ).all()
        already_alerted = {a.details.get(correlate_by) for a in recent_alerts}

        for e1 in step1_matching:
            corr_val = event_to_dict(e1).get(correlate_by)
            if corr_val in already_alerted:
                continue

            candidates2 = (
                Event.query
                .filter(
                    Event.event_type == step2["event_type"],
                    Event.timestamp > e1.timestamp,
                    Event.timestamp <= e1.timestamp + window,
                )
                .order_by(Event.timestamp)
                .all()
            )
            step2_matching = [
                e for e in candidates2
                if event_to_dict(e).get(correlate_by) == corr_val
                and match_conditions(event_to_dict(e), step2.get("conditions", {}))
            ]

            if not step2_matching:
                continue

            e2 = step2_matching[0]
            db.session.add(Alert(
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                attack_technique=rule["attack_technique"],
                attack_tactic=rule["attack_tactic"],
                host=e1.host,
                status="new",
                triggering_event_ids=[e1.id, e2.id],
                details={correlate_by: corr_val, "step1_event": e1.id, "step2_event": e2.id},
            ))
            already_alerted.add(corr_val)  # prevent duplicate in this same cycle

    db.session.commit()
```

- [ ] **Step 4: Update run_detection_cycle() to call evaluate_sequence_rules()**

Find `run_detection_cycle()` at the bottom of `app/detection/engine.py`:

```python
def run_detection_cycle(rules):
    """Run one full detection pass: single-event rules, then aggregation rules."""
    evaluate_single_event_rules(rules)
    evaluate_aggregation_rules(rules)
```

Replace with:

```python
def run_detection_cycle(rules):
    """Run one full detection pass: single-event rules, aggregation rules, then sequence rules."""
    evaluate_single_event_rules(rules)
    evaluate_aggregation_rules(rules)
    evaluate_sequence_rules(rules)
```

- [ ] **Step 5: Run the 6 sequence tests to confirm they all pass**

```
venv/Scripts/python -m pytest tests/test_sequence_rules.py -v
```

Expected: all 6 PASS.

- [ ] **Step 6: Run the full suite to confirm no regressions**

```
venv/Scripts/python -m pytest -v
```

Expected: all tests pass (currently 104 → 110 with 6 new tests + 2 from Task 1 = 112 total).

- [ ] **Step 7: Commit**

```bash
git add app/detection/engine.py tests/test_sequence_rules.py
git commit -m "feat: add evaluate_sequence_rules() for multi-step correlation (RULE-009)"
```

---

## Verification

After both tasks are complete:

1. `venv/Scripts/python -m pytest -v` → 112 tests, all green.
2. Start the app and seed demo data.
3. In Event Explorer, confirm `auth_success` and `useradd` events appear.
4. Manually trigger a sequence: POST an `auth_success` then a `useradd` for the same host to `/ingest`, then wait for the scheduler cycle (or restart the app with `TESTING=False` and call `run_one_cycle` directly).
5. In the Alert Feed, confirm a RULE-009 alert with severity `critical` and technique `T1136.001` appears.
6. Open the alert detail — confirm the Triggering Events table shows both events (one `auth_success`, one `useradd`).
7. Run `graphify update .` to update the knowledge graph.
