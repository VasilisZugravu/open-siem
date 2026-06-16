# Correlation / Sequence Rule — Design Spec

## 1. Goal

Add a third detection capability to the engine: a **sequence rule** that fires when two
different event types occur on the same host (or other correlated field) within a
configurable time window, in order. The first live rule — RULE-009 — detects SSH brute
force followed by account creation, a T1110 → T1136.001 kill-chain pattern indicating a
successful compromise leading to persistence.

## 2. Rule YAML Format

Sequence rules use a `sequence:` list instead of the top-level `event_type:` field used
by single-event and aggregation rules. The `correlate_by` field names the event attribute
that must match across steps (e.g. `host`). `timeframe_seconds` is the maximum elapsed
time between step 1 and step 2.

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
```

Only two-step sequences are supported in this implementation (YAGNI). Adding a third step
would require extending the algorithm in `evaluate_sequence_rules()`.

## 3. Engine — evaluate_sequence_rules()

New function added to `app/detection/engine.py`, called from `run_detection_cycle()` after
the existing `evaluate_single_event_rules()` and `evaluate_aggregation_rules()` calls.

**Algorithm:**

1. Skip rules without a `sequence` key.
2. For each sequence rule, query step-1 events within `now - timeframe_seconds`.
3. Apply step-1 `conditions` filter.
4. For each matching step-1 event, query step-2 events that:
   - Have the correct `event_type`
   - Have `timestamp > e1.timestamp` (strict ordering — step 2 must come after step 1)
   - Have `timestamp <= e1.timestamp + timeframe` (within window)
   - Share the same `correlate_by` value (e.g. same host)
   - Pass step-2 `conditions`
5. If any step-2 match exists, check cooldown: skip if there's already an alert for this
   `rule_id` with the same `host` value in `details` created within the window.
6. Fire one alert, with `triggering_event_ids = [e1.id, e2.id]` and
   `details = {"host": corr_val, "step1_event": e1.id, "step2_event": e2.id}`.

The cooldown check uses `Alert.details["host"].as_string()` (SQLAlchemy JSON path
operator) — compatible with both SQLite (tests) and PostgreSQL (prod). The step-2
candidate query is ordered by `Event.timestamp` so `matching2[0]` is always the earliest
qualifying event (deterministic).

## 4. Rules Loader Update

`app/detection/rules_loader.py` currently rejects any rule whose `detection` block lacks
`event_type`. Sequence rules use `sequence` instead. The check becomes:

```python
if "sequence" not in rule["detection"] and "event_type" not in rule["detection"]:
    raise ValueError(f"Rule {path} detection block missing event_type or sequence")
```

No other loader changes needed.

## 5. New Rule File

`rules/linux_brute_then_persist.yml` — RULE-009 as shown in section 2. Brings the total
to 9 rules and adds a new ATT&CK technique (T1136.001 / Persistence) to the heatmap.

## 6. Testing — tests/test_sequence_rules.py

Six engine tests (using the existing `app` fixture from `conftest.py`):

| # | Test | What it proves |
|---|---|---|
| 1 | step 1 + step 2 on same host → alert | Happy path; `rule_id == RULE-009`, `triggering_event_ids == [e1_id, e2_id]` |
| 2 | step 2 before step 1 → no alert | Ordering enforced: `e2.timestamp > e1.timestamp` is required |
| 3 | step 2 after window expires → no alert | `timeframe_seconds` upper bound enforced |
| 4 | step 1 + step 2 on different hosts → no alert | `correlate_by: host` prevents cross-host false positive |
| 5 | cooldown: second pair within window → no second alert | Prevents alert storms on repeated sequences |
| 6 | end-to-end via run_one_cycle(app) | RULE-009 loads from `rules/`, new engine path runs, alert fires |

Two additional `test_rules_loader.py` additions:

| # | Test | What it proves |
|---|---|---|
| 7 | Valid sequence rule loads without error | Loader accepts `sequence` in place of `event_type` |
| 8 | Rule with neither `event_type` nor `sequence` raises ValueError | Validation tightened correctly |

## 7. Out of Scope

- Three-or-more step sequences — not needed for this portfolio demonstration.
- Alert-based correlation (step 1 = an existing Alert) — requires a separate mechanism.
- Cross-host correlation (e.g. same `src_ip` attacking different hosts) — future extension.
- Dashboard/template changes — the alert detail page already shows all triggering events;
  RULE-009 will simply list two events instead of one.
