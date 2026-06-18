import logging
from datetime import datetime, timedelta
from app.db import db
from app.models import Event, Alert, EngineState
from app.detection.operators import match_conditions

logger = logging.getLogger(__name__)

# H1/L2: How many IDs below the current watermark we re-examine each cycle.
# Under concurrent writes (e.g. PostgreSQL), a transaction that inserts event X
# can commit *after* a later transaction that inserts event Y (Y > X) has
# already been processed, leaving X permanently below the watermark. A small
# lookback ensures we catch those late-committers; the existing dedup gate
# prevents creating duplicate alerts for events we've already alerted on.
_WATERMARK_LOOKBACK = 50

# How long an open (new/in_progress) alert suppresses a new single-event alert
# for the same rule+host+entity. Without a bound, an un-triaged alert blinds
# the rule forever; this caps that to a sane window while still avoiding
# alert-spam for an attack that's still actively unfolding.
SINGLE_EVENT_DEDUP_COOLDOWN_SECONDS = 3600

# Cooldown that prevents an aggregation rule from re-firing for the same
# group while an alert for it is still recent. Deliberately independent of
# the rule's own detection `timeframe_seconds` — tying the two together means
# a continuous attack re-alerts every time the window slides past the first
# alert's created_at, which is exactly the failure mode this constant avoids.
AGGREGATION_COOLDOWN_SECONDS = 1800


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
    state = db.session.get(EngineState, 1)
    if state is None:
        state = EngineState(id=1, last_processed_event_id=0)
        db.session.add(state)
        db.session.commit()
    return state


def evaluate_single_event_rules(rules, now=None):
    """Check events added since the last cycle against rules with no aggregation block.
    Each matching event creates exactly one alert, unless a recent open alert
    for the same rule+host+entity (src_ip, when present) already covers it."""
    now = now or datetime.utcnow()
    state = _get_engine_state()

    # H1/L2: Use a lookback window instead of a strict high-water mark so that
    # late-committing events (id < current watermark) are still examined.
    # The existing dedup gate prevents duplicate alerts for already-alerted events.
    lookback_start = max(0, state.last_processed_event_id - _WATERMARK_LOOKBACK)
    new_events = (
        Event.query.filter(Event.id > lookback_start)
        .order_by(Event.id)
        .all()
    )

    max_id = state.last_processed_event_id
    dedup_window_start = now - timedelta(seconds=SINGLE_EVENT_DEDUP_COOLDOWN_SECONDS)

    for event in new_events:
        max_id = max(max_id, event.id)
        event_dict = event_to_dict(event)
        entity_key = event_dict.get("src_ip")

        for rule in rules:
            # H3: Isolate per-rule errors so a bad rule never aborts evaluation
            # of subsequent valid rules within the same detection cycle.
            try:
                detection = rule["detection"]
                if "aggregation" in detection:
                    continue
                if "sequence" in detection:
                    continue
                if event_dict["event_type"] != detection["event_type"]:
                    continue
                if not match_conditions(event_dict, detection.get("conditions", {})):
                    continue

                open_alerts = Alert.query.filter(
                    Alert.rule_id == rule["id"],
                    Alert.host == event_dict.get("host"),
                    Alert.status.in_(["new", "in_progress"]),
                    Alert.created_at >= dedup_window_start,
                ).all()
                if any((a.details or {}).get("src_ip") == entity_key for a in open_alerts):
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
                    details={"src_ip": entity_key},
                ))
            except Exception:
                logger.exception(
                    "Rule %s raised an exception while evaluating event %s — skipping",
                    rule.get("id"), event.id,
                )

    state.last_processed_event_id = max_id
    db.session.commit()


def evaluate_aggregation_rules(rules, now=None):
    """Check rules with an aggregation block: group recent matching events by
    `group_by` and fire an alert for any group that reaches `threshold` within
    `timeframe_seconds`. A cooldown (the same timeframe) prevents re-firing for
    a group that already has a recent alert."""
    now = now or datetime.utcnow()

    for rule in rules:
        # H3: Isolate per-rule errors — a bad aggregation rule must not abort
        # evaluation of the remaining rules in the same cycle.
        try:
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
                if group_value is None:
                    # Can't attribute this event to any group — bucketing it under
                    # a shared `None` key would collapse unrelated events together.
                    continue
                groups.setdefault(group_value, []).append(event)

            cooldown_start = now - timedelta(seconds=AGGREGATION_COOLDOWN_SECONDS)
            recent_alerts = Alert.query.filter(
                Alert.rule_id == rule["id"],
                Alert.created_at >= cooldown_start,
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
        except Exception:
            logger.exception(
                "Aggregation rule %s raised an exception — skipping", rule.get("id")
            )

    db.session.commit()


def evaluate_sequence_rules(rules, now=None):
    """Fire an alert when a step-1 event is followed by a step-2 event on the same
    correlated field within timeframe_seconds. Only two-step sequences supported."""
    now = now or datetime.utcnow()

    for rule in rules:
        # H3: Isolate per-rule errors — a bad sequence rule must not abort
        # evaluation of the remaining rules in the same cycle.
        try:
            detection = rule["detection"]
            if "sequence" not in detection:
                continue

            steps = detection["sequence"]
            if len(steps) != 2:
                raise ValueError(f"Rule {rule['id']}: only two-step sequences are supported")
            correlate_by = detection["correlate_by"]
            window = timedelta(seconds=detection["timeframe_seconds"])
            step1, step2 = steps[0], steps[1]

            candidates1 = (
                Event.query
                .filter(
                    Event.event_type == step1["event_type"],
                    Event.timestamp >= now - window,
                )
                # M3/L4: secondary sort by id breaks timestamp ties deterministically
                .order_by(Event.timestamp, Event.id)
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
                if corr_val is None:
                    # Can't correlate this event to anything specific — matching
                    # it against other events that also lack the field would
                    # link unrelated activity into a bogus alert.
                    continue
                if corr_val in already_alerted:
                    continue

                candidates2 = (
                    Event.query
                    .filter(
                        Event.event_type == step2["event_type"],
                        Event.timestamp >= e1.timestamp,
                        Event.timestamp <= e1.timestamp + window,
                        Event.id != e1.id,
                    )
                    # M3/L4: secondary sort by id breaks timestamp ties deterministically
                    .order_by(Event.timestamp, Event.id)
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
                already_alerted.add(corr_val)
        except Exception:
            logger.exception(
                "Sequence rule %s raised an exception — skipping", rule.get("id")
            )

    db.session.commit()


def run_detection_cycle(rules):
    """Run one full detection pass: single-event rules, aggregation rules, then sequence rules."""
    now = datetime.utcnow()
    evaluate_single_event_rules(rules, now=now)
    evaluate_aggregation_rules(rules, now=now)
    evaluate_sequence_rules(rules, now=now)
