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
    state = db.session.get(EngineState, 1)
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
            if "sequence" in detection:
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
