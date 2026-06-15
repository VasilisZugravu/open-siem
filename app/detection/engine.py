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
