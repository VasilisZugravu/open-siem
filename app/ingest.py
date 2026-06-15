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

    try:
        timestamp = datetime.fromisoformat(data["timestamp"])
    except (ValueError, TypeError):
        return jsonify({"error": "invalid timestamp"}), 400

    event = Event(
        timestamp=timestamp,
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
