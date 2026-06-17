import secrets
from datetime import datetime, timezone
from flask import Blueprint, current_app, request, jsonify
from app.db import db
from app.models import Event
from app.enrichment import enrich_ip

ingest_bp = Blueprint("ingest", __name__)

REQUIRED_FIELDS = ["timestamp", "host", "event_type"]


@ingest_bp.route("/ingest", methods=["POST"])
def ingest_event():
    expected_key = current_app.config.get("INGEST_API_KEY")
    if expected_key and not secrets.compare_digest(request.headers.get("X-Api-Key", ""), expected_key):
        return jsonify({"error": "unauthorized"}), 401

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

    # Normalize to naive UTC at the boundary: forwarders may send timezone-aware
    # timestamps (e.g. "...+00:00"), but Event.timestamp is a naive column and
    # every comparison in the detection engine assumes naive UTC (datetime.utcnow()).
    # Storing an aware value here would silently break aggregation/sequence
    # time-window filtering.
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    src_ip = data.get("src_ip")
    event = Event(
        timestamp=timestamp,
        host=data["host"],
        event_type=data["event_type"],
        user=data.get("user"),
        src_ip=src_ip,
        dest_ip=data.get("dest_ip"),
        process_name=data.get("process_name"),
        command_line=data.get("command_line"),
        details=data.get("details"),
        raw=data.get("raw"),
        enrichment=enrich_ip(src_ip),
    )
    db.session.add(event)
    try:
        db.session.commit()
    except Exception:
        # Without this, a transient failure (e.g. "database is locked") leaves
        # the scoped session in a broken state, and every subsequent /ingest
        # on this worker fails with PendingRollbackError until it's reset.
        db.session.rollback()
        raise

    return jsonify({"id": event.id}), 201
