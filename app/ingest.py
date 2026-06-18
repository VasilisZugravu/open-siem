import secrets
from datetime import datetime, timezone
from flask import Blueprint, current_app, request, jsonify
from app.db import db
from app.models import Event
from app.enrichment import enrich_ip
from app._rate_limit import is_rate_limited, record_request

ingest_bp = Blueprint("ingest", __name__)

REQUIRED_FIELDS = ["timestamp", "host", "event_type"]

MAX_FIELD_LEN = 8192  # maximum allowed bytes for long free-text fields

INGEST_MAX_REQUESTS = 600
INGEST_WINDOW_SECONDS = 60


@ingest_bp.route("/ingest", methods=["POST"])
def ingest_event():
    expected_key = current_app.config.get("INGEST_API_KEY")
    if expected_key and not secrets.compare_digest(request.headers.get("X-Api-Key", ""), expected_key):
        return jsonify({"error": "unauthorized"}), 401

    # W4: check before record so exactly MAX_REQUESTS succeed before the 429.
    if is_rate_limited("ingest_rate", request.remote_addr, INGEST_MAX_REQUESTS, INGEST_WINDOW_SECONDS):
        return jsonify({"error": "rate limit exceeded"}), 429
    record_request("ingest_rate", request.remote_addr, INGEST_WINDOW_SECONDS)

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid JSON body"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    for field in ("command_line", "raw"):
        val = data.get(field)
        if val and len(str(val)) > MAX_FIELD_LEN:
            return jsonify({"error": f"field '{field}' exceeds {MAX_FIELD_LEN} bytes"}), 400

    # W2: Reject oversized values for short string fields before the ORM sees
    # them — SQLite silently truncates; PostgreSQL raises DataError (500).
    _SHORT_FIELD_LENGTHS = {
        "host": 64, "event_type": 64, "user": 128,
        "src_ip": 45, "dest_ip": 45, "process_name": 256,
    }
    for field, max_len in _SHORT_FIELD_LENGTHS.items():
        val = data.get(field)
        if val is not None and len(str(val)) > max_len:
            return jsonify({"error": f"field '{field}' exceeds {max_len} characters"}), 400

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

    # W12: details must be a JSON object; a list or scalar would cause
    # AttributeError when the engine or templates call .get() on it.
    details = data.get("details")
    if details is not None and not isinstance(details, dict):
        return jsonify({"error": "field 'details' must be a JSON object"}), 400

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
