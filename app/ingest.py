import secrets
import threading
import time
from datetime import datetime, timezone
from flask import Blueprint, current_app, request, jsonify
from app.db import db
from app.models import Event
from app.enrichment import enrich_ip

ingest_bp = Blueprint("ingest", __name__)

REQUIRED_FIELDS = ["timestamp", "host", "event_type"]

MAX_FIELD_LEN = 8192  # maximum allowed bytes for long free-text fields

INGEST_MAX_REQUESTS = 600
INGEST_WINDOW_SECONDS = 60
_ingest_rate_lock = threading.Lock()


def _ingest_rate_store():
    return current_app.extensions.setdefault("ingest_rate", {})


def _ingest_rate_limited(ip):
    with _ingest_rate_lock:
        store = _ingest_rate_store()
        entry = store.get(ip)
        if entry is None:
            return False
        count, window_start = entry
        if time.monotonic() - window_start > INGEST_WINDOW_SECONDS:
            del store[ip]
            return False
        return count >= INGEST_MAX_REQUESTS


def _record_ingest_request(ip):
    with _ingest_rate_lock:
        store = _ingest_rate_store()
        entry = store.get(ip)
        now = time.monotonic()
        if entry is None or now - entry[1] > INGEST_WINDOW_SECONDS:
            store[ip] = (1, now)
        else:
            count, window_start = entry
            store[ip] = (count + 1, window_start)


@ingest_bp.route("/ingest", methods=["POST"])
def ingest_event():
    expected_key = current_app.config.get("INGEST_API_KEY")
    if expected_key and not secrets.compare_digest(request.headers.get("X-Api-Key", ""), expected_key):
        return jsonify({"error": "unauthorized"}), 401

    _record_ingest_request(request.remote_addr)
    if _ingest_rate_limited(request.remote_addr):
        return jsonify({"error": "rate limit exceeded"}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid JSON body"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    for field in ("command_line", "raw"):
        val = data.get(field)
        if val and len(str(val)) > MAX_FIELD_LEN:
            return jsonify({"error": f"field '{field}' exceeds {MAX_FIELD_LEN} bytes"}), 400

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
