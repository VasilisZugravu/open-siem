import secrets
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash, current_app, session
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from app import to_athens_time
from app.db import db
from app.feeds import FEEDS, feed_manager
from app.models import Alert, Event, User
from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules

dashboard_bp = Blueprint(
    "dashboard", __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/dashboard-static",
)

# Used to equalize login timing for unknown usernames — without this, a
# missing user skips check_password's hashing entirely while a known
# username always pays that cost, letting an attacker enumerate usernames
# by response time.
_DUMMY_PASSWORD_HASH = generate_password_hash("", method="pbkdf2:sha256")

# Per-source-IP login throttling: brute-forcing the single admin account has
# no other defense (timing equalization stops enumeration, not guessing).
# Keyed by IP rather than username so an attacker can't lock the real admin
# out just by failing logins under their name from elsewhere. State lives on
# the Flask app (current_app.extensions), not a module global, so each app
# instance (and each test's fresh app) starts with a clean slate.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW_SECONDS = 300
_login_attempts_lock = threading.Lock()


def _login_attempts_store():
    return current_app.extensions.setdefault("login_attempts", {})


def _login_rate_limited(ip):
    """True if `ip` has hit LOGIN_MAX_ATTEMPTS failures within the window."""
    with _login_attempts_lock:
        store = _login_attempts_store()
        entry = store.get(ip)
        if entry is None:
            return False
        count, window_start = entry
        if time.monotonic() - window_start > LOGIN_LOCKOUT_WINDOW_SECONDS:
            del store[ip]
            return False
        return count >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(ip):
    with _login_attempts_lock:
        store = _login_attempts_store()
        entry = store.get(ip)
        now = time.monotonic()
        if entry is None or now - entry[1] > LOGIN_LOCKOUT_WINDOW_SECONDS:
            store[ip] = (1, now)
        else:
            count, window_start = entry
            store[ip] = (count + 1, window_start)


def _clear_login_failures(ip):
    with _login_attempts_lock:
        _login_attempts_store().pop(ip, None)


# Per-IP rate limiting for /api/alerts — same pattern as the login throttle.
API_ALERTS_MAX_REQUESTS = 600
API_ALERTS_WINDOW_SECONDS = 60
_api_alerts_rate_lock = threading.Lock()


def _api_alerts_rate_store():
    return current_app.extensions.setdefault("api_alerts_rate", {})


def _api_alerts_rate_limited(ip):
    with _api_alerts_rate_lock:
        store = _api_alerts_rate_store()
        entry = store.get(ip)
        if entry is None:
            return False
        count, window_start = entry
        if time.monotonic() - window_start > API_ALERTS_WINDOW_SECONDS:
            del store[ip]
            return False
        return count >= API_ALERTS_MAX_REQUESTS


def _record_api_alerts_request(ip):
    with _api_alerts_rate_lock:
        store = _api_alerts_rate_store()
        entry = store.get(ip)
        now = time.monotonic()
        if entry is None or now - entry[1] > API_ALERTS_WINDOW_SECONDS:
            store[ip] = (1, now)
        else:
            count, window_start = entry
            store[ip] = (count + 1, window_start)


def _is_safe_redirect_target(target):
    """Only allow same-app relative paths for post-login redirects — an absolute
    URL or a scheme-relative one ("//evil.example") would send a freshly
    authenticated session off-site (open redirect / phishing)."""
    if not target:
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc and target.startswith("/") and not target.startswith("//")


def _alert_feed_data():
    """Shared data for the alert feed page render and its /api/feed AJAX poll."""
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(50).all()

    since = datetime.utcnow() - timedelta(hours=24)
    recent_alerts = Alert.query.filter(Alert.created_at >= since).all()

    hourly_counts = {}
    for alert in recent_alerts:
        bucket = to_athens_time(alert.created_at, "%Y-%m-%d %H:00")
        hourly_counts[bucket] = hourly_counts.get(bucket, 0) + 1
    hourly_labels = sorted(hourly_counts.keys())
    hourly_values = [hourly_counts[label] for label in hourly_labels]

    severity_rows = (
        db.session.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    severity_counts = {row[0]: row[1] for row in severity_rows}
    total_alerts = sum(severity_counts.values())

    feed_status = feed_manager.status()

    metrics = {
        "total_alerts": total_alerts,
        "alerts_24h": len(recent_alerts),
        "critical": severity_counts.get("critical", 0),
        "active_feeds": sum(1 for running in feed_status.values() if running),
    }

    return {
        "alerts": alerts,
        "hourly_labels": hourly_labels,
        "hourly_values": hourly_values,
        "severity_labels": list(severity_counts.keys()),
        "severity_values": list(severity_counts.values()),
        "feed_status": feed_status,
        "metrics": metrics,
    }


@dashboard_bp.route("/")
@login_required
def alert_feed():
    data = _alert_feed_data()
    return render_template(
        "alert_feed.html",
        alerts=data["alerts"],
        hourly_labels=data["hourly_labels"],
        hourly_values=data["hourly_values"],
        severity_labels=data["severity_labels"],
        severity_values=data["severity_values"],
        feeds=FEEDS,
        feed_status=data["feed_status"],
        metrics=data["metrics"],
    )


@dashboard_bp.route("/api/feed")
@login_required
def api_feed():
    data = _alert_feed_data()
    return jsonify({
        "metrics": data["metrics"],
        "hourly_labels": data["hourly_labels"],
        "hourly_values": data["hourly_values"],
        "severity_labels": data["severity_labels"],
        "severity_values": data["severity_values"],
        "feed_status": data["feed_status"],
        "alerts": [
            {
                "id": a.id,
                "created_at": to_athens_time(a.created_at),
                "severity": a.severity,
                "title": a.title,
                "attack_technique": a.attack_technique,
                "host": a.host,
                "status": a.status,
                "url": url_for("dashboard.alert_detail", alert_id=a.id),
            }
            for a in data["alerts"]
        ],
    })


@dashboard_bp.route("/feeds/<name>/start", methods=["POST"])
@login_required
def start_feed(name):
    if name not in FEEDS:
        flash(f"Unknown feed: {name}")
    elif feed_manager.start(name):
        flash(f"Started {FEEDS[name]['label']}.")
    else:
        flash(f"{FEEDS[name]['label']} is already running.")
    return redirect(url_for("dashboard.alert_feed"))


@dashboard_bp.route("/feeds/<name>/stop", methods=["POST"])
@login_required
def stop_feed(name):
    if name not in FEEDS:
        flash(f"Unknown feed: {name}")
    elif feed_manager.stop(name):
        flash(f"Stopped {FEEDS[name]['label']}.")
    else:
        flash(f"{FEEDS[name]['label']} is not running.")
    return redirect(url_for("dashboard.alert_feed"))


@dashboard_bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    events = []
    if alert.triggering_event_ids:
        events = Event.query.filter(Event.id.in_(alert.triggering_event_ids)).all()
    return render_template("alert_detail.html", alert=alert, events=events)


@dashboard_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_alert_status(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    new_status = request.form.get("status")
    if new_status in ("new", "in_progress", "closed_tp", "closed_fp"):
        alert.status = new_status
        db.session.commit()
    else:
        flash(f"Invalid status value: {new_status!r}")
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))


@dashboard_bp.route("/alerts/<int:alert_id>/notes", methods=["POST"])
@login_required
def update_alert_notes(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if "notes" not in request.form:
        return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))
    note = request.form["notes"]
    if len(note) > 2000:
        flash("Note is too long. Maximum 2000 characters.")
        return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))
    alert.notes = note
    alert.notes_updated_at = datetime.utcnow()
    db.session.commit()
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))


@dashboard_bp.route("/heatmap")
@login_required
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


def _event_explorer_data(host, event_type, search):
    """Shared query for the event explorer page render and its /api/events poll."""
    query = Event.query

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

    hosts_query = db.session.query(Event.host).distinct()
    if event_type:
        hosts_query = hosts_query.filter(Event.event_type == event_type)
    hosts = sorted({row[0] for row in hosts_query.all()})

    event_types_query = db.session.query(Event.event_type).distinct()
    if host:
        event_types_query = event_types_query.filter(Event.host == host)
    event_types = sorted({row[0] for row in event_types_query.all()})

    return events, hosts, event_types


def _event_to_dict(event):
    details = event.details or {}
    enrichment = event.enrichment or {}
    geo = ""
    if enrichment and not enrichment.get("is_private") and enrichment.get("country"):
        geo = enrichment["country"] + (f" · AS{enrichment['asn']}" if enrichment.get("asn") else "")
    elif enrichment and enrichment.get("is_private"):
        geo = "private"
    dest = event.dest_ip or ""
    if dest and details.get("dest_port"):
        dest = f"{dest}:{details.get('dest_port')}"
    return {
        "timestamp": to_athens_time(event.timestamp),
        "host": event.host,
        "event_type": event.event_type,
        "direction": details.get("direction") or "",
        "user": event.user or "",
        "src_ip": event.src_ip or "",
        "geo": geo,
        "dest": dest,
        "remote_host": details.get("remote_host") or "",
        "process_name": event.process_name or "",
        "pid": details.get("pid") or "",
        "parent_process": details.get("parent_process") or "",
        "command_line": event.command_line or event.raw or "",
    }


@dashboard_bp.route("/api/events")
@login_required
def api_events():
    host = request.args.get("host") or None
    event_type = request.args.get("event_type") or None
    search = request.args.get("search") or None
    events, _hosts, _event_types = _event_explorer_data(host, event_type, search)
    return jsonify({"events": [_event_to_dict(e) for e in events]})


@dashboard_bp.route("/events")
@login_required
def event_explorer():
    host = request.args.get("host")
    event_type = request.args.get("event_type")
    search = request.args.get("search")

    events, hosts, event_types = _event_explorer_data(host, event_type, search)

    return render_template(
        "event_explorer.html",
        events=events,
        hosts=hosts,
        event_types=event_types,
        selected_host=host or "",
        selected_event_type=event_type or "",
        search=search or "",
    )


@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if _login_rate_limited(request.remote_addr):
            flash("Too many failed login attempts. Try again later.")
            return render_template("login.html"), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user is None:
            check_password_hash(_DUMMY_PASSWORD_HASH, password)  # equalize timing
        elif user.check_password(password):
            _clear_login_failures(request.remote_addr)
            session.pop("_csrf_token", None)  # L6: rotate CSRF token on login
            login_user(user)
            next_page = request.args.get("next")
            if not _is_safe_redirect_target(next_page):
                next_page = url_for("dashboard.alert_feed")
            return redirect(next_page)
        _record_login_failure(request.remote_addr)
        flash("Invalid username or password.")
    return render_template("login.html")


@dashboard_bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    session.clear()   # L6: invalidate the session including the CSRF token
    return redirect(url_for("dashboard.login"))


# dashboard_bp has no url_prefix (registered at "/") — /api/alerts lives here intentionally.
# If a url_prefix is ever added, update validate.py's --siem URL accordingly.
@dashboard_bp.route("/api/alerts")
def api_alerts():
    expected_key = current_app.config.get("INGEST_API_KEY")
    if expected_key:
        if not secrets.compare_digest(request.headers.get("X-Api-Key", ""), expected_key):
            return jsonify({"error": "unauthorized"}), 401
    elif not current_user.is_authenticated:
        # No API key configured: fail closed rather than serving alert data
        # to anyone, instead of falling back to "open to the world".
        return jsonify({"error": "unauthorized"}), 401

    # W4: check before record so exactly API_ALERTS_MAX_REQUESTS succeed per window.
    if _api_alerts_rate_limited(request.remote_addr):
        return jsonify({"error": "rate limit exceeded"}), 429
    _record_api_alerts_request(request.remote_addr)

    rule_id = request.args.get("rule_id")
    since = request.args.get("since")

    query = Alert.query
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            query = query.filter(Alert.created_at >= since_dt)
        except ValueError:
            return jsonify({"error": "Invalid ISO 8601 format for 'since' parameter"}), 400

    alerts = query.order_by(Alert.created_at.desc()).all()
    return jsonify([
        {
            "id": a.id,
            "rule_id": a.rule_id,
            "title": a.title,
            "severity": a.severity,
            "created_at": a.created_at.isoformat(),
            "host": a.host,
        }
        for a in alerts
    ])
