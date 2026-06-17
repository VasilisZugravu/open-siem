from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash, current_app
from flask_login import login_required, login_user, logout_user
from app import to_athens_time
from app.db import db
from app.feeds import FEEDS, feed_manager
from app.models import Alert, Event
from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard_bp.route("/")
@login_required
def alert_feed():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(50).all()

    since = datetime.utcnow() - timedelta(hours=24)
    recent_alerts = Alert.query.filter(Alert.created_at >= since).all()

    hourly_counts = {}
    for alert in recent_alerts:
        bucket = to_athens_time(alert.created_at, "%Y-%m-%d %H:00")
        hourly_counts[bucket] = hourly_counts.get(bucket, 0) + 1
    hourly_labels = sorted(hourly_counts.keys())
    hourly_values = [hourly_counts[label] for label in hourly_labels]

    severity_counts = {}
    for alert in Alert.query.all():
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    feed_status = feed_manager.status()

    return render_template(
        "alert_feed.html",
        alerts=alerts,
        hourly_labels=hourly_labels,
        hourly_values=hourly_values,
        severity_labels=list(severity_counts.keys()),
        severity_values=list(severity_counts.values()),
        feeds=FEEDS,
        feed_status=feed_status,
    )


@dashboard_bp.route("/feeds/<name>/start", methods=["POST"])
@login_required
def start_feed(name):
    if name not in FEEDS:
        flash(f"Unknown feed: {name}")
    elif feed_manager.start(name):
        flash(f"Started {FEEDS[name]['label']}.")
    else:
        flash(f"{FEEDS[name]['label']} is already running.")
    return redirect(request.referrer or url_for("dashboard.alert_feed"))


@dashboard_bp.route("/feeds/<name>/stop", methods=["POST"])
@login_required
def stop_feed(name):
    if name not in FEEDS:
        flash(f"Unknown feed: {name}")
    elif feed_manager.stop(name):
        flash(f"Stopped {FEEDS[name]['label']}.")
    else:
        flash(f"{FEEDS[name]['label']} is not running.")
    return redirect(request.referrer or url_for("dashboard.alert_feed"))


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


@dashboard_bp.route("/events")
@login_required
def event_explorer():
    query = Event.query

    host = request.args.get("host")
    event_type = request.args.get("event_type")
    search = request.args.get("search")

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
    if not current_app.config.get("DASHBOARD_PASSWORD"):
        return redirect(url_for("dashboard.alert_feed"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if (username == current_app.config.get("DASHBOARD_USER", "admin")
                and password == current_app.config["DASHBOARD_PASSWORD"]):
            from app.auth import _admin
            login_user(_admin)
            next_page = request.args.get("next") or url_for("dashboard.alert_feed")
            return redirect(next_page)
        flash("Invalid username or password.")
    return render_template("login.html")


@dashboard_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("dashboard.login"))


# dashboard_bp has no url_prefix (registered at "/") — /api/alerts lives here intentionally.
# If a url_prefix is ever added, update validate.py's --siem URL accordingly.
@dashboard_bp.route("/api/alerts")
def api_alerts():
    expected_key = current_app.config.get("INGEST_API_KEY")
    if expected_key and request.headers.get("X-Api-Key") != expected_key:
        return jsonify({"error": "unauthorized"}), 401

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
