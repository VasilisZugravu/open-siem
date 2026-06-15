from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for
from app.db import db
from app.models import Alert, Event
from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard_bp.route("/")
def alert_feed():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(50).all()

    since = datetime.utcnow() - timedelta(hours=24)
    recent_alerts = Alert.query.filter(Alert.created_at >= since).all()

    hourly_counts = {}
    for alert in recent_alerts:
        bucket = alert.created_at.strftime("%Y-%m-%d %H:00")
        hourly_counts[bucket] = hourly_counts.get(bucket, 0) + 1
    hourly_labels = sorted(hourly_counts.keys())
    hourly_values = [hourly_counts[label] for label in hourly_labels]

    severity_counts = {}
    for alert in Alert.query.all():
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    return render_template(
        "alert_feed.html",
        alerts=alerts,
        hourly_labels=hourly_labels,
        hourly_values=hourly_values,
        severity_labels=list(severity_counts.keys()),
        severity_values=list(severity_counts.values()),
    )


@dashboard_bp.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    events = []
    if alert.triggering_event_ids:
        events = Event.query.filter(Event.id.in_(alert.triggering_event_ids)).all()
    return render_template("alert_detail.html", alert=alert, events=events)


@dashboard_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    new_status = request.form.get("status")
    if new_status in ("new", "in_progress", "closed_tp", "closed_fp"):
        alert.status = new_status
        db.session.commit()
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))


@dashboard_bp.route("/heatmap")
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
