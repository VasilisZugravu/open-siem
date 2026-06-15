from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for
from app.db import db
from app.models import Alert, Event

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
