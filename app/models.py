from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.db import db


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    host = db.Column(db.String(64), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    user = db.Column(db.String(128), nullable=True)
    src_ip = db.Column(db.String(45), nullable=True)
    dest_ip = db.Column(db.String(45), nullable=True)
    process_name = db.Column(db.String(256), nullable=True)
    command_line = db.Column(db.Text, nullable=True)
    details = db.Column(db.JSON, nullable=True)
    raw = db.Column(db.Text, nullable=True)
    enrichment = db.Column(db.JSON, nullable=True)


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    rule_id = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    attack_technique = db.Column(db.String(32), nullable=False)
    attack_tactic = db.Column(db.String(64), nullable=False)
    host = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="new")
    triggering_event_ids = db.Column(db.JSON, nullable=False)
    details = db.Column(db.JSON, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    notes_updated_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.Index("ix_alert_rule_host_status", "rule_id", "host", "status"),
        db.CheckConstraint("status IN ('new','in_progress','closed_tp','closed_fp')", name="ck_alert_status"),
        db.CheckConstraint("severity IN ('low','medium','high','critical')", name="ck_alert_severity"),
    )


class EngineState(db.Model):
    __tablename__ = "engine_state"

    id = db.Column(db.Integer, primary_key=True)
    last_processed_event_id = db.Column(db.Integer, nullable=False, default=0)


class User(UserMixin, db.Model):
    """Single admin account used to log in to the dashboard. Created/updated via
    the `flask create-admin` CLI command (see app/cli.py) or the demo seed script
    — there is no public signup."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
