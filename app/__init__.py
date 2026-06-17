import os
from datetime import timezone
from zoneinfo import ZoneInfo

from flask import Flask
from app.db import db

ATHENS_TZ = ZoneInfo("Europe/Athens")


def to_athens_time(value, fmt="%Y-%m-%d %H:%M:%S"):
    """Render a UTC-naive datetime (as stored in the DB) in Athens local time."""
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ATHENS_TZ).strftime(fmt)


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["INGEST_API_KEY"] = os.environ.get("INGEST_API_KEY")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["DASHBOARD_USER"] = os.environ.get("DASHBOARD_USER", "admin")
    app.config["DASHBOARD_PASSWORD"] = os.environ.get("DASHBOARD_PASSWORD")

    if config:
        app.config.update(config)

    db.init_app(app)
    app.jinja_env.filters["athens_time"] = to_athens_time

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.ingest import ingest_bp
    from app.dashboard.routes import dashboard_bp
    from app.auth import init_auth

    app.register_blueprint(ingest_bp)
    app.register_blueprint(dashboard_bp)
    init_auth(app)

    with app.app_context():
        db.create_all()

    if not app.config.get("TESTING"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
