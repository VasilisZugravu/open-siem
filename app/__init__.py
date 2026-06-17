import os
import secrets
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
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

    if config:
        app.config.update(config)

    # Outside TESTING, a forged/leaked SECRET_KEY lets anyone mint a valid
    # session cookie, and a missing INGEST_API_KEY leaves /ingest open to
    # the whole network — neither should have a usable hardcoded default.
    # ALLOW_UNAUTHENTICATED_INGEST is an explicit, deliberate opt-out for the
    # latter (e.g. a closed network / demo box).
    if not app.config.get("TESTING"):
        if not app.config.get("SECRET_KEY"):
            raise RuntimeError(
                "SECRET_KEY is not set. Set the SECRET_KEY environment variable "
                "to a long random value before starting the app."
            )
        if not app.config.get("INGEST_API_KEY") and not os.environ.get("ALLOW_UNAUTHENTICATED_INGEST"):
            raise RuntimeError(
                "INGEST_API_KEY is not set, which would leave /ingest open to "
                "anyone on the network. Set INGEST_API_KEY, or set "
                "ALLOW_UNAUTHENTICATED_INGEST=1 to explicitly accept that risk."
            )
    elif not app.config.get("SECRET_KEY"):
        # Sessions (login, CSRF token) still need a key under TESTING; an
        # ephemeral random one is fine here since test fixtures don't rely
        # on it being stable across processes.
        app.config["SECRET_KEY"] = secrets.token_hex(32)

    # Session cookie carries the login session and the CSRF token: keep it out
    # of JS (HTTPONLY) and off cross-site requests (SAMESITE). SECURE
    # (HTTPS-only) is forced off under TESTING — the test client and a plain
    # local dev server both talk plain HTTP, so the cookie would otherwise
    # never round-trip. Flask's own config already pre-populates these keys
    # (HTTPONLY=True, SAMESITE=None, SECURE=False), so setdefault() is a
    # no-op here — only apply our values where the caller didn't explicitly
    # override them via `config`.
    overrides = config or {}
    if "SESSION_COOKIE_HTTPONLY" not in overrides:
        app.config["SESSION_COOKIE_HTTPONLY"] = True
    if "SESSION_COOKIE_SAMESITE" not in overrides:
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    if "SESSION_COOKIE_SECURE" not in overrides:
        app.config["SESSION_COOKIE_SECURE"] = not app.config.get("TESTING")

    db.init_app(app)
    app.jinja_env.filters["athens_time"] = to_athens_time

    # Baseline hardening headers. The dashboard renders attacker-influenced
    # event data (host, command lines, etc. from /ingest); these are
    # defense-in-depth against XSS/clickjacking even where escaping is
    # already correct. script-src/style-src allow the specific CDNs the
    # templates load (Chart.js, Bootstrap, Google Fonts) plus 'unsafe-inline'
    # for the inline <script> blocks that render server-side chart data —
    # tightening that further would require a nonce-based rewrite of every
    # template.
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "frame-ancestors 'none'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.ingest import ingest_bp
    from app.dashboard.routes import dashboard_bp
    from app.auth import init_auth
    from app.cli import register_cli
    from app.csrf import init_csrf

    app.register_blueprint(ingest_bp)
    app.register_blueprint(dashboard_bp)
    init_auth(app)
    register_cli(app)
    init_csrf(app)

    with app.app_context():
        db.create_all()

    app.config.setdefault("START_SCHEDULER", not app.config.get("TESTING"))
    if app.config.get("START_SCHEDULER"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
