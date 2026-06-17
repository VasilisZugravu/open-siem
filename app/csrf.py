"""Minimal session-based CSRF protection for dashboard POST routes.

Not Flask-WTF (not a project dependency) — generates a per-session token,
exposes it to templates via the `csrf_token()` Jinja global, and rejects
POST/PUT/PATCH/DELETE requests to the dashboard blueprint that don't echo it
back. The ingest/api blueprints are exempt: they authenticate via
X-Api-Key, not the session cookie, so there's no session to forge.

Disabled under TESTING unless WTF_CSRF_ENABLED is explicitly set, so the
existing test client fixtures (which post forms without a token) keep
working — mirroring Flask-WTF's own default test behavior.
"""
import secrets

from flask import abort, current_app, request, session


def _csrf_enabled(app):
    if "WTF_CSRF_ENABLED" in app.config:
        return app.config["WTF_CSRF_ENABLED"]
    return not app.config.get("TESTING")


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def init_csrf(app):
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    @app.before_request
    def _check_csrf():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        if request.blueprint != "dashboard":
            return
        if not _csrf_enabled(current_app):
            return
        sent = request.form.get("csrf_token")
        expected = session.get("_csrf_token")
        if not expected or not sent or not secrets.compare_digest(expected, sent):
            abort(400)
