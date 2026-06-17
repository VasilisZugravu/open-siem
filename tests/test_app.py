import pytest


def test_app_is_created(app):
    assert app is not None
    assert app.config["TESTING"] is True


def test_db_is_initialized(app):
    from app.db import db
    assert db.engine is not None


def test_start_scheduler_false_skips_background_loop(monkeypatch):
    """START_SCHEDULER=False must opt out of the scheduler even when TESTING
    is not set (used by scripts/seed_demo_data.py to avoid a second scheduler
    thread racing the live server's)."""
    import app.scheduler
    from app import create_app

    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_INGEST", "1")
    started = []
    monkeypatch.setattr(
        app.scheduler, "start_background_loop", lambda app: started.append(app)
    )

    create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "START_SCHEDULER": False,
    })

    assert started == []


def test_create_app_refuses_to_start_without_secret_key_outside_testing(monkeypatch):
    """A missing SECRET_KEY outside TESTING must not silently fall back to a
    hardcoded default — that default, once known, lets anyone forge a session
    cookie and log in as admin."""
    from app import create_app

    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_INGEST", "1")

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app({
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "START_SCHEDULER": False,
        })


def test_create_app_refuses_to_start_without_ingest_key_outside_testing(monkeypatch):
    """A missing INGEST_API_KEY outside TESTING must not silently leave /ingest
    open to anyone on the network — require an explicit opt-in instead."""
    from app import create_app

    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_UNAUTHENTICATED_INGEST", raising=False)

    with pytest.raises(RuntimeError, match="INGEST_API_KEY"):
        create_app({
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "START_SCHEDULER": False,
        })


def test_create_app_sets_hardened_session_cookie_flags_outside_testing(monkeypatch):
    """The session cookie carries the login session and the CSRF token, so it
    must not be readable by JS (HTTPONLY), sendable over plain HTTP
    (SECURE), or attached to cross-site requests (SAMESITE)."""
    from app import create_app

    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_INGEST", "1")

    real_app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "START_SCHEDULER": False,
    })

    assert real_app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert real_app.config["SESSION_COOKIE_SECURE"] is True
    assert real_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_session_cookie_secure_flag_is_relaxed_under_testing(app):
    """The TESTING fixture posts over plain http (the Flask test client),
    so SECURE must not be forced on there or every session-dependent test
    would silently lose its cookie."""
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is False


def test_create_app_allows_unauthenticated_ingest_with_explicit_opt_in(monkeypatch):
    from app import create_app

    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_INGEST", "1")

    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "START_SCHEDULER": False,
    })

    assert app is not None
