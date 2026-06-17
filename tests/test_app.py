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

    started = []
    monkeypatch.setattr(
        app.scheduler, "start_background_loop", lambda app: started.append(app)
    )

    create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "START_SCHEDULER": False,
    })

    assert started == []
