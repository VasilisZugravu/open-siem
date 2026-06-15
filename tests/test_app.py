def test_app_is_created(app):
    assert app is not None
    assert app.config["TESTING"] is True


def test_db_is_initialized(app):
    from app.db import db
    assert db.engine is not None
