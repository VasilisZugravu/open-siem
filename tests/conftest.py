import pytest
from app import create_app
from app.db import db


@pytest.fixture
def app():
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
    })
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    return app.test_client()
