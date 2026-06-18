import pytest
from app import create_app
from app.cli import ensure_admin


@pytest.fixture
def app():
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
    })
    with app.app_context():
        ensure_admin("admin", "secret")
        yield app


@pytest.fixture
def anon_client(app):
    """Unauthenticated client — used for login-redirect/login-flow tests."""
    return app.test_client()


@pytest.fixture
def client(app):
    """Logged-in client. Login is always required, so most tests that exercise
    dashboard routes need a session; the few that test the auth flow itself use
    anon_client instead."""
    client = app.test_client()
    # T14: Assert login succeeded so a regression in the auth route surfaces
    # here rather than as a confusing redirect in every downstream test.
    resp = client.post("/login", data={"username": "admin", "password": "secret"},
                       follow_redirects=False)
    assert resp.status_code == 302, f"fixture login failed (status {resp.status_code})"
    return client


@pytest.fixture
def authed_app(app):
    """Back-compat alias: auth is always enforced now, so this is just `app`
    with the admin seeded."""
    return app
