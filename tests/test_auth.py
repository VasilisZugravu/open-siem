import pytest
from app import create_app


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def authed_app():
    """App with DASHBOARD_PASSWORD set — auth enforced."""
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
        "DASHBOARD_USER": "admin",
        "DASHBOARD_PASSWORD": "secret",
        "INGEST_API_KEY": "test-secret",
        "SECRET_KEY": "test-secret-key",
    })
    with app.app_context():
        yield app


@pytest.fixture
def authed_client(authed_app):
    return authed_app.test_client()


# ── Auth-disabled (no DASHBOARD_PASSWORD) ───────────────────────────────────

def test_auth_disabled_allows_dashboard(client):
    """When DASHBOARD_PASSWORD is not set, / returns 200 without any login."""
    response = client.get("/")
    assert response.status_code == 200
