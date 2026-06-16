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


# ── Auth-enabled (DASHBOARD_PASSWORD set) ───────────────────────────────────

def test_unauthenticated_get_redirects_to_login(authed_client):
    response = authed_client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_unauthenticated_heatmap_redirects_to_login(authed_client):
    response = authed_client.get("/heatmap")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_unauthenticated_events_redirects_to_login(authed_client):
    response = authed_client.get("/events")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_correct_credentials_redirects_to_feed(authed_client):
    response = authed_client.post(
        "/login",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_wrong_credentials_rerenders_form(authed_client):
    response = authed_client.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
    )
    assert response.status_code == 200
    assert b"Invalid" in response.data


def test_login_wrong_username_rerenders_form(authed_client):
    response = authed_client.post(
        "/login",
        data={"username": "root", "password": "secret"},
    )
    assert response.status_code == 200
    assert b"Invalid" in response.data


def test_logout_clears_session_and_blocks_dashboard(authed_client):
    authed_client.post("/login", data={"username": "admin", "password": "secret"})
    authed_client.get("/logout", follow_redirects=False)
    response = authed_client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_when_auth_disabled_redirects_to_feed(client):
    """When DASHBOARD_PASSWORD is not set, /login immediately redirects to /."""
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


# ── /api/alerts key guard ────────────────────────────────────────────────────

def test_api_alerts_requires_key_when_configured(authed_client):
    response = authed_client.get("/api/alerts")
    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_api_alerts_with_correct_key_returns_200(authed_client):
    response = authed_client.get("/api/alerts", headers={"X-Api-Key": "test-secret"})
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)


def test_api_alerts_no_key_configured_allows_through(client):
    """When INGEST_API_KEY is not set, /api/alerts is open (existing behaviour)."""
    response = client.get("/api/alerts")
    assert response.status_code == 200
