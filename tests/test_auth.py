import pytest
from app import create_app
from app.cli import ensure_admin


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def authed_app():
    """App with the admin seeded and an INGEST_API_KEY configured, for the
    /api/alerts key-guard tests."""
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
        "INGEST_API_KEY": "test-secret",
        "SECRET_KEY": "test-secret-key",
    })
    with app.app_context():
        ensure_admin("admin", "secret")
        yield app


@pytest.fixture
def authed_client(authed_app):
    return authed_app.test_client()


# ── Login is always required ────────────────────────────────────────────────

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


def test_login_hashes_password_even_for_unknown_username(authed_client, monkeypatch):
    """An unknown username must still pay the password-hashing cost, so a
    timing attacker can't distinguish 'no such user' from 'wrong password'."""
    import app.dashboard.routes as routes

    calls = []
    monkeypatch.setattr(
        routes, "check_password_hash",
        lambda pwhash, password: calls.append(password) or False,
    )

    authed_client.post("/login", data={"username": "no-such-user", "password": "x"})

    assert calls == ["x"]


def test_logout_clears_session_and_blocks_dashboard(authed_client):
    authed_client.post("/login", data={"username": "admin", "password": "secret"})
    authed_client.get("/logout", follow_redirects=False)
    response = authed_client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_ensure_admin_rejects_empty_password(authed_app):
    """An empty ADMIN_PASSWORD env var must not silently create an
    admin account with no password."""
    from app.cli import ensure_admin
    with authed_app.app_context():
        with pytest.raises(ValueError):
            ensure_admin("admin", "")


def test_load_user_with_non_numeric_id_returns_none(authed_app):
    """A stale pre-migration session cookie (old singleton stored the literal
    string "admin" as the user id) must not crash the user_loader."""
    from app.auth import load_user
    with authed_app.app_context():
        assert load_user("admin") is None


def test_password_is_stored_hashed(authed_app):
    from app.models import User
    with authed_app.app_context():
        user = User.query.filter_by(username="admin").first()
        assert user.password_hash != "secret"
        assert user.check_password("secret")
        assert not user.check_password("wrong")


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
