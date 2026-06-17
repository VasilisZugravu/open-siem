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


def test_api_alerts_compares_key_in_constant_time(authed_client, monkeypatch):
    """Same rationale as the /ingest key check: must use secrets.compare_digest,
    not `!=`, to avoid a timing side-channel on the API key."""
    import app.dashboard.routes as routes

    calls = []
    real_compare_digest = routes.secrets.compare_digest

    def spy_compare_digest(a, b):
        calls.append((a, b))
        return real_compare_digest(a, b)

    monkeypatch.setattr(routes.secrets, "compare_digest", spy_compare_digest)

    authed_client.get("/api/alerts", headers={"X-Api-Key": "wrong-key"})

    assert calls, "expected the API key check to go through secrets.compare_digest"


def test_api_alerts_no_key_configured_allows_through(client):
    """When INGEST_API_KEY is not set, a logged-in dashboard session can still
    reach /api/alerts (existing behaviour)."""
    response = client.get("/api/alerts")
    assert response.status_code == 200


def test_api_alerts_no_key_configured_blocks_anonymous_access(anon_client):
    """Without an API key configured, /api/alerts must fail closed for anyone
    without a logged-in session — not fall open to the entire internet."""
    response = anon_client.get("/api/alerts")
    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


# ── Login is throttled against brute-force guessing ────────────────────────

def test_login_locks_out_after_too_many_failed_attempts(authed_client):
    from app.dashboard.routes import LOGIN_MAX_ATTEMPTS

    for _ in range(LOGIN_MAX_ATTEMPTS):
        response = authed_client.post(
            "/login", data={"username": "admin", "password": "wrong"}
        )
        assert response.status_code == 200

    locked_response = authed_client.post(
        "/login", data={"username": "admin", "password": "wrong"}
    )
    assert locked_response.status_code == 429


def test_login_lockout_also_blocks_the_correct_password(authed_client):
    """Once locked out, even the correct password must not log the attacker
    in — the lockout has to apply before credentials are checked."""
    from app.dashboard.routes import LOGIN_MAX_ATTEMPTS

    for _ in range(LOGIN_MAX_ATTEMPTS):
        authed_client.post("/login", data={"username": "admin", "password": "wrong"})

    response = authed_client.post(
        "/login", data={"username": "admin", "password": "secret"}, follow_redirects=False
    )
    assert response.status_code == 429

    whoami = authed_client.get("/")
    assert whoami.status_code == 302  # still not logged in


def test_login_lockout_is_scoped_per_client_ip(authed_app):
    """A lockout triggered by one source IP must not block a different IP —
    otherwise an attacker could DoS the real admin just by failing logins."""
    from app.dashboard.routes import LOGIN_MAX_ATTEMPTS

    attacker = authed_app.test_client()
    for _ in range(LOGIN_MAX_ATTEMPTS):
        attacker.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": "203.0.113.50"},
        )
    locked = attacker.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.50"},
    )
    assert locked.status_code == 429

    admin = authed_app.test_client()
    response = admin.post(
        "/login",
        data={"username": "admin", "password": "secret"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.7"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_lockout_expires_after_the_window(authed_client, monkeypatch):
    from app.dashboard import routes
    from app.dashboard.routes import LOGIN_MAX_ATTEMPTS

    clock = {"now": 1000.0}
    monkeypatch.setattr(routes.time, "monotonic", lambda: clock["now"])

    for _ in range(LOGIN_MAX_ATTEMPTS):
        authed_client.post("/login", data={"username": "admin", "password": "wrong"})
    locked = authed_client.post("/login", data={"username": "admin", "password": "wrong"})
    assert locked.status_code == 429

    clock["now"] += routes.LOGIN_LOCKOUT_WINDOW_SECONDS + 1

    response = authed_client.post(
        "/login", data={"username": "admin", "password": "secret"}, follow_redirects=False
    )
    assert response.status_code == 302


def test_successful_login_resets_the_attempt_counter(authed_client):
    from app.dashboard.routes import LOGIN_MAX_ATTEMPTS

    for _ in range(LOGIN_MAX_ATTEMPTS - 1):
        authed_client.post("/login", data={"username": "admin", "password": "wrong"})

    success = authed_client.post(
        "/login", data={"username": "admin", "password": "secret"}, follow_redirects=False
    )
    assert success.status_code == 302

    authed_client.get("/logout")
    again = authed_client.post(
        "/login", data={"username": "admin", "password": "secret"}, follow_redirects=False
    )
    assert again.status_code == 302


# ── Login redirect (`next` param) is restricted to local paths ─────────────

def test_login_redirects_to_safe_relative_next_path(anon_client):
    response = anon_client.post(
        "/login?next=/heatmap",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/heatmap"


def test_login_rejects_offsite_next_param(anon_client):
    response = anon_client.post(
        "/login?next=https://evil.example/phish",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_rejects_scheme_relative_next_param(anon_client):
    """'//evil.example' has no scheme but a netloc — browsers treat it as an
    absolute, off-site URL."""
    response = anon_client.post(
        "/login?next=//evil.example",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


# ── CSRF protection on dashboard POST routes ────────────────────────────────

@pytest.fixture
def csrf_app():
    """App with CSRF protection explicitly enabled (it's off under TESTING by
    default so the rest of the suite doesn't need to thread a token through
    every form post)."""
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
    })
    with app.app_context():
        ensure_admin("admin", "secret")
        yield app


def test_post_without_csrf_token_is_rejected(csrf_app):
    client = csrf_app.test_client()
    response = client.post("/login", data={"username": "admin", "password": "secret"})
    assert response.status_code == 400


def test_post_with_valid_csrf_token_succeeds(csrf_app):
    client = csrf_app.test_client()
    client.get("/login")  # populates the session's csrf token
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]

    response = client.post(
        "/login",
        data={"username": "admin", "password": "secret", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 302
