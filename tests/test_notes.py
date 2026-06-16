import pytest
from app.db import db
from app.models import Alert


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def unauthed_client(authed_app):
    """Unauthenticated test client for the auth-enabled app."""
    return authed_app.test_client()


@pytest.fixture
def logged_in_client(authed_app):
    """Test client that has already POSTed to /login."""
    client = authed_app.test_client()
    client.post("/login", data={"username": "admin", "password": "secret"})
    return client


@pytest.fixture
def alert_id(authed_app):
    """Create a minimal Alert in the test DB and return its id."""
    alert = Alert(
        rule_id="RULE-001",
        title="Test Alert",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="test-host",
        triggering_event_ids=[1],
    )
    db.session.add(alert)
    db.session.commit()
    return alert.id


# ── POST route tests ──────────────────────────────────────────────────────────

def test_unauthenticated_post_redirects_to_login(unauthed_client, alert_id):
    response = unauthed_client.post(f"/alerts/{alert_id}/notes", data={"notes": "hi"})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_save_note_sets_notes_and_timestamp(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "test note"})
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == "test note"
    assert alert.notes_updated_at is not None


def test_overwrite_note_replaces_previous(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "first"})
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "second"})
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == "second"


def test_save_empty_note_clears_text_but_sets_timestamp(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "something"})
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": ""})
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == ""
    assert alert.notes_updated_at is not None


def test_max_length_guard_rejects_note_over_2000_chars(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "initial"})
    response = logged_in_client.post(
        f"/alerts/{alert_id}/notes",
        data={"notes": "x" * 2001},
        follow_redirects=False,
    )
    assert response.status_code == 302
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == "initial"  # unchanged


# ── GET / template rendering tests ───────────────────────────────────────────

def test_detail_page_shows_saved_note(logged_in_client, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "my findings"})
    response = logged_in_client.get(f"/alerts/{alert_id}")
    assert response.status_code == 200
    assert b"my findings" in response.data


def test_detail_page_shows_last_updated_when_note_saved(logged_in_client, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "check"})
    response = logged_in_client.get(f"/alerts/{alert_id}")
    assert b"Last updated" in response.data


def test_xss_note_is_html_escaped_in_template(logged_in_client, alert_id):
    logged_in_client.post(
        f"/alerts/{alert_id}/notes",
        data={"notes": "<script>alert(1)</script>"},
    )
    response = logged_in_client.get(f"/alerts/{alert_id}")
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data
