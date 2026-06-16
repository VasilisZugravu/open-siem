import pytest
from app import create_app
from app.models import Event


@pytest.fixture
def authed_client():
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
        "INGEST_API_KEY": "test-secret",
    })
    with app.app_context():
        yield app.test_client()


def test_ingest_valid_event(client):
    response = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
        "src_ip": "203.0.113.50",
        "details": {"service": "sshd"},
    })

    assert response.status_code == 201
    assert "id" in response.get_json()

    event = Event.query.first()
    assert event.host == "linux-vm"
    assert event.event_type == "auth_failure"
    assert event.details == {"service": "sshd"}


def test_ingest_missing_required_field(client):
    response = client.post("/ingest", json={
        "host": "linux-vm",
        "event_type": "auth_failure",
    })

    assert response.status_code == 400
    assert "timestamp" in response.get_json()["error"]


def test_ingest_invalid_json(client):
    response = client.post("/ingest", data="not json", content_type="application/json")

    assert response.status_code == 400


def test_ingest_invalid_timestamp(client):
    response = client.post("/ingest", json={
        "timestamp": "not-a-date",
        "host": "linux-vm",
        "event_type": "auth_failure",
    })

    assert response.status_code == 400
    assert "timestamp" in response.get_json()["error"]


def test_ingest_rejects_missing_key(authed_client):
    response = authed_client.post("/ingest", json={
        "timestamp": "2026-06-16T10:00:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
    })

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_ingest_accepts_correct_key(authed_client):
    response = authed_client.post(
        "/ingest",
        json={
            "timestamp": "2026-06-16T10:00:00",
            "host": "linux-vm",
            "event_type": "auth_failure",
        },
        headers={"X-Api-Key": "test-secret"},
    )

    assert response.status_code == 201
