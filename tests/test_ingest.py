from app.models import Event


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
