from datetime import datetime

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


def test_ingest_normalizes_timezone_aware_timestamp_to_naive_utc(client):
    """A forwarder may send a tz-aware ISO timestamp (e.g. host_forwarder.py's
    datetime.now(timezone.utc).isoformat()). Event.timestamp is a naive column
    compared against naive datetime.utcnow() throughout the detection engine —
    storing the aware value as-is would silently break those comparisons."""
    response = client.post("/ingest", json={
        "timestamp": "2026-06-15T13:00:00+03:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
    })

    assert response.status_code == 201
    event = Event.query.first()
    assert event.timestamp.tzinfo is None
    assert event.timestamp == datetime(2026, 6, 15, 10, 0, 0)


def test_ingest_invalid_timestamp(client):
    response = client.post("/ingest", json={
        "timestamp": "not-a-date",
        "host": "linux-vm",
        "event_type": "auth_failure",
    })

    assert response.status_code == 400
    assert "timestamp" in response.get_json()["error"]


def test_ingest_rolls_back_session_on_commit_failure(client, monkeypatch):
    """A failed commit (e.g. a transient DB lock) must not leave the scoped
    session broken for the next request on this worker."""
    from app.db import db

    real_commit = db.session.commit
    calls = {"n": 0}

    def flaky_commit():
        calls["n"] += 1
        if calls["n"] == 1:
            raise Exception("simulated commit failure")
        return real_commit()

    monkeypatch.setattr(db.session, "commit", flaky_commit)

    # TESTING=True makes Flask propagate unhandled exceptions out of the test
    # client instead of converting them to a 500 response — that's fine, the
    # behavior under test is whether the session recovers afterwards.
    with pytest.raises(Exception, match="simulated commit failure"):
        client.post("/ingest", json={
            "timestamp": "2026-06-15T10:00:00",
            "host": "linux-vm",
            "event_type": "auth_failure",
        })

    monkeypatch.setattr(db.session, "commit", real_commit)

    recovered_response = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:01",
        "host": "linux-vm",
        "event_type": "auth_failure",
    })
    assert recovered_response.status_code == 201


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


def test_ingest_compares_api_key_in_constant_time(authed_client, monkeypatch):
    """The API key check must use secrets.compare_digest, not `!=`, so an
    attacker can't recover the key byte-by-byte via response timing."""
    import app.ingest as ingest

    calls = []
    real_compare_digest = ingest.secrets.compare_digest

    def spy_compare_digest(a, b):
        calls.append((a, b))
        return real_compare_digest(a, b)

    monkeypatch.setattr(ingest.secrets, "compare_digest", spy_compare_digest)

    authed_client.post(
        "/ingest",
        json={
            "timestamp": "2026-06-16T10:00:00",
            "host": "linux-vm",
            "event_type": "auth_failure",
        },
        headers={"X-Api-Key": "wrong-key"},
    )

    assert calls, "expected the API key check to go through secrets.compare_digest"


# ── T2: /ingest rate limiter ─────────────────────────────────────────────────

def test_ingest_rate_limit_blocks_at_limit(app, client, monkeypatch):
    """/ingest must return 429 when the per-IP counter reaches INGEST_MAX_REQUESTS."""
    import app.ingest as ingest_mod

    clock = {"t": 0.0}
    monkeypatch.setattr(ingest_mod.time, "monotonic", lambda: clock["t"])

    # Pre-seed the rate store at exactly the limit for the test-client IP.
    app.extensions["ingest_rate"] = {
        "127.0.0.1": (ingest_mod.INGEST_MAX_REQUESTS, 0.0)
    }
    payload = {"timestamp": "2026-06-15T10:00:00", "host": "h", "event_type": "e"}
    resp = client.post("/ingest", json=payload)
    assert resp.status_code == 429
    assert "rate limit" in resp.get_json()["error"]


def test_ingest_rate_limit_does_not_affect_other_ips(app, client, monkeypatch):
    """Rate limit is per-IP — a different source IP must not be throttled."""
    import app.ingest as ingest_mod

    clock = {"t": 0.0}
    monkeypatch.setattr(ingest_mod.time, "monotonic", lambda: clock["t"])

    app.extensions["ingest_rate"] = {
        "203.0.113.99": (ingest_mod.INGEST_MAX_REQUESTS, 0.0)
    }
    payload = {"timestamp": "2026-06-15T10:00:00", "host": "h", "event_type": "e"}
    resp = client.post("/ingest", json=payload)
    assert resp.status_code == 201


def test_ingest_rate_limit_resets_after_window(app, client, monkeypatch):
    """After the rate window expires the IP is unthrottled."""
    import app.ingest as ingest_mod

    clock = {"t": 0.0}
    monkeypatch.setattr(ingest_mod.time, "monotonic", lambda: clock["t"])

    app.extensions["ingest_rate"] = {
        "127.0.0.1": (ingest_mod.INGEST_MAX_REQUESTS, 0.0)
    }
    payload = {"timestamp": "2026-06-15T10:00:00", "host": "h", "event_type": "e"}
    assert client.post("/ingest", json=payload).status_code == 429
    clock["t"] = ingest_mod.INGEST_WINDOW_SECONDS + 1
    assert client.post("/ingest", json=payload).status_code == 201


# ── T7/W2: field-length validation ───────────────────────────────────────────

def test_ingest_rejects_oversized_command_line(client):
    resp = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
        "command_line": "x" * 8193,
    })
    assert resp.status_code == 400
    assert "command_line" in resp.get_json()["error"]


def test_ingest_accepts_max_length_command_line(client):
    resp = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
        "command_line": "x" * 8192,
    })
    assert resp.status_code == 201


def test_ingest_rejects_oversized_host(client):
    resp = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:00",
        "host": "h" * 65,
        "event_type": "auth_failure",
    })
    assert resp.status_code == 400
    assert "host" in resp.get_json()["error"]


# ── W12: details type validation ─────────────────────────────────────────────

def test_ingest_rejects_non_dict_details(client):
    """details must be a JSON object — a list would cause AttributeError in
    the engine and templates when .get() is called on it."""
    resp = client.post("/ingest", json={
        "timestamp": "2026-06-15T10:00:00",
        "host": "linux-vm",
        "event_type": "auth_failure",
        "details": ["not", "a", "dict"],
    })
    assert resp.status_code == 400
    assert "details" in resp.get_json()["error"]
