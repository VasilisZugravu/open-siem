import pytest
from app.db import db
from app.models import Event


# ── Unit tests: pure enrich_ip function ──────────────────────────────────────

def test_none_ip_returns_none():
    from app.enrichment import enrich_ip
    assert enrich_ip(None) is None


def test_empty_string_returns_none():
    from app.enrichment import enrich_ip
    assert enrich_ip("") is None


def test_private_rfc1918_10_block(  ):
    from app.enrichment import enrich_ip
    result = enrich_ip("10.0.0.1")
    assert result["is_private"] is True
    assert result["country"] is None
    assert result["asn"] is None


def test_private_rfc1918_192_168(  ):
    from app.enrichment import enrich_ip
    result = enrich_ip("192.168.1.5")
    assert result["is_private"] is True


def test_private_loopback(  ):
    from app.enrichment import enrich_ip
    result = enrich_ip("127.0.0.1")
    assert result["is_private"] is True


def test_invalid_ip_string_returns_none():
    # L10a: an unparseable IP is not known to be private — return None (no enrichment)
    from app.enrichment import enrich_ip
    result = enrich_ip("not-an-ip")
    assert result is None


def test_public_ip_returns_enrichment_dict():
    from app.enrichment import enrich_ip
    result = enrich_ip("8.8.8.8")
    assert result is not None
    assert result["is_private"] is False
    assert result["country"] is not None
    assert isinstance(result["asn"], int)
    assert result["asn_org"]


def test_public_ip_deterministic():
    from app.enrichment import enrich_ip
    assert enrich_ip("8.8.8.8") == enrich_ip("8.8.8.8")
    assert enrich_ip("1.1.1.1") == enrich_ip("1.1.1.1")


def test_different_public_ips_may_differ():
    from app.enrichment import enrich_ip
    # Not guaranteed, but with a reasonable COUNTRIES list they should differ
    # for addresses that hash differently — just check both return valid dicts.
    r1 = enrich_ip("8.8.8.8")
    r2 = enrich_ip("1.1.1.1")
    assert r1["is_private"] is False
    assert r2["is_private"] is False


# ── Integration tests: enrichment through /ingest ────────────────────────────

def test_ingest_public_ip_stores_enrichment(app):
    client = app.test_client()
    from datetime import datetime
    resp = client.post("/ingest", json={
        "timestamp": datetime.utcnow().isoformat(),
        "host": "linux-vm",
        "event_type": "auth_failure",
        "src_ip": "1.1.1.1",
    })
    assert resp.status_code == 201
    event_id = resp.get_json()["id"]

    db.session.expire_all()
    event = db.session.get(Event, event_id)
    assert event.enrichment is not None
    assert event.enrichment["is_private"] is False
    assert event.enrichment["country"] is not None


def test_ingest_no_src_ip_leaves_enrichment_none(app):
    client = app.test_client()
    from datetime import datetime
    resp = client.post("/ingest", json={
        "timestamp": datetime.utcnow().isoformat(),
        "host": "win-vm",
        "event_type": "process_creation",
        "command_line": "cmd.exe",
    })
    assert resp.status_code == 201
    event_id = resp.get_json()["id"]

    db.session.expire_all()
    event = db.session.get(Event, event_id)
    assert event.enrichment is None


# ── Template test: enrichment renders in event explorer ──────────────────────

def test_event_explorer_shows_country_for_enriched_event(app):
    from datetime import datetime
    from app.enrichment import enrich_ip

    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "secret"})
    src_ip = "1.1.1.1"
    client.post("/ingest", json={
        "timestamp": datetime.utcnow().isoformat(),
        "host": "linux-vm",
        "event_type": "auth_failure",
        "src_ip": src_ip,
    })

    expected_country = enrich_ip(src_ip)["country"]
    response = client.get("/events")
    assert response.status_code == 200
    assert expected_country.encode() in response.data
