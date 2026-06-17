from scripts.seed_demo_data import build_demo_events, seed_demo_admin


class _FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {"id": 1}


def test_post_event_sends_api_key_header_when_configured(monkeypatch):
    import scripts.seed_demo_data as seed_demo_data

    monkeypatch.setattr(seed_demo_data, "API_KEY", "test-key")
    captured = {}

    def fake_post(url, json=None, headers=None, **kwargs):
        captured["headers"] = headers
        return _FakeResponse()

    monkeypatch.setattr(seed_demo_data.requests, "post", fake_post)

    seed_demo_data.post_event(seed_demo_data.BASE_URL, {"event_type": "x", "host": "h"})

    assert captured["headers"] == {"X-Api-Key": "test-key"}


def test_post_event_sends_no_header_when_api_key_unset(monkeypatch):
    import scripts.seed_demo_data as seed_demo_data

    monkeypatch.setattr(seed_demo_data, "API_KEY", "")
    captured = {}

    def fake_post(url, json=None, headers=None, **kwargs):
        captured["headers"] = headers
        return _FakeResponse()

    monkeypatch.setattr(seed_demo_data.requests, "post", fake_post)

    seed_demo_data.post_event(seed_demo_data.BASE_URL, {"event_type": "x", "host": "h"})

    assert captured["headers"] == {}


def test_build_demo_events_covers_all_scenarios():
    events = build_demo_events()

    assert len(events) == 18

    event_types = {e["event_type"] for e in events}
    assert event_types == {
        "auth_failure", "auth_success", "command_execution", "process_creation", "network_connection",
    }

    ssh_events = [e for e in events if e["event_type"] == "auth_failure"]
    assert len(ssh_events) == 6
    assert all(e["src_ip"] == "45.155.205.233" for e in ssh_events)

    command_lines = " ".join(e.get("command_line", "") for e in events)
    assert "visudo" in command_lines          # RULE-002
    assert "useradd" in command_lines         # RULE-003
    assert "-enc" in command_lines            # RULE-004
    assert "/create" in command_lines         # RULE-006
    assert "lsass" in command_lines           # RULE-007
    assert "comsvcs.dll" in command_lines     # RULE-010
    assert "EnCoDedCommand" in command_lines  # RULE-011
    assert "-decode" in command_lines         # RULE-012

    parent_processes = [e.get("details", {}).get("parent_process") for e in events]
    assert "winword.exe" in parent_processes  # RULE-005

    dest_ports = [e.get("details", {}).get("dest_port") for e in events]
    assert 4444 in dest_ports                 # RULE-008


def test_seed_demo_admin_does_not_start_scheduler(monkeypatch):
    """seed_demo_admin() must opt out of the background scheduler — running
    it against a live server would otherwise spawn a second competing
    detection-cycle thread against the same database."""
    import app as app_module

    # Real (non-TESTING) create_app() now requires these, same as the live
    # server it's seeding alongside would already have set.
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_INGEST", "1")

    captured = {}
    real_create_app = app_module.create_app

    def fake_create_app(config=None):
        captured["config"] = config
        return real_create_app({**(config or {}), "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    monkeypatch.setattr(app_module, "create_app", fake_create_app)

    seed_demo_admin()

    assert captured["config"]["START_SCHEDULER"] is False
