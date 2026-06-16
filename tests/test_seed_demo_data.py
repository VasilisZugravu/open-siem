from scripts.seed_demo_data import build_demo_events


def test_build_demo_events_covers_all_scenarios():
    events = build_demo_events()

    assert len(events) == 15

    event_types = {e["event_type"] for e in events}
    assert event_types == {
        "auth_failure", "auth_success", "command_execution", "process_creation", "network_connection",
    }

    ssh_events = [e for e in events if e["event_type"] == "auth_failure"]
    assert len(ssh_events) == 6
    assert all(e["src_ip"] == "45.155.205.233" for e in ssh_events)

    command_lines = " ".join(e.get("command_line", "") for e in events)
    assert "visudo" in command_lines        # RULE-002
    assert "useradd" in command_lines       # RULE-003
    assert "-enc" in command_lines          # RULE-004
    assert "/create" in command_lines       # RULE-006
    assert "lsass" in command_lines         # RULE-007

    parent_processes = [e.get("details", {}).get("parent_process") for e in events]
    assert "winword.exe" in parent_processes  # RULE-005

    dest_ports = [e.get("details", {}).get("dest_port") for e in events]
    assert 4444 in dest_ports                 # RULE-008
