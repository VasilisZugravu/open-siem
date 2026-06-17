import re

from scripts.simulate_traffic import ATTACK_SCENARIOS, build_benign_events


def _matches_attack_signature(event):
    """True if event would trip any rule signature exercised by ATTACK_SCENARIOS."""
    command_line = (event.get("command_line") or "").lower()
    process_name = (event.get("process_name") or "").lower()
    dest_port = event.get("details", {}).get("dest_port")

    if "lsass" in command_line:
        return True
    if "-enc" in command_line:
        return True
    if re.search(r"comsvcs\.dll.*minidump", command_line, re.I):
        return True
    if "-decode" in command_line:
        return True
    if "/create" in command_line and process_name == "schtasks.exe":
        return True
    if "useradd" in command_line:
        return True
    if re.search(r"(shadow|visudo)", command_line):
        return True
    if process_name in ("cmd.exe", "powershell.exe") and event.get("details", {}).get("parent_process") in (
        "winword.exe", "excel.exe",
    ):
        return True
    if dest_port in (4444, 4445):
        return True
    return False


def test_build_benign_events_never_matches_attack_signatures():
    for _ in range(50):  # benign builder is randomized; sample many ticks
        events = build_benign_events()
        assert events, "benign tick should produce at least one event"
        for event in events:
            assert not _matches_attack_signature(event), f"benign event tripped a signature: {event}"


def test_all_attack_scenarios_produce_their_signature():
    for scenario in ATTACK_SCENARIOS:
        events = scenario()
        assert events, f"{scenario.__name__} produced no events"

        # RULE-001 is an aggregation rule (5+ auth_failure/sshd from one src_ip), not a
        # single-event signature, so check its threshold directly instead of per-event.
        if scenario.__name__ == "attack_ssh_bruteforce":
            failures = [e for e in events if e["event_type"] == "auth_failure" and e["details"]["service"] == "sshd"]
            assert len(failures) >= 5
            assert len({e["src_ip"] for e in failures}) == 1
            continue

        assert any(_matches_attack_signature(e) for e in events), (
            f"{scenario.__name__} did not produce a matching attack signature"
        )


def test_ssh_bruteforce_scenario_has_six_events_same_ip():
    from scripts.simulate_traffic import attack_ssh_bruteforce

    events = attack_ssh_bruteforce()
    assert len(events) == 6
    ips = {e["src_ip"] for e in events}
    assert len(ips) == 1


def test_brute_then_persist_scenario_is_sequence():
    from scripts.simulate_traffic import attack_brute_then_persist

    events = attack_brute_then_persist()
    assert len(events) == 2
    assert events[0]["event_type"] == "auth_success"
    assert events[1]["event_type"] == "command_execution"
    assert "useradd" in events[1]["command_line"]
