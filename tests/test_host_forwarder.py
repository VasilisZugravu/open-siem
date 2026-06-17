from forwarders.host_forwarder import (
    connection_to_event,
    diff_new,
    process_to_event,
    _is_public_ip,
    _should_capture_connection,
)


def test_process_to_event_shape():
    info = {
        "pid": 1234, "ppid": 4, "name": "chrome.exe",
        "cmdline": ["chrome.exe", "--profile-directory=Default"],
        "username": "DESKTOP\\vasil", "parent_name": "explorer.exe",
    }
    event = process_to_event(info, "my-pc")

    assert event["host"] == "my-pc"
    assert event["event_type"] == "process_creation"
    assert event["process_name"] == "chrome.exe"
    assert event["command_line"] == "chrome.exe --profile-directory=Default"
    assert event["user"] == "DESKTOP\\vasil"
    assert event["details"] == {"pid": 1234, "ppid": 4, "parent_process": "explorer.exe"}
    assert "timestamp" in event


def test_process_to_event_handles_missing_cmdline():
    info = {"pid": 1, "ppid": 0, "name": "kernel_task", "cmdline": [], "username": None, "parent_name": None}
    event = process_to_event(info, "my-pc")
    assert event["command_line"] is None


def test_connection_to_event_shape():
    info = {"pid": 99, "process_name": "chrome.exe", "raddr_ip": "93.184.216.34", "raddr_port": 443}
    event = connection_to_event(info, "my-pc")

    assert event["host"] == "my-pc"
    assert event["event_type"] == "network_connection"
    assert event["process_name"] == "chrome.exe"
    assert event["dest_ip"] == "93.184.216.34"
    assert event["details"] == {"dest_port": 443, "pid": 99}


def test_diff_new_returns_only_unseen_items():
    previous = {1, 2, 3}
    current = [1, 2, 3, 4, 5]
    new = diff_new(previous, current, key_fn=lambda x: x)
    assert set(new) == {4, 5}


def test_diff_new_empty_when_nothing_new():
    previous = {1, 2}
    current = [1, 2]
    assert diff_new(previous, current, key_fn=lambda x: x) == []


def test_diff_new_uses_key_fn():
    previous = {("a",)}
    current = [{"key": ("a",)}, {"key": ("b",)}]
    new = diff_new(previous, current, key_fn=lambda item: item["key"])
    assert new == [{"key": ("b",)}]


def test_is_public_ip_excludes_private_and_loopback():
    assert _is_public_ip("93.184.216.34") is True
    assert _is_public_ip("10.0.0.5") is False
    assert _is_public_ip("127.0.0.1") is False
    assert _is_public_ip("192.168.1.1") is False
    assert _is_public_ip("not-an-ip") is False


def test_should_capture_connection_allows_public_ip_any_port():
    assert _should_capture_connection("93.184.216.34", 443) is True


def test_should_capture_connection_allows_private_ip_on_c2_port():
    assert _should_capture_connection("127.0.0.1", 4444) is True
    assert _should_capture_connection("192.168.1.5", 4445) is True


def test_should_capture_connection_excludes_private_ip_on_ordinary_port():
    assert _should_capture_connection("127.0.0.1", 5000) is False
    assert _should_capture_connection("10.0.0.5", 443) is False
