import pytest

from forwarders.host_forwarder import (
    connection_to_event,
    diff_new,
    process_to_event,
    resolve_host,
    _is_public_ip,
    _is_loopback_or_unspecified,
    _is_capturable_peer,
)
import forwarders.host_forwarder as host_forwarder


@pytest.fixture(autouse=True)
def _clear_rdns_cache():
    host_forwarder._RDNS_CACHE.clear()
    yield
    host_forwarder._RDNS_CACHE.clear()


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


def test_connection_to_event_outbound_shape():
    info = {
        "pid": 99, "process_name": "chrome.exe", "direction": "outbound",
        "external": True, "local_ip": "10.0.0.5", "local_port": 54321,
        "remote_ip": "93.184.216.34", "remote_port": 443, "remote_host": "example.com",
    }
    event = connection_to_event(info, "my-pc")

    assert event["host"] == "my-pc"
    assert event["event_type"] == "network_connection"
    assert event["process_name"] == "chrome.exe"
    assert event["src_ip"] is None
    assert event["dest_ip"] == "93.184.216.34"
    assert event["details"] == {
        "direction": "outbound", "external": True, "local_port": 54321,
        "remote_port": 443, "remote_host": "example.com", "pid": 99,
        "dest_port": 443,
    }


def test_connection_to_event_inbound_shape():
    info = {
        "pid": 100, "process_name": "sshd", "direction": "inbound",
        "external": True, "local_ip": "10.0.0.5", "local_port": 22,
        "remote_ip": "203.0.113.50", "remote_port": 51000, "remote_host": None,
    }
    event = connection_to_event(info, "my-pc")

    assert event["src_ip"] == "203.0.113.50"  # the external connector
    assert event["dest_ip"] == "10.0.0.5"
    assert event["details"]["dest_port"] == 22  # the local port that was connected to
    assert event["details"]["direction"] == "inbound"


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


def test_is_loopback_or_unspecified():
    assert _is_loopback_or_unspecified("127.0.0.1") is True
    assert _is_loopback_or_unspecified("::1") is True
    assert _is_loopback_or_unspecified("0.0.0.0") is True
    assert _is_loopback_or_unspecified("10.0.0.5") is False
    assert _is_loopback_or_unspecified("93.184.216.34") is False
    assert _is_loopback_or_unspecified("not-an-ip") is False


def test_is_capturable_peer_allows_public_and_lan():
    assert _is_capturable_peer("93.184.216.34", 443) is True
    assert _is_capturable_peer("192.168.1.5", 443) is True
    assert _is_capturable_peer("10.0.0.5", 22) is True


def test_is_capturable_peer_excludes_pure_loopback():
    assert _is_capturable_peer("127.0.0.1", 5000) is False
    assert _is_capturable_peer("::1", 5000) is False


def test_is_capturable_peer_allows_c2_port_even_on_loopback():
    assert _is_capturable_peer("127.0.0.1", 4444) is True
    assert _is_capturable_peer("127.0.0.1", 4445) is True


def test_resolve_host_returns_hostname(monkeypatch):
    monkeypatch.setattr(
        "socket.gethostbyaddr",
        lambda ip: ("example.com", [], [ip]),
    )
    assert resolve_host("93.184.216.34") == "example.com"


def test_resolve_host_caches_result(monkeypatch):
    calls = []

    def fake_gethostbyaddr(ip):
        calls.append(ip)
        return ("example.com", [], [ip])

    monkeypatch.setattr("socket.gethostbyaddr", fake_gethostbyaddr)

    assert resolve_host("8.8.8.8") == "example.com"
    assert resolve_host("8.8.8.8") == "example.com"
    assert calls == ["8.8.8.8"]  # second call hit the cache


def test_resolve_host_returns_none_on_no_ptr(monkeypatch):
    import socket as socket_module

    def fake_gethostbyaddr(ip):
        raise socket_module.herror("no PTR")

    monkeypatch.setattr("socket.gethostbyaddr", fake_gethostbyaddr)
    assert resolve_host("1.1.1.1") is None


def test_resolve_host_skips_private_ips(monkeypatch):
    def fail(ip):
        raise AssertionError("should not call gethostbyaddr for private IPs")

    monkeypatch.setattr("socket.gethostbyaddr", fail)
    assert resolve_host("10.0.0.5") is None
    assert resolve_host("127.0.0.1") is None
