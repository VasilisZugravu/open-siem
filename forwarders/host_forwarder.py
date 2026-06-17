"""Forward THIS machine's real process launches and outbound network connections to the SIEM.

Unlike linux_forwarder.py / windows_forwarder.py (which tail a log file or poll Sysmon, both
needing a specific OS setup), this forwarder uses psutil to snapshot the live process table and
network connection table directly, diffs against the previous snapshot, and forwards anything new.
No admin rights, no Sysmon, no log file required - it reports what's actually running on this PC.
"""
import logging
import os
import socket
import time
from datetime import datetime, timezone

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:5000")
SIEM_API_KEY = os.environ.get("SIEM_API_KEY", "")
POLL_INTERVAL = float(os.environ.get("SIEM_POLL_INTERVAL", "2"))

HOST_LABEL = os.environ.get("SIEM_HOST_LABEL", socket.gethostname())


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def process_to_event(info, host):
    """info: dict with pid, ppid, name, exe/cmdline, username (as returned by psutil.Process.as_dict)."""
    cmdline = info.get("cmdline") or []
    return {
        "timestamp": _now_iso(),
        "host": host,
        "event_type": "process_creation",
        "process_name": info.get("name"),
        "command_line": " ".join(cmdline) if cmdline else None,
        "user": info.get("username"),
        "details": {"pid": info.get("pid"), "ppid": info.get("ppid"), "parent_process": info.get("parent_name")},
        "raw": f"pid={info.get('pid')} ppid={info.get('ppid')} name={info.get('name')} cmdline={cmdline}",
    }


def connection_to_event(info, host):
    """info: dict with pid, process_name, raddr_ip, raddr_port."""
    return {
        "timestamp": _now_iso(),
        "host": host,
        "event_type": "network_connection",
        "process_name": info.get("process_name"),
        "dest_ip": info.get("raddr_ip"),
        "details": {"dest_port": info.get("raddr_port"), "pid": info.get("pid")},
        "raw": f"pid={info.get('pid')} process={info.get('process_name')} -> {info.get('raddr_ip')}:{info.get('raddr_port')}",
    }


def diff_new(previous_keys, current_items, key_fn):
    """Return the items in current_items whose key_fn(item) was not in previous_keys."""
    return [item for item in current_items if key_fn(item) not in previous_keys]


def _is_public_ip(ip):
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


# Ports worth capturing even on a private/loopback address - a connection to a known
# C2 port (RULE-008) is suspicious regardless of whether the destination happens to be
# on a private network, and a real SIEM would not ignore it just because of that.
INTERESTING_PRIVATE_PORTS = {4444, 4445}


def _should_capture_connection(ip, port):
    return _is_public_ip(ip) or port in INTERESTING_PRIVATE_PORTS


def snapshot_processes():
    """Return {(pid, create_time): info_dict} for all currently-visible processes."""
    import psutil

    snapshot = {}
    for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "username", "create_time"]):
        try:
            info = proc.info
            parent_name = None
            try:
                parent = proc.parent()
                parent_name = parent.name() if parent else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            info["parent_name"] = parent_name
            snapshot[(info["pid"], info["create_time"])] = info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return snapshot


def snapshot_connections():
    """Return {(pid, raddr_ip, raddr_port): info_dict} for established connections worth
    forwarding: anything to a public IP, plus anything to a known C2 port (see
    INTERESTING_PRIVATE_PORTS) even on a private/loopback address."""
    import psutil

    snapshot = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        connections = []

    pid_names = {}
    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.pid:
            continue
        if not _should_capture_connection(conn.raddr.ip, conn.raddr.port):
            continue
        if conn.pid not in pid_names:
            try:
                pid_names[conn.pid] = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pid_names[conn.pid] = None
        key = (conn.pid, conn.raddr.ip, conn.raddr.port)
        snapshot[key] = {
            "pid": conn.pid,
            "process_name": pid_names[conn.pid],
            "raddr_ip": conn.raddr.ip,
            "raddr_port": conn.raddr.port,
        }
    return snapshot


def post_event(event):
    try:
        headers = {"X-Api-Key": SIEM_API_KEY} if SIEM_API_KEY else {}
        response = requests.post(f"{SIEM_URL}/ingest", json=event, headers=headers, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        logger.warning("failed to post event: %s", exc)
        return False


def main():
    known_process_keys = set(snapshot_processes().keys())
    known_connection_keys = set(snapshot_connections().keys())
    logger.info(
        "baseline: %d processes, %d connections (not forwarded)",
        len(known_process_keys), len(known_connection_keys),
    )

    while True:
        processes = snapshot_processes()
        for key in diff_new(known_process_keys, processes.keys(), key_fn=lambda k: k):
            event = process_to_event(processes[key], HOST_LABEL)
            if post_event(event):
                logger.info("sent process_creation: %s", event["process_name"])
        known_process_keys = set(processes.keys())

        connections = snapshot_connections()
        for key in diff_new(known_connection_keys, connections.keys(), key_fn=lambda k: k):
            event = connection_to_event(connections[key], HOST_LABEL)
            if post_event(event):
                logger.info("sent network_connection: %s -> %s:%s", event["process_name"], event["dest_ip"], event["details"]["dest_port"])
        known_connection_keys = set(connections.keys())

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
