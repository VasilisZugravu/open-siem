"""Forward THIS machine's real process launches and network connections to the SIEM.

Unlike linux_forwarder.py / windows_forwarder.py (which tail a log file or poll Sysmon, both
needing a specific OS setup), this forwarder uses psutil to snapshot the live process table and
network connection table directly, diffs against the previous snapshot, and forwards anything new.
No admin rights, no Sysmon, no log file required - it reports what's actually running on this PC.

Connections are captured in both directions: outbound (this PC connected out to a peer) and
inbound (a peer connected in to one of our listening ports) - see snapshot_connections().
"""
import ipaddress
import logging
import os
import socket
import time
from datetime import datetime, timezone

from forwarders import post_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

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
    """info: dict with pid, process_name, direction, external, local_ip, local_port,
    remote_ip, remote_port, remote_host (see snapshot_connections()).

    Outbound: this PC is the connector, so the remote peer is the "destination".
    Inbound: a peer connected to us, so the remote peer is the "source" - this is what
    lets enrich_ip() (keyed on src_ip) geo/ASN-tag the connecting host in app/ingest.py."""
    direction = info.get("direction")
    details = {
        "direction": direction,
        "external": info.get("external"),
        "local_port": info.get("local_port"),
        "remote_port": info.get("remote_port"),
        "remote_host": info.get("remote_host"),
        "pid": info.get("pid"),
    }
    if direction == "inbound":
        src_ip, dest_ip = info.get("remote_ip"), info.get("local_ip")
        details["dest_port"] = info.get("local_port")
    else:
        src_ip, dest_ip = None, info.get("remote_ip")
        details["dest_port"] = info.get("remote_port")
    return {
        "timestamp": _now_iso(),
        "host": host,
        "event_type": "network_connection",
        "process_name": info.get("process_name"),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "details": details,
        "raw": (
            f"pid={info.get('pid')} process={info.get('process_name')} {direction} "
            f"{info.get('local_ip')}:{info.get('local_port')} <-> "
            f"{info.get('remote_ip')}:{info.get('remote_port')} ({info.get('remote_host') or 'no PTR'})"
        ),
    }


def diff_new(previous_keys, current_items, key_fn):
    """Return the items in current_items whose key_fn(item) was not in previous_keys."""
    return [item for item in current_items if key_fn(item) not in previous_keys]


def _is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def _is_loopback_or_unspecified(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified


# Ports worth capturing even on loopback - a connection to a known C2 port (RULE-008)
# is suspicious regardless of whether the destination happens to be on loopback, and a
# real SIEM would not ignore it just because of that.
INTERESTING_PRIVATE_PORTS = {4444, 4445}


def _is_capturable_peer(ip, port):
    """A connection is worth forwarding when the remote peer is a real network peer -
    public internet OR private LAN - but not pure loopback/IPC noise, unless the port
    is a known C2 port (still worth seeing even on loopback)."""
    if port in INTERESTING_PRIVATE_PORTS:
        return True
    return not _is_loopback_or_unspecified(ip)


_RDNS_CACHE = {}


def resolve_host(ip, timeout=0.3):
    """Reverse-DNS lookup for ip, e.g. "93.184.216.34" -> "example.com". Returns None
    if there's no PTR record, the lookup times out, or ip is private/loopback (where
    rDNS is slow and not useful). Cached (including negative results) so repeated
    connections to the same peer don't re-resolve every poll cycle."""
    if ip in _RDNS_CACHE:
        return _RDNS_CACHE[ip]

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            _RDNS_CACHE[ip] = None
            return None
    except ValueError:
        _RDNS_CACHE[ip] = None
        return None

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        hostname = None
    finally:
        socket.setdefaulttimeout(previous_timeout)

    _RDNS_CACHE[ip] = hostname
    return hostname


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
    """Return {(pid, direction, remote_ip, remote_port, local_port): info_dict} for
    established connections worth forwarding: both inbound (a peer connected to one of
    our listening ports) and outbound (we connected out to a peer), to a real network
    peer (public or LAN) - see _is_capturable_peer()."""
    import psutil

    snapshot = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        connections = []

    listening_ports = {
        conn.laddr.port for conn in connections
        if conn.status == psutil.CONN_LISTEN and conn.laddr
    }

    pid_names = {}
    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.laddr or not conn.pid:
            continue
        if not _is_capturable_peer(conn.raddr.ip, conn.raddr.port):
            continue
        if conn.pid not in pid_names:
            try:
                pid_names[conn.pid] = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pid_names[conn.pid] = None

        direction = "inbound" if conn.laddr.port in listening_ports else "outbound"
        key = (conn.pid, direction, conn.raddr.ip, conn.raddr.port, conn.laddr.port)
        snapshot[key] = {
            "pid": conn.pid,
            "process_name": pid_names[conn.pid],
            "direction": direction,
            "external": _is_public_ip(conn.raddr.ip),
            "local_ip": conn.laddr.ip,
            "local_port": conn.laddr.port,
            "remote_ip": conn.raddr.ip,
            "remote_port": conn.raddr.port,
            "remote_host": resolve_host(conn.raddr.ip),
        }
    return snapshot



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
                logger.info(
                    "sent network_connection: %s %s %s:%s -> %s:%s",
                    event["process_name"], event["details"]["direction"],
                    connections[key]["local_ip"], connections[key]["local_port"],
                    connections[key]["remote_ip"], connections[key]["remote_port"],
                )
        known_connection_keys = set(connections.keys())

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
