import logging
import os
import re
import socket
import time
from datetime import datetime, timedelta, timezone

from forwarders import post_event, load_state, save_state

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

POLL_INTERVAL = float(os.environ.get("SIEM_POLL_INTERVAL", "2"))
AUTH_LOG = os.environ.get("SIEM_AUTH_LOG", "/var/log/auth.log")
STATE_FILE = os.environ.get(
    "SIEM_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".linux_forwarder_state.json"),
)

HOST_LABEL = os.environ.get("SIEM_HOST_LABEL", socket.gethostname())

SSH_FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+) ssh2"
)
SSH_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted password for (\S+) from (\S+) port (\d+) ssh2"
)
SUDO_RE = re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.+)$")
SYSLOG_TIMESTAMP_RE = re.compile(r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})")


def _parse_timestamp(line):
    match = SYSLOG_TIMESTAMP_RE.match(line)
    if not match:
        return datetime.now(timezone.utc).isoformat()
    now = datetime.now(timezone.utc)
    parsed = datetime.strptime(match.group(1), "%b %d %H:%M:%S").replace(
        year=now.year, tzinfo=timezone.utc
    )
    # Syslog timestamps have no year. Stamping the current year is wrong for a
    # "Dec 31" line read on "Jan 1/2" of the next year — it lands ~12 months in
    # the future and never falls inside any "recent" detection window. If the
    # naive guess is more than a day ahead of now, it must be from last year.
    if parsed - now > timedelta(days=1):
        parsed = parsed.replace(year=now.year - 1)
    return parsed.isoformat()


def parse_auth_log_line(line):
    timestamp = _parse_timestamp(line)

    match = SSH_FAILED_RE.search(line)
    if match:
        user, src_ip, port = match.groups()
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "auth_failure",
            "user": user,
            "src_ip": src_ip,
            "details": {"service": "sshd", "port": int(port)},
            "raw": line,
        }

    match = SSH_ACCEPTED_RE.search(line)
    if match:
        user, src_ip, port = match.groups()
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "auth_success",
            "user": user,
            "src_ip": src_ip,
            "details": {"service": "sshd", "port": int(port)},
            "raw": line,
        }

    match = SUDO_RE.search(line)
    if match:
        user, command_line = match.groups()
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "command_execution",
            "user": user,
            "command_line": command_line,
            "raw": line,
        }

    return None



def main():
    state = load_state(STATE_FILE)
    if "offset" not in state:
        state["offset"] = os.path.getsize(AUTH_LOG)
        save_state(state, STATE_FILE)

    while True:
        current_size = os.path.getsize(AUTH_LOG)
        if state["offset"] > current_size:
            state["offset"] = 0

        with open(AUTH_LOG) as f:
            f.seek(state["offset"])
            while True:
                line = f.readline()
                if not line.endswith("\n"):
                    break
                # O7: guard per-line parse errors so a malformed line doesn't
                # crash the forwarder loop (mirrors windows_forwarder.py).
                try:
                    event = parse_auth_log_line(line.rstrip("\n"))
                except Exception as exc:
                    logger.warning("Failed to parse auth.log line: %s — skipping", exc)
                    state["offset"] = f.tell()
                    save_state(state, STATE_FILE)
                    continue
                if event is not None:
                    if not post_event(event):
                        break
                    logger.info("sent %s from %s", event["event_type"], event["host"])
                state["offset"] = f.tell()
                save_state(state, STATE_FILE)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
