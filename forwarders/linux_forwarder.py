import os
import re
import socket
from datetime import datetime

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
        return datetime.utcnow().isoformat()
    parsed = datetime.strptime(match.group(1), "%b %d %H:%M:%S")
    return parsed.replace(year=datetime.utcnow().year).isoformat()


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
