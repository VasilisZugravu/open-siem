from forwarders.linux_forwarder import parse_auth_log_line


def test_parse_ssh_failed_password():
    line = "Jun 16 10:23:45 linux-vm sshd[1234]: Failed password for root from 203.0.113.50 port 51234 ssh2"
    event = parse_auth_log_line(line)
    assert event["event_type"] == "auth_failure"
    assert event["user"] == "root"
    assert event["src_ip"] == "203.0.113.50"
    assert event["details"] == {"service": "sshd", "port": 51234}
    assert event["raw"] == line


def test_parse_ssh_failed_password_invalid_user():
    line = "Jun 16 10:23:50 linux-vm sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 51235 ssh2"
    event = parse_auth_log_line(line)
    assert event["event_type"] == "auth_failure"
    assert event["user"] == "admin"
    assert event["src_ip"] == "203.0.113.50"
    assert event["details"] == {"service": "sshd", "port": 51235}


def test_parse_ssh_accepted_password():
    line = "Jun 16 10:24:00 linux-vm sshd[1234]: Accepted password for alice from 203.0.113.10 port 51240 ssh2"
    event = parse_auth_log_line(line)
    assert event["event_type"] == "auth_success"
    assert event["user"] == "alice"
    assert event["src_ip"] == "203.0.113.10"
    assert event["details"] == {"service": "sshd", "port": 51240}


def test_parse_sudo_visudo():
    line = "Jun 16 10:24:10 linux-vm sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/visudo"
    event = parse_auth_log_line(line)
    assert event["event_type"] == "command_execution"
    assert event["user"] == "alice"
    assert "visudo" in event["command_line"]


def test_parse_sudo_useradd():
    line = "Jun 16 10:24:20 linux-vm sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor"
    event = parse_auth_log_line(line)
    assert event["event_type"] == "command_execution"
    assert event["user"] == "alice"
    assert "useradd" in event["command_line"]


def test_parse_unrelated_line_returns_none():
    line = "Jun 16 10:24:30 linux-vm CRON[5678]: pam_unix(cron:session): session opened for user root"
    assert parse_auth_log_line(line) is None
