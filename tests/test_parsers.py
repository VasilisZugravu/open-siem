from datetime import datetime, timedelta, timezone

from forwarders.linux_forwarder import _parse_timestamp, parse_auth_log_line
from forwarders.windows_forwarder import map_sysmon_event


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


def test_parse_timestamp_year_rollover_dec_line_read_in_january(monkeypatch):
    """A 'Dec 31' line tailed on Jan 2 actually happened last year — stamping
    the current year would put it ~12 months in the future and it would never
    fall inside any 'recent' detection window."""
    import forwarders.linux_forwarder as linux_forwarder

    fixed_now = datetime(2026, 1, 2, 9, 0, 0, tzinfo=timezone.utc)

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(linux_forwarder, "datetime", _FixedDatetime)

    result = _parse_timestamp("Dec 31 23:59:00 linux-vm sshd[1]: some line")
    parsed = datetime.fromisoformat(result)

    assert parsed.year == 2025
    assert parsed <= fixed_now


SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SYSMON_ENCODED_POWERSHELL = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-06-16T10:23:45.1234567Z"/>
    <EventRecordID>100</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:23:45.123</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc SGVsbG8gV29ybGQ=</Data>
    <Data Name="User">WIN-VM\\bob</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>"""

SYSMON_OFFICE_SPAWNS_CMD = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-06-16T10:25:00.0000000Z"/>
    <EventRecordID>101</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:25:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="User">WIN-VM\\bob</Data>
    <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
  </EventData>
</Event>"""

SYSMON_SCHEDULED_TASK = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-06-16T10:26:00.0000000Z"/>
    <EventRecordID>102</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:26:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\schtasks.exe</Data>
    <Data Name="CommandLine">schtasks.exe /create /tn Updater /tr evil.exe /sc daily</Data>
    <Data Name="User">WIN-VM\\bob</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>"""

SYSMON_PROCDUMP_LSASS = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-06-16T10:27:00.0000000Z"/>
    <EventRecordID>103</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:27:00.000</Data>
    <Data Name="Image">C:\\Tools\\procdump.exe</Data>
    <Data Name="CommandLine">procdump.exe -ma lsass.exe lsass.dmp</Data>
    <Data Name="User">WIN-VM\\bob</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>"""

SYSMON_NETWORK_CONNECTION_C2 = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-06-16T10:28:00.0000000Z"/>
    <EventRecordID>104</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:28:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="User">WIN-VM\\bob</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="SourceIp">10.0.0.5</Data>
    <Data Name="SourcePort">52344</Data>
    <Data Name="DestinationIp">198.51.100.23</Data>
    <Data Name="DestinationPort">4444</Data>
  </EventData>
</Event>"""

SYSMON_PROCESS_TERMINATE = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>5</EventID>
    <TimeCreated SystemTime="2026-06-16T10:29:00.0000000Z"/>
    <EventRecordID>105</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:29:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
  </EventData>
</Event>"""


def test_map_encoded_powershell():
    event = map_sysmon_event(SYSMON_ENCODED_POWERSHELL)
    assert event["event_type"] == "process_creation"
    assert event["process_name"] == "powershell.exe"
    assert "-enc" in event["command_line"]
    assert event["user"] == "WIN-VM\\bob"
    assert event["details"] == {"parent_process": "explorer.exe"}
    assert event["timestamp"] == "2026-06-16T10:23:45.123456+00:00"
    assert event["raw"] == SYSMON_ENCODED_POWERSHELL


def test_map_office_spawns_cmd():
    event = map_sysmon_event(SYSMON_OFFICE_SPAWNS_CMD)
    assert event["event_type"] == "process_creation"
    assert event["process_name"] == "cmd.exe"
    assert event["details"] == {"parent_process": "winword.exe"}


def test_map_scheduled_task():
    event = map_sysmon_event(SYSMON_SCHEDULED_TASK)
    assert event["event_type"] == "process_creation"
    assert event["process_name"] == "schtasks.exe"
    assert "/create" in event["command_line"]


def test_map_procdump_lsass():
    event = map_sysmon_event(SYSMON_PROCDUMP_LSASS)
    assert event["event_type"] == "process_creation"
    assert event["process_name"] == "procdump.exe"
    assert "lsass" in event["command_line"]


def test_map_network_connection_c2_port():
    event = map_sysmon_event(SYSMON_NETWORK_CONNECTION_C2)
    assert event["event_type"] == "network_connection"
    assert event["process_name"] == "powershell.exe"
    assert event["dest_ip"] == "198.51.100.23"
    assert event["details"] == {"dest_port": 4444}
    assert isinstance(event["details"]["dest_port"], int)


def test_map_unhandled_event_id_returns_none():
    assert map_sysmon_event(SYSMON_PROCESS_TERMINATE) is None


SYSMON_NETWORK_CONNECTION_NO_PORT = f"""<Event xmlns="{SYSMON_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-06-16T10:28:00.0000000Z"/>
    <EventRecordID>106</EventRecordID>
    <Computer>WIN-VM</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-16 10:28:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="User">WIN-VM\\bob</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="SourceIp">10.0.0.5</Data>
    <Data Name="DestinationIp">198.51.100.23</Data>
  </EventData>
</Event>"""


def test_map_network_connection_without_destination_port_does_not_crash():
    """Some Sysmon network_connection records (notably some IPv6 records) omit
    DestinationPort entirely — int(None) must not blow up the whole poll loop."""
    event = map_sysmon_event(SYSMON_NETWORK_CONNECTION_NO_PORT)
    assert event["event_type"] == "network_connection"
    assert event["dest_ip"] == "198.51.100.23"
    assert "dest_port" not in event["details"]


def test_replay_dispatch_auth_line_uses_auth_parser():
    from scripts.replay_dataset import parse_events

    line = "Jun 16 10:23:45 linux-vm sshd[1234]: Failed password for root from 203.0.113.50 port 51234 ssh2"
    events = parse_events([line], "auth")
    assert len(events) == 1
    assert events[0]["event_type"] == "auth_failure"


def test_replay_dispatch_sysmon_line_uses_sysmon_parser():
    from scripts.replay_dataset import parse_events

    events = parse_events([SYSMON_ENCODED_POWERSHELL], "sysmon")
    assert len(events) == 1
    assert events[0]["event_type"] == "process_creation"


def test_replay_dispatch_skips_unparseable_lines():
    from scripts.replay_dataset import parse_events

    unrelated = "Jun 16 10:24:30 linux-vm CRON[5678]: pam_unix(cron:session): session opened for user root"
    events = parse_events([unrelated], "auth")
    assert events == []


def test_replay_rebase_timestamps_preserves_order_and_steps_evenly():
    from scripts.replay_dataset import rebase_timestamps
    from datetime import datetime

    events = [{"event_type": "auth_failure"}, {"event_type": "auth_success"}, {"event_type": "command_execution"}]
    rebase_timestamps(events, step_seconds=2.0)

    timestamps = [datetime.fromisoformat(e["timestamp"]) for e in events]
    assert timestamps[1] - timestamps[0] == timedelta(seconds=2)
    assert timestamps[2] - timestamps[1] == timedelta(seconds=2)
