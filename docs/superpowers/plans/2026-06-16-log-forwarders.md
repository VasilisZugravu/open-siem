# Log Forwarders + Parser Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `forwarders/linux_forwarder.py` and `forwarders/windows_forwarder.py`, each a standalone polling script that normalizes host log events and POSTs them to `/ingest`, plus `tests/test_parsers.py` covering their pure parsing/mapping functions.

**Architecture:** Each forwarder is a single self-contained file: a pure parsing function (`parse_auth_log_line` / `map_sysmon_event`, stdlib-only, unit tested), plus small `post_event`/`load_state`/`save_state` helpers and a `main()` polling loop. The Windows forwarder's only `pywin32` usage is inside the event-reading function, imported lazily so the module (and its pure mapping function) import and test cleanly on any OS.

**Tech Stack:** Python 3.12, stdlib `re`/`xml.etree.ElementTree`/`json`/`logging`, `requests` (already in `requirements.txt`), `pywin32` (new, Windows-only, in `forwarders/requirements-windows.txt`), `pytest`.

**Reference spec:** `docs/superpowers/specs/2026-06-16-log-forwarders-design.md`

---

## Environment Note

This repo currently has no working Python environment (the previous worktree's venv was deleted with PR #1's cleanup). Task 1 creates a fresh `venv/` (already gitignored) and verifies the existing 45 tests pass before adding new code.

---

### Task 1: Environment setup + forwarders package scaffolding

**Files:**
- Create: `forwarders/__init__.py`
- Create: `forwarders/requirements-windows.txt`

- [ ] **Step 1: Set up the Python virtualenv and verify the existing suite passes**

Run:
```bash
test -f venv/Scripts/python.exe || "/c/Users/vasil/AppData/Local/Programs/Python/Python312/python.exe" -m venv venv
./venv/Scripts/python.exe -m pip install -q -r requirements.txt
./venv/Scripts/python.exe -m pytest -q
```
Expected: `45 passed`

- [ ] **Step 2: Create the forwarders package**

Create `forwarders/__init__.py` as an empty file (0 bytes).

- [ ] **Step 3: Add the Windows-only requirements file**

Create `forwarders/requirements-windows.txt`:
```
pywin32==306
```

- [ ] **Step 4: Commit**

```bash
git add forwarders/__init__.py forwarders/requirements-windows.txt
git commit -m "feat: scaffold forwarders package and Windows requirements"
```

---

### Task 2: Linux forwarder — `parse_auth_log_line` (TDD)

**Files:**
- Create: `forwarders/linux_forwarder.py`
- Create: `tests/test_parsers.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_parsers.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
./venv/Scripts/python.exe -m pytest tests/test_parsers.py -v
```
Expected: `ModuleNotFoundError: No module named 'forwarders.linux_forwarder'` (collection error — the module doesn't exist yet)

- [ ] **Step 3: Implement `parse_auth_log_line`**

Create `forwarders/linux_forwarder.py`:

```python
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
./venv/Scripts/python.exe -m pytest tests/test_parsers.py -v
```
Expected: `6 passed`

- [ ] **Step 5: Commit**

```bash
git add forwarders/linux_forwarder.py tests/test_parsers.py
git commit -m "feat: add Linux auth.log parser with tests"
```

---

### Task 3: Linux forwarder — polling loop

**Files:**
- Modify: `forwarders/linux_forwarder.py`

- [ ] **Step 1: Add config, state, post, and main-loop code**

Modify `forwarders/linux_forwarder.py` — add these imports at the top (alongside the existing `os`, `re`, `socket`, `datetime`):

```python
import json
import logging
import time

import requests
```

Add this configuration block right after the imports (before `HOST_LABEL`):

```python
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:5000")
POLL_INTERVAL = float(os.environ.get("SIEM_POLL_INTERVAL", "2"))
AUTH_LOG = os.environ.get("SIEM_AUTH_LOG", "/var/log/auth.log")
STATE_FILE = os.environ.get(
    "SIEM_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".linux_forwarder_state.json"),
)
```

Append these functions at the end of the file (after `parse_auth_log_line`):

```python
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def post_event(event):
    try:
        response = requests.post(f"{SIEM_URL}/ingest", json=event, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        logger.warning("failed to post event: %s", exc)
        return False


def main():
    state = load_state()
    if "offset" not in state:
        state["offset"] = os.path.getsize(AUTH_LOG)
        save_state(state)

    while True:
        current_size = os.path.getsize(AUTH_LOG)
        if state["offset"] > current_size:
            state["offset"] = 0

        with open(AUTH_LOG) as f:
            f.seek(state["offset"])
            for line in f:
                if not line.endswith("\n"):
                    break
                event = parse_auth_log_line(line.rstrip("\n"))
                if event is not None:
                    if not post_event(event):
                        break
                    logger.info("sent %s from %s", event["event_type"], event["host"])
                state["offset"] = f.tell()
                save_state(state)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify the module imports cleanly and existing tests still pass**

Run:
```bash
./venv/Scripts/python.exe -c "import forwarders.linux_forwarder"
./venv/Scripts/python.exe -m pytest tests/test_parsers.py -v
```
Expected: no import errors, `6 passed`

- [ ] **Step 3: Commit**

```bash
git add forwarders/linux_forwarder.py
git commit -m "feat: add Linux forwarder polling loop"
```

---

### Task 4: Windows forwarder — `map_sysmon_event` (TDD)

**Files:**
- Create: `forwarders/windows_forwarder.py`
- Modify: `tests/test_parsers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_parsers.py` — add this import alongside the existing one at the top of the file:

```python
from forwarders.windows_forwarder import map_sysmon_event
```

Then append these fixtures and test functions to the end of the file:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
./venv/Scripts/python.exe -m pytest tests/test_parsers.py -v
```
Expected: `ModuleNotFoundError: No module named 'forwarders.windows_forwarder'` (collection error — the module doesn't exist yet; this temporarily also blocks the now-existing Linux tests in the same file)

- [ ] **Step 3: Implement `map_sysmon_event`**

Create `forwarders/windows_forwarder.py`:

```python
import os
import socket
import xml.etree.ElementTree as ET
from datetime import datetime

HOST_LABEL = os.environ.get("SIEM_HOST_LABEL", socket.gethostname())

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _basename(path):
    if path is None:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def map_sysmon_event(xml_string):
    root = ET.fromstring(xml_string)
    system = root.find(f"{EVENT_NS}System")
    event_id = int(system.find(f"{EVENT_NS}EventID").text)
    system_time = system.find(f"{EVENT_NS}TimeCreated").get("SystemTime")
    timestamp = datetime.fromisoformat(system_time.replace("Z", "+00:00")).isoformat()

    event_data = {}
    for data in root.find(f"{EVENT_NS}EventData"):
        event_data[data.get("Name")] = data.text

    if event_id == 1:
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "process_creation",
            "process_name": _basename(event_data.get("Image")),
            "command_line": event_data.get("CommandLine"),
            "user": event_data.get("User"),
            "details": {"parent_process": _basename(event_data.get("ParentImage"))},
            "raw": xml_string,
        }

    if event_id == 3:
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "network_connection",
            "process_name": _basename(event_data.get("Image")),
            "user": event_data.get("User"),
            "dest_ip": event_data.get("DestinationIp"),
            "details": {"dest_port": int(event_data.get("DestinationPort"))},
            "raw": xml_string,
        }

    return None
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
./venv/Scripts/python.exe -m pytest tests/test_parsers.py -v
```
Expected: `12 passed`

- [ ] **Step 5: Commit**

```bash
git add forwarders/windows_forwarder.py tests/test_parsers.py
git commit -m "feat: add Windows Sysmon event mapper with tests"
```

---

### Task 5: Windows forwarder — polling loop, final verification

**Files:**
- Modify: `forwarders/windows_forwarder.py`

- [ ] **Step 1: Add config, state, post, event-reading, and main-loop code**

Modify `forwarders/windows_forwarder.py` — add these imports at the top (alongside the existing `os`, `socket`, `xml.etree.ElementTree`, `datetime`):

```python
import json
import logging
import time

import requests
```

Add this configuration block right after the imports (before `HOST_LABEL`):

```python
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:5000")
POLL_INTERVAL = float(os.environ.get("SIEM_POLL_INTERVAL", "2"))
STATE_FILE = os.environ.get(
    "SIEM_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".windows_forwarder_state.json"),
)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
```

Append these functions at the end of the file (after `map_sysmon_event`):

```python
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def post_event(event):
    try:
        response = requests.post(f"{SIEM_URL}/ingest", json=event, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        logger.warning("failed to post event: %s", exc)
        return False


def _record_id(xml_string):
    root = ET.fromstring(xml_string)
    return int(root.find(f"{EVENT_NS}System/{EVENT_NS}EventRecordID").text)


def _get_latest_record_id():
    import win32evtlog

    handle = win32evtlog.EvtQuery(
        SYSMON_CHANNEL,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
    )
    batch = win32evtlog.EvtNext(handle, 1)
    if not batch:
        return 0
    xml_string = win32evtlog.EvtRender(batch[0], win32evtlog.EvtRenderEventXml)
    return _record_id(xml_string)


def _get_new_events(last_record_id):
    import win32evtlog

    query = f"*[System[EventRecordID > {last_record_id}]]"
    handle = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, query)

    events = []
    while True:
        batch = win32evtlog.EvtNext(handle, 10)
        if not batch:
            break
        for raw_event in batch:
            xml_string = win32evtlog.EvtRender(raw_event, win32evtlog.EvtRenderEventXml)
            events.append((_record_id(xml_string), xml_string))
    return events


def main():
    state = load_state()
    if "last_record_id" not in state:
        state["last_record_id"] = _get_latest_record_id()
        save_state(state)

    while True:
        for record_id, xml_string in _get_new_events(state["last_record_id"]):
            event = map_sysmon_event(xml_string)
            if event is not None:
                if not post_event(event):
                    break
                logger.info("sent %s from %s", event["event_type"], event["host"])
            state["last_record_id"] = record_id
            save_state(state)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify the module imports cleanly without pywin32 installed, and the full suite passes**

This machine doesn't have `pywin32` installed — this step confirms `win32evtlog` is never imported at module load time (only lazily inside `_get_latest_record_id`/`_get_new_events`).

Run:
```bash
./venv/Scripts/python.exe -c "import forwarders.windows_forwarder"
./venv/Scripts/python.exe -m pytest -q
```
Expected: no import errors, `57 passed`

- [ ] **Step 3: Update the graphify graph**

Run:
```bash
"/c/Users/vasil/AppData/Local/Programs/Python/Python312/python.exe" -m graphify update .
```
Expected: graph updated (AST-only, no API cost) — `graphify-out/` is gitignored, no commit needed for this.

- [ ] **Step 4: Commit**

```bash
git add forwarders/windows_forwarder.py
git commit -m "feat: add Windows forwarder polling loop"
```

---

## Self-Review Notes

- **Spec coverage:** §4 (config/state/post/loop conventions) → Tasks 3 & 5; §5 (Linux parsing table, all 3 line types + timestamp handling) → Task 2; §6 (Windows EventID 1/3 mapping, basename reduction, pywin32 isolation) → Tasks 4 & 5; §7 (all 12 listed test cases) → Tasks 2 & 4; file layout (§3) → Task 1.
- **Type consistency:** `HOST_LABEL`, `SIEM_URL`, `POLL_INTERVAL`, `STATE_FILE`, `load_state`/`save_state`/`post_event` signatures are identical in shape across both forwarders (per the design's "self-contained scripts" choice — intentional duplication, not drift).
- **Refinement beyond spec:** `_basename` lowercases the result (spec didn't specify case handling). Real Sysmon `Image` paths for Office apps are `WINWORD.EXE`/`EXCEL.EXE` (uppercase), but `rules/windows_office_spawns_shell.yml` matches lowercase `winword.exe`/`excel.exe` via `op_in` (case-sensitive). Lowercasing is required for RULE-005 to actually fire on real data — covered by `test_map_office_spawns_cmd`.
