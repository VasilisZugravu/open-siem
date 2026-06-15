# Log Forwarders + Parser Tests — Design Spec

**Date:** 2026-06-16
**Covers:** Design spec §6 (Log Forwarders) and the parser/forwarder-test portion of §9 (Testing & Validation)

## 1. Overview

Two standalone Python scripts, one per attack-lab VM, that read host log sources and POST normalized JSON events to the SIEM's `/ingest` endpoint:

- `forwarders/linux_forwarder.py` — tails `/var/log/auth.log` on the Linux VM
- `forwarders/windows_forwarder.py` — polls the Sysmon Operational event log on the Windows VM

Each runs as a long-lived polling loop and persists its read position to a local state file so a restart doesn't replay old events. Both produce events matching the normalized schema already accepted by `/ingest` (see `app/models.py` `Event` and `tests/test_ingest.py`).

## 2. Scope

**In scope:**
- `forwarders/linux_forwarder.py` and `forwarders/windows_forwarder.py`
- `forwarders/requirements-windows.txt` (pywin32, Windows-only)
- `tests/test_parsers.py` — unit tests for each forwarder's pure parsing function

**Out of scope (future work):**
- §7/§10 Attack Lab scenario scripts and the live end-to-end validation/coverage table (§9's other bullet) — these exercise the forwarders against a live SIEM instance and belong to a separate brainstorming cycle
- §10 README polish (architecture diagram, screenshots, VM setup instructions)

## 3. File Layout

```
forwarders/
├── __init__.py
├── linux_forwarder.py        # tails /var/log/auth.log, normalizes, POSTs to /ingest
├── windows_forwarder.py       # polls Sysmon Operational log, normalizes, POSTs to /ingest
└── requirements-windows.txt   # pywin32 — installed only on the Windows lab VM

tests/
└── test_parsers.py            # unit tests for parse_auth_log_line() and map_sysmon_event()
```

Each forwarder is run directly on its VM: `python forwarders/linux_forwarder.py` (Linux) or `python forwarders\windows_forwarder.py` (Windows, after `pip install -r forwarders/requirements-windows.txt`). The root `requirements.txt` (used by the Flask app's Docker image) is unchanged — `pywin32` is Windows-only and not needed by the app.

## 4. Shared Conventions

Both scripts follow the same conventions, implemented independently in each file (no shared module — each script stays self-contained and copyable to a VM on its own).

### 4.1 Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_URL` | `http://localhost:5000` | Base URL of the SIEM Flask app |
| `SIEM_HOST_LABEL` | `socket.gethostname()` | Value for the event's `host` field |
| `SIEM_POLL_INTERVAL` | `2` | Seconds to sleep between polls |
| `SIEM_STATE_FILE` | `.linux_forwarder_state.json` / `.windows_forwarder_state.json` (next to the script) | Path to the persisted read-position file |
| `SIEM_AUTH_LOG` (Linux only) | `/var/log/auth.log` | Path to the log file to tail |

### 4.2 State file

A small JSON file storing the read position:

- Linux: `{"offset": <byte offset into auth.log>}`
- Windows: `{"last_record_id": <int>}`

If the state file doesn't exist on startup, initialize from the current end of the log / current max EventRecordID — new forwarders don't replay history. If the Linux log file's current size is smaller than the stored `offset` (log rotation/truncation), reset `offset` to `0`.

### 4.3 Sending events

`post_event(event: dict) -> bool`:
- `requests.post(f"{SIEM_URL}/ingest", json=event, timeout=5)`
- Returns `True` on a 2xx response.
- On `requests.exceptions.RequestException` or a non-2xx response: log a warning, return `False`.

### 4.4 Main loop shape

```python
while True:
    for event in get_new_events():   # yields normalized dicts, one at a time, oldest first
        if post_event(event):
            save_state(...)          # persist position advanced past this event
        else:
            break                     # stop this cycle; retry from here on next poll
    time.sleep(POLL_INTERVAL)
```

This gives at-least-once delivery: if `/ingest` is unreachable, the forwarder retries the same unsent event(s) on the next cycle rather than dropping them or advancing past them.

### 4.5 Logging

Stdlib `logging`, INFO level, to stdout. One line per event successfully sent (`event_type` + `host`). Warnings on POST failures. Lines that don't match any known pattern are silently skipped (not logged) — `auth.log` contains many lines forwarders don't care about, and logging all of them would be noise.

## 5. Linux Forwarder (`forwarders/linux_forwarder.py`)

### 5.1 `parse_auth_log_line(line: str) -> dict | None`

Pure function, stdlib `re` + `datetime` only. Matches three patterns:

| Pattern (regex, simplified) | `event_type` | Extracted fields |
|---|---|---|
| `sshd[PID]: Failed password for (invalid user )?(\S+) from (\S+) port (\d+) ssh2` | `auth_failure` | `user` = group 2, `src_ip` = group 3, `details: {"service": "sshd", "port": <int group 4>}` |
| `sshd[PID]: Accepted password for (\S+) from (\S+) port (\d+) ssh2` | `auth_success` | `user` = group 1, `src_ip` = group 2, `details: {"service": "sshd", "port": <int group 3>}` |
| `sudo:\s+(\S+) : .*COMMAND=(.+)$` | `command_execution` | `user` = group 1 (the invoking user, not the `USER=root` target), `command_line` = group 2 |

Any line not matching one of these → return `None` (caller skips it).

**Common fields on all returned events:**
- `host`: `SIEM_HOST_LABEL`
- `timestamp`: parsed from the syslog prefix (`%b %d %H:%M:%S`, e.g. `Jun 15 10:23:45`) with the current year substituted, converted to `.isoformat()`. *Known limitation:* if the forwarder is far behind on entries spanning a year boundary, the substituted year could be wrong — acceptable for a live-tailing demo lab.
- `raw`: the original line, unmodified

### 5.2 Poll loop

1. Open `SIEM_AUTH_LOG`, seek to the stored `offset`.
2. Read complete lines (buffer any trailing partial line until a newline arrives).
3. For each complete line, call `parse_auth_log_line`. If non-`None`, attempt `post_event`.
4. On success, advance and persist `offset` to the byte position after that line. On failure, stop processing this cycle (per §4.4) — the unsent line and anything after it will be re-read next cycle.
5. Sleep `SIEM_POLL_INTERVAL`, repeat.

## 6. Windows Forwarder (`forwarders/windows_forwarder.py`)

### 6.1 `map_sysmon_event(xml_string: str) -> dict | None`

Pure function, stdlib `xml.etree.ElementTree` + `datetime` only — **no pywin32 dependency**, so this function (and therefore this module) imports and runs on any OS.

Parses the rendered Sysmon event XML. Reads `System/EventID`:

| Sysmon `EventID` | `event_type` | Extracted fields |
|---|---|---|
| `1` (Process Create) | `process_creation` | `process_name` = basename of `EventData/Image`, `command_line` = `EventData/CommandLine`, `user` = `EventData/User`, `details: {"parent_process": <basename of EventData/ParentImage>}` |
| `3` (Network Connection) | `network_connection` | `process_name` = basename of `EventData/Image`, `user` = `EventData/User`, `dest_ip` = `EventData/DestinationIp`, `details: {"dest_port": <int EventData/DestinationPort>}` |

Any other `EventID` → return `None`.

**Common fields:**
- `host`: `SIEM_HOST_LABEL`
- `timestamp`: `System/TimeCreated@SystemTime` (already ISO 8601 UTC), parsed via `datetime.fromisoformat` and re-serialized via `.isoformat()`
- `raw`: the full XML string

`process_name` and `parent_process` are reduced to basenames (e.g. `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` → `powershell.exe`) to match the bare-name conditions in `rules/*.yml`.

### 6.2 Poll loop

The only part of this module requiring `pywin32` — imported lazily inside this function so the module itself remains importable (and `map_sysmon_event` testable) without `pywin32` installed.

1. Build an XPath filter `*[System[EventRecordID > N]]` where `N` is the stored `last_record_id`.
2. `win32evtlog.EvtQuery("Microsoft-Windows-Sysmon/Operational", EvtQueryChannelPath, query=<filter>)`, iterate with `EvtNext`.
3. For each event handle, `EvtRender(handle, EvtRenderEventXml)` to get the XML string, pass to `map_sysmon_event`.
4. For each non-`None` result, attempt `post_event`. On success, advance and persist `last_record_id` to that event's `EventRecordID`. On failure, stop this cycle (per §4.4).
5. Sleep `SIEM_POLL_INTERVAL`, repeat.

## 7. Testing (`tests/test_parsers.py`)

Pure unit tests — no live files, no `pywin32`, no Flask app/db fixtures. Runs as part of the normal `pytest` suite on any OS.

**`parse_auth_log_line` cases:**
- Failed SSH password → `auth_failure`; correct `user`, `src_ip`, `details.service == "sshd"`, `details.port`
- Failed SSH password for an `invalid user` → same shape, `user` extracted correctly
- Accepted SSH password → `auth_success`
- `sudo` line running `visudo` → `command_execution`, `command_line` contains `"visudo"`, `user` is the invoking user (not `root`)
- `sudo` line running `useradd ...` → `command_execution`, `command_line` contains `"useradd"`
- An unrelated `auth.log` line (e.g. a cron/PAM session line) → `None`

**`map_sysmon_event` cases** (using realistic sample Sysmon XML fixtures as literal strings in the test file):
- EventID 1: `powershell.exe -enc ...` spawned from `explorer.exe` → `process_creation`, basenamed `process_name`/`details.parent_process`, `command_line` preserved verbatim
- EventID 1: `cmd.exe` spawned from `winword.exe` → `process_creation` (covers RULE-005)
- EventID 1: `schtasks.exe /create ...` → `process_creation` (covers RULE-006)
- EventID 1: `procdump.exe -ma lsass.exe ...` → `process_creation` (covers RULE-007)
- EventID 3: connection to port `4444` → `network_connection`, `details.dest_port == 4444` (as `int`, not string)
- EventID 5 (Process Terminate, unhandled) → `None`

Together these cover the input shapes for all 8 attack-lab detection rules (RULE-001 through RULE-008). The broader end-to-end validation (running real attack scripts against a live SIEM and confirming alerts fire) is out of scope per §2 — that belongs to the Attack Lab cycle.
