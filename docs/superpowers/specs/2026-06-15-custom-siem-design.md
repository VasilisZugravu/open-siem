# Custom Detection-Focused SIEM — Design Spec

## 1. Goal & Pitch

A self-built SIEM aimed at demonstrating SOC Analyst / Detection Engineer skills for a CV portfolio. The differentiator: rather than configuring an existing SIEM/rule format (e.g., Sigma + ELK), the detection engine, rule format, and correlation logic are built from scratch — while still using the industry-standard **MITRE ATT&CK** framework to tag and visualize detection coverage.

The project tells a complete story: a small **attack simulation lab** generates real attack telemetry on Windows/Linux VMs, which is ingested, normalized, and evaluated against custom detection rules, producing alerts visible on a dashboard with an ATT&CK coverage heatmap.

Target timeline: 1-2 months, built incrementally and demo-able at each stage.

## 2. Architecture

```
[Attack Lab: Windows VM (Sysmon) + Linux VM] --(attack scripts)-->
        |
        v
[Log Forwarders] --(POST normalized JSON)-->
        |
        v
   [Flask App]
     - /ingest endpoint (forwarders POST events here)
     - Normalization (forwarders do most of this; Flask validates/stores)
     - Detection Engine (background loop, custom YAML rules, ATT&CK-tagged)
     - Dashboard UI (alert feed, alert detail, ATT&CK heatmap, event explorer, charts)
        |
        v
   [PostgreSQL] (events, alerts tables)
```

Single Flask service handles ingestion API, detection engine, and dashboard UI. PostgreSQL is the only datastore. The attack lab VMs are separate from the Dockerized SIEM stack.

## 3. Tech Stack

- **Backend + UI**: Python, Flask, Jinja2 templates
- **Storage**: PostgreSQL (SQLAlchemy for models/queries)
- **Charts**: Chart.js (script tag + JSON data, no build step)
- **Orchestration**: Docker Compose (`app` + `db` services)
- **Attack lab**: Separate VMs (Windows w/ Sysmon, Linux), small Python forwarder scripts
- **Testing**: pytest

## 4. Data Model

### `events` table
| Column | Type | Notes |
|---|---|---|
| id | int, PK | |
| timestamp | datetime | when the event occurred |
| host | string | e.g. `win-vm`, `linux-vm` |
| event_type | string | normalized category, e.g. `auth_failure`, `process_creation`, `network_connection`, `logon`, `command_execution` |
| user | string, nullable | |
| src_ip | string, nullable | |
| dest_ip | string, nullable | |
| process_name | string, nullable | |
| command_line | text, nullable | |
| details | JSONB | source-specific extra fields (e.g., parent_process, port, pid) |
| raw | text | original log line / Sysmon XML for reference |

### `alerts` table
| Column | Type | Notes |
|---|---|---|
| id | int, PK | |
| created_at | datetime | |
| rule_id | string | references rule YAML `id` |
| title | string | from rule |
| severity | string | low / medium / high |
| attack_technique | string | e.g. `T1110` |
| attack_tactic | string | e.g. `Credential Access` |
| host | string | |
| status | string | `new` / `in_progress` / `closed_tp` / `closed_fp` |
| triggering_event_ids | JSONB | array of event ids that caused this alert |
| details | JSONB | e.g. `{"src_ip": "1.2.3.4", "count": 7}` for aggregation rules |

## 5. Detection Engine

### Rule format (YAML, one file per rule under `rules/`)

```yaml
id: RULE-001
title: SSH Brute Force
description: Multiple failed SSH logins from the same source IP
severity: medium
attack_technique: T1110
attack_tactic: Credential Access
detection:
  event_type: auth_failure
  conditions:
    service: sshd
  aggregation:
    group_by: src_ip
    threshold: 5
    timeframe_seconds: 60
tags: [linux, authentication]
```

```yaml
id: RULE-004
title: Encoded PowerShell Command
description: PowerShell executed with a base64-encoded (-enc) command
severity: high
attack_technique: T1059.001
attack_tactic: Execution
detection:
  event_type: process_creation
  conditions:
    process_name: powershell.exe
    command_line:
      contains: "-enc"
tags: [windows, execution]
```

**Condition operators** supported on any field: literal value (equality), `contains`, `regex`, `in` (list membership). `aggregation` is optional — its absence means "any single matching event triggers an alert" (implicit threshold of 1).

### Evaluation loop

A single background loop runs every ~30 seconds:

1. For each rule, query `events` newer than the last check time matching `detection.conditions` (and `event_type`).
2. If `aggregation` is absent: each matching event not yet alerted on creates a new `alerts` row, with `triggering_event_ids = [event.id]`.
3. If `aggregation` is present: group matching events (within the last `timeframe_seconds`) by `group_by`. For any group with count >= `threshold`, create an `alerts` row (with a cooldown — e.g., don't re-fire for the same group within 5 minutes) with `triggering_event_ids` = the matched event ids and `details = {group_by_field: value, "count": N}`.

This is implemented as plain SQL queries (`GROUP BY` / `HAVING COUNT(*) >=`) against the `events` table — no separate stream-processing framework.

## 6. Log Forwarders

One small Python script per VM. Each reads new log entries and POSTs normalized JSON to `/ingest`:

- **Linux forwarder**: tails `/var/log/auth.log`, regex-parses lines (failed/accepted SSH logins, sudo usage, useradd) into the normalized schema.
- **Windows forwarder**: reads new Sysmon events via the Windows Event Log API, maps a handful of Event IDs (1 = process creation, 3 = network connection) to `event_type`, extracts relevant fields (process_name, command_line, parent_process, dest_ip/port).

Both forwarders produce the same shape of JSON; `/ingest` validates and inserts into `events`.

## 7. Attack Lab Scenarios

8 independent scenarios, each a small script (bash for Linux, PowerShell for Windows) plus a corresponding rule file. Built and validated one at a time.

| # | Scenario | VM | ATT&CK Technique | Rule Type |
|---|----------|-----|-------------------|-----------|
| 1 | SSH brute force (repeated failed logins from one IP) | Linux | T1110 – Brute Force | Aggregation (5+ in 60s) |
| 2 | Sudo used to edit `/etc/shadow` or run `visudo` | Linux | T1548.003 – Sudo Caching | Single event |
| 3 | New local user created (`useradd`) | Linux | T1136.001 – Create Account | Single event |
| 4 | PowerShell run with `-enc` (encoded command) | Windows | T1059.001 / T1027 | Single event |
| 5 | Word/Excel spawns `cmd.exe` or `powershell.exe` | Windows | T1566 + T1059 | Single event (parent/child match) |
| 6 | Scheduled task created (`schtasks /create`) | Windows | T1053.005 – Scheduled Task | Single event |
| 7 | `procdump` targeting `lsass.exe` | Windows | T1003.001 – LSASS Memory | Single event |
| 8 | Outbound connection to a known C2 port (e.g., 4444) | Windows | T1071 – Application Layer Protocol (C2) | Single event |

This spread covers Credential Access, Privilege Escalation, Persistence, Execution, Initial Access, and Command & Control — giving the ATT&CK heatmap a meaningful spread across tactics.

## 8. Dashboard Views

Four Flask routes + Jinja2 templates, each backed by simple SQL queries:

1. **Alert Feed (home)** — overview charts at top (alerts per hour over last 24h; alerts by severity, via Chart.js), then a table of recent alerts (time, severity, title, ATT&CK technique, host, status). Auto-refreshes every ~30s via simple JS polling.
2. **Alert Detail** — rule that fired (title, severity, ATT&CK tactic/technique, description), the triggering event(s) (raw + normalized fields), and a status dropdown (`New` / `In Progress` / `Closed - True Positive` / `Closed - False Positive`).
3. **ATT&CK Coverage Heatmap** — grid of tactics × techniques. Gray = no rule covers this technique; Green = rule exists, hasn't fired; Red = rule exists and has fired.
4. **Event Explorer** — filterable table of raw events (by host, event_type, time range, free-text search on `raw`/`command_line`).

## 9. Testing & Validation

- **Rule engine unit tests** (pytest): given a rule definition + synthetic events, verify alerts are/aren't produced. Covers all condition operators and both aggregation and single-event rules.
- **Parser/forwarder tests**: given sample raw log lines (Sysmon XML, auth.log lines), verify correct normalized field extraction.
- **End-to-end validation**: run each of the 8 attack lab scenarios against a live instance, confirm the expected alert appears. Recorded as a coverage table (scenario → expected alert → ✅/❌) — this table doubles as interview material.

## 10. Deployment & Demo Packaging

- **SIEM stack**: `docker-compose.yml` with `app` (Flask) and `db` (Postgres) services. `docker-compose up` brings up the full stack; tables are created on first start.
- **Attack lab**: separate from Docker — 2 VMs (Windows with Sysmon installed, Linux), each running a forwarder script pointed at the SIEM's `/ingest` endpoint (host/IP configurable). Attack scripts live under `attack-lab/`, one folder per scenario, with run instructions.
- **README**: architecture diagram, setup steps for both the SIEM stack and the lab VMs, dashboard/heatmap screenshots, and the scenario → detection coverage table.
- **Demo flow**: run an attack script on a VM → alert appears on the dashboard within ~30s → visible on the ATT&CK heatmap → walk through which rule fired and why.

## 11. Suggested Project Structure

```
siem/
├── app/
│   ├── __init__.py
│   ├── models.py            # SQLAlchemy models: Event, Alert
│   ├── ingest.py             # /ingest route
│   ├── detection/
│   │   ├── engine.py          # background evaluation loop
│   │   ├── rules_loader.py    # loads/validates YAML rules
│   │   └── operators.py       # equals/contains/regex/in matching
│   ├── dashboard/
│   │   ├── routes.py           # alert feed, alert detail, heatmap, event explorer
│   │   └── templates/
│   └── attack_reference/
│       └── attack_data.json    # ATT&CK technique/tactic reference data for heatmap
├── rules/
│   ├── linux_ssh_bruteforce.yml
│   ├── linux_sudo_shadow_edit.yml
│   ├── linux_useradd.yml
│   ├── windows_encoded_powershell.yml
│   ├── windows_office_spawns_shell.yml
│   ├── windows_scheduled_task.yml
│   ├── windows_lsass_dump.yml
│   └── windows_c2_port.yml
├── forwarders/
│   ├── linux_forwarder.py
│   └── windows_forwarder.py
├── attack-lab/
│   ├── 01-ssh-bruteforce/
│   ├── 02-sudo-shadow-edit/
│   ├── ... (one per scenario)
├── tests/
│   ├── test_rule_engine.py
│   └── test_parsers.py
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## 12. Out of Scope / Future Enhancements

- Correlation engine grouping alerts into multi-stage "incidents" (deferred — core engine ships with standalone alerts first)
- Additional log sources (cloud audit logs, web server logs)
- Additional charts (alerts by ATT&CK tactic, top source IPs/users)
- In-dashboard rule management (enable/disable rules without editing files)
- Dashboard authentication (not needed for local/demo use)
