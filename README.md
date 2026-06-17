# Custom Detection-Focused SIEM

A self-built SIEM core for a SOC Analyst / Detection Engineer portfolio: ingest
normalized security events, evaluate them against custom YAML-defined detection
rules tagged with MITRE ATT&CK techniques, and review alerts/events on a Flask
dashboard with an ATT&CK coverage heatmap.

**Key capabilities:**
- **Three detection paths**: single-event rules, aggregation (count threshold over time window), and sequence/correlation rules (multi-step kill-chain detection)
- **Mock IP enrichment**: deterministic geo/ASN annotation on `src_ip` at ingest — country and AS number shown in Event Explorer and alert detail
- **Analyst triage**: per-alert status workflow (New → In Progress → Closed TP/FP) with timestamped analyst notes
- **Alert deduplication**: status-gate prevents re-firing while an open alert for the same rule+host exists; aggregation and sequence rules use cooldown windows
- **139 automated tests** covering unit, integration, end-to-end detection chains, false-positive (true-negative) validation, and Pydantic schema validation for every rule

## Architecture

```
[Attack Lab: Windows VM (Sysmon) + Linux VM] --(attack scripts)-->
        |
        v
[Log Forwarders] --(POST normalized JSON)-->
        |
        v
   [Flask App]
     - /ingest endpoint (forwarders POST events here)
     - Detection Engine (background loop every ~30s, YAML rules, ATT&CK-tagged)
     - Dashboard UI (alert feed, alert detail, ATT&CK heatmap, event explorer, charts)
        |
        v
   [PostgreSQL] (events, alerts, engine_state tables)
```

## Running with Docker Compose

```bash
docker-compose up --build
```

This starts:
- `db` — PostgreSQL 16
- `app` — the Flask app at http://localhost:5000

Database tables are created automatically on first start.

## Running locally without Docker

```bash
pip install -r requirements.txt
python run.py
```

By default this uses a local SQLite database file (`siem.db`). Set the
`DATABASE_URL` environment variable to point at Postgres instead, e.g.:

```bash
export DATABASE_URL=postgresql://siem:siem@localhost:5432/siem
```

## Generating demo data

With the app running, seed synthetic events covering all detection rules:

```bash
python scripts/seed_demo_data.py
```

Within one detection cycle (~30 seconds) alerts for all rules should appear
on the dashboard at http://localhost:5000.

For the sequence rule (RULE-009), seed an `auth_success` followed by a
`useradd` event on the same host within 10 minutes — the detection cycle will
fire a `critical` Persistence alert.

## Using real data instead of synthetic events

Two ways to feed the SIEM genuine (non-synthetic) telemetry:

**This machine's real activity** — `forwarders/host_forwarder.py` uses
[`psutil`](https://pypi.org/project/psutil/) to watch this PC's actual
processes and outbound network connections (no admin rights, no Sysmon
required) and forwards anything new:

```bash
pip install -r forwarders/requirements-windows.txt   # installs psutil (and pywin32 on Windows)
python forwarders/host_forwarder.py
```

Open an app or make a network connection on this machine and watch it show
up in the Event Explorer, with real source/destination IPs (real public IPs
get real geo/ASN lookups via `app/enrichment.py`).

**Replay a real captured dataset** — `scripts/replay_dataset.py` parses a
genuine historical log file with the *same parser functions the live
forwarders use* (`parse_auth_log_line` / `map_sysmon_event`), then posts the
events to `/ingest`. By default it fetches the
[loghub `OpenSSH_2k.log` dataset](https://github.com/logpai/loghub/tree/master/OpenSSH) —
a real, anonymized production sshd log containing genuine brute-force
activity (one source IP alone makes 286 real failed-login attempts):

```bash
python -m scripts.replay_dataset --limit 200
```

Timestamps are rebased to "now" (`--no-rebase` to disable) so the
aggregation/sequence rules actually fire on replay. `--source sysmon`
supports replaying your own real Sysmon EventXML export via `--file`.

## Attack Lab

Nine attack simulation scripts (bash for Linux, PowerShell for Windows) each
target one detection rule and generate real telemetry through the forwarders.
See **[attack-lab/README.md](attack-lab/README.md)** for full setup instructions.

### Forwarder setup (quick reference)

**Linux VM** — tails `/var/log/auth.log` and the sudo audit log:

```bash
export SIEM_URL="http://<siem-ip>:5000"
python forwarders/linux_forwarder.py
```

**Windows VM** — reads Sysmon Event ID 1 (process creation) and Event ID 3
(network connection) from the Windows Event Log. Requires Sysmon installed and
`pywin32`:

```powershell
pip install -r forwarders/requirements-windows.txt
$env:SIEM_URL = "http://<siem-ip>:5000"
python forwarders/windows_forwarder.py
```

After running scenarios on the VMs, validate detection coverage:

```bash
python attack-lab/validate.py --siem http://<siem-ip>:5000
```

This polls `/api/alerts` for each rule and writes results to
[attack-lab/COVERAGE.md](attack-lab/COVERAGE.md).

## Dashboard

- `/` — Alert feed: overview charts (alerts per hour, alerts by severity) plus
  a table of recent alerts
- `/alerts/<id>` — Alert detail: rule metadata, triggering events with mock
  geo/ASN enrichment, triage status dropdown, and timestamped analyst notes
- `/heatmap` — ATT&CK coverage heatmap: every rule's tactic/technique, marked
  "fired" once it has produced at least one alert
- `/events` — Event explorer: filter raw ingested events by host, event type,
  or free-text search; shows mock country · AS for public source IPs

## Screenshots

**Alert feed** — bar chart (alerts/hour) + severity donut + sortable alert table

![Alert feed](docs/img/alert-feed.png)

**ATT&CK Coverage Heatmap** — every rule fired across 5 tactics

![ATT&CK heatmap](docs/img/heatmap.png)

**Event Explorer** — filterable event table with mock geo/ASN enrichment

![Event explorer](docs/img/event-explorer.png)

**Alert detail** — RULE-009 two-step correlation showing both triggering events

![Alert detail](docs/img/alert-detail.png)

## Detection coverage

| # | Scenario | Rule ID | ATT&CK Technique | Tactic | Rule Type |
|---|----------|---------|-------------------|--------|-----------|
| 1 | SSH brute force (5+ failed logins from one IP within 60s) | RULE-001 | T1110 | Credential Access | Aggregation |
| 2 | Sudo used to run visudo / edit /etc/shadow | RULE-002 | T1548.003 | Privilege Escalation | Single event |
| 3 | New local user account created (useradd) | RULE-003 | T1136.001 | Persistence | Single event |
| 4 | PowerShell executed with -enc (base64-encoded command) | RULE-004 | T1059.001 | Execution | Single event |
| 5 | Word spawns cmd.exe / powershell.exe | RULE-005 | T1059 | Execution | Single event |
| 6 | Scheduled task created via schtasks /create | RULE-006 | T1053.005 | Persistence | Single event |
| 7 | procdump targeting lsass.exe | RULE-007 | T1003.001 | Credential Access | Single event |
| 8 | Outbound connection to known C2 port (4444/4445) | RULE-008 | T1071 | Command and Control | Single event |
| 9 | SSH auth success → useradd on same host within 10 min | RULE-009 | T1136.001 | Persistence | Sequence (correlation) |
| 10 | LSASS dump via comsvcs.dll (rundll32 LOLBin, no procdump needed) | RULE-010 | T1003.001 | Credential Access | Single event |
| 11 | Encoded PowerShell, case/long-form evasion of RULE-004 | RULE-011 | T1059.001 | Execution | Single event |
| 12 | certutil -decode used to stage a decoded payload | RULE-012 | T1140 | Defense Evasion | Single event |

RULE-010 and RULE-011 are deliberate alternate-path coverage, not duplicate rules —
see [docs/false-positives.md](docs/false-positives.md) for the evasion each one closes.

## Playbooks and hunting

- **[playbooks/](playbooks/)** — 12 incident-response playbooks, one per rule
  (triage, investigation, containment, escalation, closure criteria).
- **[hunting/](hunting/)** — 5 proactive SQL hunts for activity the 12 rules
  don't cover (LOLBin use outside known flag combos, rare process lineage,
  off-hours privileged commands, beaconing on arbitrary ports, cross-host
  rule fan-out).

## Testing

```bash
pytest
```
