# Custom Detection-Focused SIEM

A self-built SIEM core for a SOC Analyst / Detection Engineer portfolio: ingest
normalized security events, evaluate them against custom YAML-defined detection
rules tagged with MITRE ATT&CK techniques, and review alerts/events on a Flask
dashboard with an ATT&CK coverage heatmap.

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

With the app running, POST 13 synthetic events covering all 8 attack lab
scenarios to `/ingest`:

```bash
python scripts/seed_demo_data.py
```

Within one detection cycle (~30 seconds) alerts for all 8 scenarios should
appear on the dashboard at http://localhost:5000.

## Dashboard

- `/` — Alert feed: overview charts (alerts per hour, alerts by severity) plus
  a table of recent alerts
- `/alerts/<id>` — Alert detail: rule metadata, triggering events, and a triage
  status dropdown (New / In Progress / Closed - True Positive / Closed - False Positive)
- `/heatmap` — ATT&CK coverage heatmap: every rule's tactic/technique, marked
  "fired" once it has produced at least one alert
- `/events` — Event explorer: filter raw ingested events by host, event type,
  or free-text search

## Detection coverage

| # | Scenario | Rule ID | ATT&CK Technique | Tactic | Rule Type |
|---|----------|---------|-------------------|--------|-----------|
| 1 | SSH brute force (6 failed logins from one IP within 60s) | RULE-001 | T1110 | Credential Access | Aggregation (5+ in 60s) |
| 2 | Sudo used to run visudo / edit /etc/shadow | RULE-002 | T1548.003 | Privilege Escalation | Single event |
| 3 | New local user account created (useradd) | RULE-003 | T1136.001 | Persistence | Single event |
| 4 | PowerShell executed with -enc (base64-encoded command) | RULE-004 | T1059.001 | Execution | Single event |
| 5 | Word spawns cmd.exe / powershell.exe | RULE-005 | T1059 | Execution | Single event |
| 6 | Scheduled task created via schtasks /create | RULE-006 | T1053.005 | Persistence | Single event |
| 7 | procdump targeting lsass.exe | RULE-007 | T1003.001 | Credential Access | Single event |
| 8 | Outbound connection to known C2 port (4444/4445) | RULE-008 | T1071 | Command and Control | Single event |

## Testing

```bash
pytest
```
