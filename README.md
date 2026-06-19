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

## Quick start (local dev — zero config)

```bash
git clone <this-repo>
cd <this-repo>
python -m venv venv
venv\Scripts\activate        # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open http://localhost:5000 and log in with **`admin` / `demo`**.

That's it. `run.py` sets dev-safe secret defaults and auto-seeds the admin
account on every start — no environment variables needed for local dev.

---

## Running with Docker Compose

```bash
cp .env.example .env   # fill in SECRET_KEY, INGEST_API_KEY, ADMIN_PASSWORD, POSTGRES_PASSWORD
docker-compose up --build
```

This starts:
- `db` — PostgreSQL 16
- `app` — the Flask app at http://localhost:5000

Database tables are created automatically on first start. `.env` is
gitignored — generate secret values with
`python -c "import secrets; print(secrets.token_hex(32))"`.

Log in with `admin` and the **`ADMIN_PASSWORD`** you set in `.env` (not the default `demo` — that only applies to `python run.py`).

## Running locally without Docker (full options)

1. **Create and activate a virtualenv:**

   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **(Production only) run behind a reverse proxy** — the app uses
   `ProxyFix` to key rate limits (login throttle, `/ingest`) on the real
   client IP from `X-Forwarded-For`. If the app is exposed directly to a
   public interface without a trusted proxy (Nginx, the compose service, a
   load balancer) in front of it, clients can spoof that header and bypass
   per-IP rate limiting. Always place a reverse proxy between the app and
   untrusted networks in production.

3. **(Production only) set secrets** — `run.py` provides dev-safe defaults
   when run directly, so this step is only needed for production or gunicorn:

   ```bash
   export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   export INGEST_API_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   ```

   Windows PowerShell: `$env:SECRET_KEY = $(python -c "import secrets; print(secrets.token_hex(32))")`

   To open `/ingest` with no auth (isolated lab box only), set
   `ALLOW_UNAUTHENTICATED_INGEST=1` instead. The bundled forwarders and
   scripts read `SIEM_API_KEY` first, then fall back to `INGEST_API_KEY`.

4. **(Optional) point at Postgres instead of SQLite:**

   ```bash
   export DATABASE_URL=postgresql://siem:siem@localhost:5432/siem
   ```

5. **Start the app:**

   ```bash
   python run.py
   ```

   Tables are created on first start. The admin account (`admin` / `demo`) is
   seeded automatically — set `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars to
   override.

6. **Open** http://localhost:5000 and log in with `admin` / `demo`.

   See [Generating demo data](#generating-demo-data) to populate the dashboard.

## Dashboard login

The dashboard is gated behind a login page (Flask-Login) — there is no
public signup. The single admin account is stored in the database with a
hashed password.

**Local dev:** `python run.py` automatically seeds `admin` / `demo` on every
start, so no setup is needed. Set `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars
to override the defaults.

**docker-compose / production:** the `create-admin` CLI command is used instead
(run automatically by docker-compose on container start via `ADMIN_PASSWORD`
from `.env`):

```bash
flask --app run create-admin --username admin
```

Omit `--password` to be prompted interactively.

## Generating demo data

The quickest way is the **Synthetic Traffic** feed on the dashboard (no CLI
needed) — click **Start** next to it and alerts will appear within ~30 seconds.

To seed via CLI instead:

```bash
python scripts/seed_demo_data.py
```

For the sequence rule (RULE-009), seed an `auth_success` followed by a
`useradd` event on the same host within 10 minutes — the detection cycle will
fire a `critical` Persistence alert.

## Using real data instead of synthetic events

Two ways to feed the SIEM genuine (non-synthetic) telemetry:

**This machine's real activity** — `forwarders/host_forwarder.py` uses
[`psutil`](https://pypi.org/project/psutil/) to watch this PC's actual
processes and network connections, **both outbound (this PC connecting out)
and inbound (a peer connecting in to one of our listening ports)** — no admin
rights, no Sysmon required — and forwards anything new. Pure loopback traffic
(127.0.0.1/::1) is skipped as noise; known C2 ports (4444/4445) are always
captured. Each connection's remote IP is reverse-DNS resolved (cached) so you
see e.g. `chrome.exe → *.googlevideo.com:443` instead of just an IP, and
RULE-013 fires when an external host connects in:

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
supports replaying your own real Sysmon EventXML export via `--file`. Pass
`--loop` to replay the dataset on repeat forever instead of exiting once
exhausted.

## Controlling telemetry feeds from the dashboard

The three feeds above (Machine Monitor, Real Incident Logs, Synthetic
Traffic) can each be started/stopped independently from a control panel on
the main dashboard (http://localhost:5000/) — no command line needed. None
of them run by default; the SIEM starts as a clean slate and you opt into
whichever feed(s) you want, e.g. just Machine Monitor to watch this PC, or
add Real Incident Logs/Synthetic Traffic on top to also exercise the rest of
the rule set.

**Running under Docker:** the Machine Monitor button becomes **"Download
run-monitor.bat"**. Docker containers run in a Linux VM and cannot access
the Windows process table, so the forwarder must run on the host instead.
Click the button, save `run-monitor.bat` to the repo root, and double-click
it — it reads your `.env` automatically and posts events to the container's
published port.

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

- `/` — Alert feed: stat cards (total alerts / last 24h / critical / active
  feeds), a **Telemetry Feeds** control panel (start/stop each feed, LIVE/PAUSE
  toggle), and charts (alerts per hour, severity breakdown) plus a sortable
  alert table
- `/alerts/<id>` — Alert detail: rule metadata, triggering events with mock
  geo/ASN enrichment, triage status dropdown, and timestamped analyst notes
- `/heatmap` — ATT&CK coverage heatmap: every rule's tactic/technique, marked
  "fired" once it has produced at least one alert
- `/events` — Event Explorer: filter raw ingested events by host, event type,
  or free-text search; shows direction and mock country · AS for public source IPs

## Screenshots

**Dashboard** — stat cards + Telemetry Feeds control panel (LIVE/PAUSE, per-feed Start/Stop)

![Dashboard](docs/img/dashboard.png)

**Alert feed** — severity-badged alert table with ATT&CK technique, host, and status per row

![Alert feed](docs/img/alert-feed.png)

**ATT&CK Coverage Heatmap** — every rule mapped to MITRE tactic/technique, FIRED once triggered

![ATT&CK heatmap](docs/img/heatmap.png)

**Event Explorer** — filterable raw-event table with direction and mock geo/ASN enrichment

![Event explorer](docs/img/event-explorer.png)

**Alert detail** — rule metadata, triggering events, triage status dropdown, and analyst notes

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
| 13 | Inbound connection from an external host to a listening port | RULE-013 | T1133 | Initial Access | Single event |

RULE-010 and RULE-011 are deliberate alternate-path coverage, not duplicate rules —
see [docs/false-positives.md](docs/false-positives.md) for the evasion each one closes.

## Playbooks and hunting

- **[playbooks/](playbooks/)** — 13 incident-response playbooks, one per rule
  (triage, investigation, containment, escalation, closure criteria).
- **[hunting/](hunting/)** — 5 proactive SQL hunts for activity the 13 rules
  don't cover (LOLBin use outside known flag combos, rare process lineage,
  off-hours privileged commands, beaconing on arbitrary ports, cross-host
  rule fan-out).

## Testing

```bash
pytest
```
