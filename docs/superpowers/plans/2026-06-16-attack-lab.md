# Attack Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build 8 attack simulation scripts, a `/api/alerts` JSON endpoint, and a `validate.py` polling helper that confirms each script triggers its expected SIEM detection rule.

**Architecture:** A new `GET /api/alerts` route is added to the existing Flask dashboard Blueprint, filterable by `rule_id` and `since` timestamp. Eight standalone scripts (3 bash, 5 PowerShell) live under `attack-lab/NN-<name>/` and run directly on the target VMs. `validate.py` (stdlib-only) prompts the user to run each script, then polls `/api/alerts` and writes results to `attack-lab/COVERAGE.md`.

**Tech Stack:** Python/Flask/SQLAlchemy (existing), bash, PowerShell, `urllib`/`argparse`/`json` (stdlib only for validate.py), pytest.

---

## Context for the implementer

This is a custom SIEM project. The Flask app lives at `app/`, tests at `tests/`, detection rules at `rules/`. The `Alert` model (in `app/models.py`) has columns: `id`, `created_at`, `rule_id`, `title`, `severity`, `attack_technique`, `attack_tactic`, `host`, `status`, `triggering_event_ids`, `details`. The dashboard Blueprint is registered in `app/__init__.py` and its routes are in `app/dashboard/routes.py`. Tests use an in-memory SQLite DB via the `client` fixture from `tests/conftest.py`. Run tests with `./venv/Scripts/python.exe -m pytest -q` from the repo root. All 57 existing tests must continue to pass.

The existing `app/dashboard/routes.py` imports:
```python
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for
from app.db import db
from app.models import Alert, Event
from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules
```

---

## Task 1: `/api/alerts` JSON endpoint (TDD)

**Files:**
- Create: `tests/test_api_alerts.py`
- Modify: `app/dashboard/routes.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_alerts.py`:

```python
import json
from datetime import datetime
from app.db import db
from app.models import Alert


def _make_alert(**kwargs):
    defaults = dict(
        created_at=datetime(2026, 6, 16, 10, 0, 0),
        rule_id="RULE-001",
        title="SSH Brute Force",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="linux-vm",
        status="new",
        triggering_event_ids=[],
        details={},
    )
    defaults.update(kwargs)
    a = Alert(**defaults)
    db.session.add(a)
    db.session.commit()
    return a


def test_api_alerts_returns_all(client):
    _make_alert()
    _make_alert(rule_id="RULE-004", title="Encoded PowerShell")
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 2


def test_api_alerts_filters_by_rule_id(client):
    _make_alert(rule_id="RULE-001")
    _make_alert(rule_id="RULE-004", title="Encoded PowerShell")
    response = client.get("/api/alerts?rule_id=RULE-001")
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["rule_id"] == "RULE-001"


def test_api_alerts_filters_by_since(client):
    _make_alert(created_at=datetime(2026, 6, 16, 9, 0, 0))
    _make_alert(created_at=datetime(2026, 6, 16, 11, 0, 0))
    response = client.get("/api/alerts?since=2026-06-16T10:00:00")
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["created_at"] == "2026-06-16T11:00:00"


def test_api_alerts_returns_correct_fields(client):
    _make_alert()
    response = client.get("/api/alerts")
    data = json.loads(response.data)
    assert set(data[0].keys()) == {"id", "rule_id", "title", "severity", "created_at", "host"}
```

- [ ] **Step 2: Run tests to verify they fail**

```
./venv/Scripts/python.exe -m pytest tests/test_api_alerts.py -v
```

Expected: 4 failures — `404 NOT FOUND` (route doesn't exist yet).

- [ ] **Step 3: Add `jsonify` to the import and implement the route**

In `app/dashboard/routes.py`, change the Flask import line (line 3) from:
```python
from flask import Blueprint, render_template, request, redirect, url_for
```
to:
```python
from flask import Blueprint, render_template, request, redirect, url_for, jsonify
```

Then append this route at the end of `app/dashboard/routes.py`:

```python
@dashboard_bp.route("/api/alerts")
def api_alerts():
    rule_id = request.args.get("rule_id")
    since = request.args.get("since")

    query = Alert.query
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    if since:
        since_dt = datetime.fromisoformat(since)
        query = query.filter(Alert.created_at >= since_dt)

    alerts = query.order_by(Alert.created_at.desc()).all()
    return jsonify([
        {
            "id": a.id,
            "rule_id": a.rule_id,
            "title": a.title,
            "severity": a.severity,
            "created_at": a.created_at.isoformat(),
            "host": a.host,
        }
        for a in alerts
    ])
```

- [ ] **Step 4: Run tests to verify they pass**

```
./venv/Scripts/python.exe -m pytest tests/test_api_alerts.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Run full suite to confirm no regressions**

```
./venv/Scripts/python.exe -m pytest -q
```

Expected: 61 passed.

- [ ] **Step 6: Commit**

```bash
git add tests/test_api_alerts.py app/dashboard/routes.py
git commit -m "feat: add GET /api/alerts JSON endpoint with rule_id and since filters"
```

---

## Task 2: Linux attack scripts (scenarios 01–03)

**Files:**
- Create: `attack-lab/01-ssh-bruteforce/run.sh`
- Create: `attack-lab/02-sudo-shadow-edit/run.sh`
- Create: `attack-lab/03-useradd/run.sh`

These are bash scripts that run on the Linux VM. There are no unit tests — the scripts are validated with `bash -n` (syntax check) and reviewed manually.

- [ ] **Step 1: Create `attack-lab/01-ssh-bruteforce/run.sh`**

```bash
#!/usr/bin/env bash
# Scenario 01 — SSH Brute Force
# Triggers RULE-001: 5+ auth_failure events from the same src_ip within 60s
# Run on: Linux VM, with linux_forwarder.py running

set -euo pipefail

echo "[01] Sending 6 failed SSH login attempts to localhost..."
for i in $(seq 1 6); do
    ssh \
        -o BatchMode=yes \
        -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no \
        nonexistent@localhost 2>/dev/null || true
    sleep 1
done
echo "[01] Done."
```

- [ ] **Step 2: Create `attack-lab/02-sudo-shadow-edit/run.sh`**

```bash
#!/usr/bin/env bash
# Scenario 02 — Sudo Shadow File Access
# Triggers RULE-002: sudo command_line matching (shadow|visudo)
# Run on: Linux VM with sudo access, with linux_forwarder.py running

set -euo pipefail

echo "[02] Running sudo grep against /etc/shadow..."
sudo grep root /etc/shadow > /dev/null
echo "[02] Done."
```

- [ ] **Step 3: Create `attack-lab/03-useradd/run.sh`**

```bash
#!/usr/bin/env bash
# Scenario 03 — New Local User Created
# Triggers RULE-003: sudo command_line containing "useradd"
# Run on: Linux VM with sudo access, with linux_forwarder.py running

set -euo pipefail

echo "[03] Creating and immediately deleting test user..."
sudo useradd attack-lab-user 2>/dev/null || true
sudo userdel -r attack-lab-user 2>/dev/null || sudo userdel attack-lab-user 2>/dev/null || true
echo "[03] Done."
```

- [ ] **Step 4: Syntax-check all three scripts**

```bash
bash -n attack-lab/01-ssh-bruteforce/run.sh
bash -n attack-lab/02-sudo-shadow-edit/run.sh
bash -n attack-lab/03-useradd/run.sh
```

Expected: no output (syntax valid).

- [ ] **Step 5: Make scripts executable and commit**

```bash
chmod +x attack-lab/01-ssh-bruteforce/run.sh \
         attack-lab/02-sudo-shadow-edit/run.sh \
         attack-lab/03-useradd/run.sh
git add attack-lab/
git commit -m "feat: add Linux attack scripts for scenarios 01-03"
```

---

## Task 3: Windows attack scripts (scenarios 04–08)

**Files:**
- Create: `attack-lab/04-encoded-powershell/run.ps1`
- Create: `attack-lab/05-office-spawns-shell/run.ps1`
- Create: `attack-lab/06-scheduled-task/run.ps1`
- Create: `attack-lab/07-procdump-lsass/run.ps1`
- Create: `attack-lab/08-c2-port/run.ps1`

These are PowerShell scripts for the Windows VM. No unit tests — each requires Sysmon + `windows_forwarder.py` running. Script 07 additionally requires `procdump.exe` (Sysinternals) in the same folder and must run as Administrator.

- [ ] **Step 1: Create `attack-lab/04-encoded-powershell/run.ps1`**

```powershell
# Scenario 04 — Encoded PowerShell Command
# Triggers RULE-004: process_creation, process_name=powershell.exe, command_line contains "-enc"
# Run on: Windows VM with Sysmon + windows_forwarder.py running

$cmd = "Write-Output 'attack-lab'"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Write-Host "[04] Running: powershell.exe -enc <base64>..."
powershell.exe -enc $enc
Write-Host "[04] Done."
```

- [ ] **Step 2: Create `attack-lab/05-office-spawns-shell/run.ps1`**

```powershell
# Scenario 05 — Office Application Spawns Shell (simulated)
# Triggers RULE-005: process_creation, process_name=cmd.exe, parent_process=winword.exe
# Simulation: copies cmd.exe to $TEMP\winword.exe, spawns cmd.exe from it.
# Sysmon Event ID 1 captures cmd.exe with ParentImage ending in winword.exe.
# Run on: Windows VM with Sysmon + windows_forwarder.py running

$fake = "$env:TEMP\winword.exe"
Write-Host "[05] Copying cmd.exe to $fake..."
Copy-Item "$env:SystemRoot\System32\cmd.exe" $fake -Force
Write-Host "[05] Spawning cmd.exe from simulated winword.exe..."
& $fake /c "echo attack-lab"
Write-Host "[05] Cleaning up..."
Remove-Item $fake -Force
Write-Host "[05] Done."
```

- [ ] **Step 3: Create `attack-lab/06-scheduled-task/run.ps1`**

```powershell
# Scenario 06 — Scheduled Task Created
# Triggers RULE-006: process_creation, process_name=schtasks.exe, command_line contains "/create"
# Run on: Windows VM with Sysmon + windows_forwarder.py running

Write-Host "[06] Creating scheduled task AttackLabTask..."
schtasks /create /tn "AttackLabTask" /tr "cmd.exe" /sc once /st 00:00 /f | Out-Null
Write-Host "[06] Deleting scheduled task..."
schtasks /delete /tn "AttackLabTask" /f | Out-Null
Write-Host "[06] Done."
```

- [ ] **Step 4: Create `attack-lab/07-procdump-lsass/run.ps1`**

```powershell
# Scenario 07 — LSASS Memory Dump via procdump
# Triggers RULE-007: process_creation, command_line contains "lsass"
# REQUIRES: procdump.exe in the same folder as this script, run as Administrator.
# Download procdump.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
# Run on: Windows VM with Sysmon + windows_forwarder.py running, as Administrator

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$procdump = Join-Path $here "procdump.exe"

if (-not (Test-Path $procdump)) {
    Write-Error "procdump.exe not found at $procdump. Download it from Sysinternals."
    exit 1
}

Write-Host "[07] Running procdump against lsass.exe..."
& $procdump -accepteula -ma lsass.exe lsass.dmp | Out-Null
Write-Host "[07] Removing dump file..."
Remove-Item lsass.dmp -Force -ErrorAction SilentlyContinue
Write-Host "[07] Done."
```

- [ ] **Step 5: Create `attack-lab/08-c2-port/run.ps1`**

```powershell
# Scenario 08 — Outbound Connection to C2 Port
# Triggers RULE-008: network_connection, dest_port in [4444, 4445]
# The connection attempt is refused (nothing listening) but Sysmon Event ID 3 still fires.
# Run on: Windows VM with Sysmon + windows_forwarder.py running

Write-Host "[08] Attempting TCP connection to 127.0.0.1:4444..."
$tcp = New-Object System.Net.Sockets.TcpClient
try { $tcp.Connect("127.0.0.1", 4444) } catch {}
$tcp.Close()
Write-Host "[08] Done."
```

- [ ] **Step 6: Commit**

```bash
git add attack-lab/
git commit -m "feat: add Windows attack scripts for scenarios 04-08"
```

---

## Task 4: `validate.py` + initial `COVERAGE.md` (TDD)

**Files:**
- Create: `tests/test_validate.py`
- Create: `attack-lab/validate.py`
- Create: `attack-lab/COVERAGE.md`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_validate.py`:

```python
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

# attack-lab/ has a hyphen so it can't be imported normally — use importlib
_spec = importlib.util.spec_from_file_location(
    "validate",
    Path(__file__).parent.parent / "attack-lab" / "validate.py",
)
_validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validate)

_write_coverage_md = _validate._write_coverage_md
_poll_alert = _validate._poll_alert
SCENARIOS = _validate.SCENARIOS


def test_write_coverage_md_all_passing(tmp_path):
    results = [(s, "✅") for s in SCENARIOS]
    out = str(tmp_path / "COVERAGE.md")
    _write_coverage_md(results, out)
    content = Path(out).read_text(encoding="utf-8")
    assert "✅" in content
    assert "RULE-001" in content
    assert "RULE-008" in content
    assert content.count("| 0") == 8  # 8 scenario rows


def test_write_coverage_md_pending(tmp_path):
    results = [(s, "⏳") for s in SCENARIOS]
    out = str(tmp_path / "COVERAGE.md")
    _write_coverage_md(results, out)
    content = Path(out).read_text(encoding="utf-8")
    assert "⏳" in content
    assert "✅" not in content
    assert "❌" not in content


def test_poll_alert_found():
    alert = {
        "id": 1, "rule_id": "RULE-001", "title": "SSH Brute Force",
        "severity": "medium", "created_at": "2026-06-16T10:00:00", "host": "linux-vm",
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps([alert]).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = _poll_alert("http://localhost:5000", "RULE-001", "2026-06-16T09:00:00", timeout=10)

    assert result == alert


def test_poll_alert_timeout():
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps([]).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch("time.sleep"):
            result = _poll_alert("http://localhost:5000", "RULE-001", "2026-06-16T09:00:00", timeout=0)

    assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

```
./venv/Scripts/python.exe -m pytest tests/test_validate.py -v
```

Expected: 4 failures — `attack-lab/validate.py` does not exist yet.

- [ ] **Step 3: Create `attack-lab/validate.py`**

```python
#!/usr/bin/env python3
"""Attack lab validation helper — polls /api/alerts after each scenario."""

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCENARIOS = [
    {"num": "01", "name": "SSH Brute Force",    "folder": "01-ssh-bruteforce",     "ext": "sh",  "vm": "Linux",   "rule": "RULE-001", "technique": "T1110"},
    {"num": "02", "name": "Sudo Shadow Edit",   "folder": "02-sudo-shadow-edit",   "ext": "sh",  "vm": "Linux",   "rule": "RULE-002", "technique": "T1548.003"},
    {"num": "03", "name": "New Local User",     "folder": "03-useradd",            "ext": "sh",  "vm": "Linux",   "rule": "RULE-003", "technique": "T1136.001"},
    {"num": "04", "name": "Encoded PowerShell", "folder": "04-encoded-powershell", "ext": "ps1", "vm": "Windows", "rule": "RULE-004", "technique": "T1059.001"},
    {"num": "05", "name": "Office Spawns Shell","folder": "05-office-spawns-shell","ext": "ps1", "vm": "Windows", "rule": "RULE-005", "technique": "T1059"},
    {"num": "06", "name": "Scheduled Task",     "folder": "06-scheduled-task",     "ext": "ps1", "vm": "Windows", "rule": "RULE-006", "technique": "T1053.005"},
    {"num": "07", "name": "LSASS Memory Dump",  "folder": "07-procdump-lsass",     "ext": "ps1", "vm": "Windows", "rule": "RULE-007", "technique": "T1003.001"},
    {"num": "08", "name": "C2 Port Connection", "folder": "08-c2-port",            "ext": "ps1", "vm": "Windows", "rule": "RULE-008", "technique": "T1071"},
]

POLL_INTERVAL = 5
TIMEOUT = 60


def _poll_alert(siem_url, rule_id, since_iso, timeout=TIMEOUT):
    """Poll /api/alerts until an alert is found or timeout expires. Returns alert dict or None."""
    params = urllib.parse.urlencode({"rule_id": rule_id, "since": since_iso})
    url = f"{siem_url}/api/alerts?{params}"
    deadline = time.time() + timeout
    while True:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                alerts = json.loads(resp.read())
                if alerts:
                    return alerts[0]
        except (urllib.error.URLError, OSError):
            pass
        if time.time() >= deadline:
            return None
        time.sleep(POLL_INTERVAL)


def _write_coverage_md(results, path):
    """Write COVERAGE.md. results: list of (scenario_dict, result_str) for all 8 scenarios."""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    lines = [
        "# Attack Lab Coverage",
        "",
        f"Last validated: {ts}",
        "",
        "| # | Scenario | VM | ATT&CK | Rule | Result |",
        "|---|----------|-----|--------|------|--------|",
    ]
    for s, result in results:
        lines.append(
            f"| {s['num']} | {s['name']} | {s['vm']} | {s['technique']} | {s['rule']} | {result} |"
        )
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _run_scenario(siem_url, scenario):
    """Prompt user to run script on VM, poll for alert. Returns '✅' or '❌'."""
    script = f"attack-lab/{scenario['folder']}/run.{scenario['ext']}"
    print(f"\n▶  Scenario {scenario['num']} — {scenario['name']} ({scenario['technique']})")
    print(f"   VM: {scenario['vm']}   Script: {script}")
    since_iso = datetime.datetime.utcnow().isoformat()
    input("   Press Enter when the script has been run on the VM...")
    print(f"   Polling {scenario['rule']}...", end="", flush=True)
    alert = _poll_alert(siem_url, scenario["rule"], since_iso)
    if alert:
        print(f" ✅  (alert id={alert['id']})")
        return "✅"
    print(f" ❌  (no alert within {TIMEOUT}s)")
    return "❌"


def main():
    parser = argparse.ArgumentParser(description="Validate attack lab scenarios against the SIEM.")
    parser.add_argument("--siem", default="http://localhost:5000", help="SIEM base URL")
    parser.add_argument("--scenario", metavar="NUM", help="Run only this scenario number, e.g. 01")
    args = parser.parse_args()

    to_run = SCENARIOS
    if args.scenario:
        to_run = [s for s in SCENARIOS if s["num"] == args.scenario]
        if not to_run:
            print(f"Unknown scenario: {args.scenario}", file=sys.stderr)
            sys.exit(1)

    results = {s["num"]: (s, "⏳") for s in SCENARIOS}
    for s in to_run:
        results[s["num"]] = (s, _run_scenario(args.siem, s))

    coverage_path = "attack-lab/COVERAGE.md"
    _write_coverage_md([results[n] for n in sorted(results)], coverage_path)
    print(f"\nCoverage table written to {coverage_path}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

```
./venv/Scripts/python.exe -m pytest tests/test_validate.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Run full suite to confirm no regressions**

```
./venv/Scripts/python.exe -m pytest -q
```

Expected: 65 passed.

- [ ] **Step 6: Create initial `attack-lab/COVERAGE.md`**

```markdown
# Attack Lab Coverage

Last validated: (not yet run)

| # | Scenario | VM | ATT&CK | Rule | Result |
|---|----------|-----|--------|------|--------|
| 01 | SSH Brute Force | Linux | T1110 | RULE-001 | ⏳ |
| 02 | Sudo Shadow Edit | Linux | T1548.003 | RULE-002 | ⏳ |
| 03 | New Local User | Linux | T1136.001 | RULE-003 | ⏳ |
| 04 | Encoded PowerShell | Windows | T1059.001 | RULE-004 | ⏳ |
| 05 | Office Spawns Shell | Windows | T1059 | RULE-005 | ⏳ |
| 06 | Scheduled Task | Windows | T1053.005 | RULE-006 | ⏳ |
| 07 | LSASS Memory Dump | Windows | T1003.001 | RULE-007 | ⏳ |
| 08 | C2 Port Connection | Windows | T1071 | RULE-008 | ⏳ |
```

- [ ] **Step 7: Commit**

```bash
git add tests/test_validate.py attack-lab/validate.py attack-lab/COVERAGE.md
git commit -m "feat: add validate.py polling helper and initial COVERAGE.md"
```

---

## Self-Review Notes

- **RULE-005 simulation correctness:** `run.ps1` copies `cmd.exe` to `$TEMP\winword.exe` and spawns `cmd.exe` from it. Sysmon Event ID 1 captures `cmd.exe` with `ParentImage` ending in `winword.exe`. The windows forwarder's `_basename(ParentImage).lower()` returns `"winword.exe"`, matching RULE-005's `parent_process in ["winword.exe", "excel.exe"]`. ✅
- **RULE-008 simulation:** The TCP connect attempt to port 4444 is refused (nothing listening), but Sysmon Event ID 3 fires on the connection attempt itself. The `dest_port` field is typed as `int` in `map_sysmon_event()`, matching RULE-008's `dest_port in [4444, 4445]`. ✅
- **`_poll_alert` timeout=0 test:** With `timeout=0`, `deadline = time.time() + 0`. The function polls once (returns empty array), then checks `time.time() >= deadline` — True immediately — and returns None. ✅
- **`since_iso` is captured before the user prompt** in `_run_scenario`, so alerts generated while the user was running the script on the VM are not missed. ✅
