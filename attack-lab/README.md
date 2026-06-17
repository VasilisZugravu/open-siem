
# Attack Lab

Twelve attack simulation scenarios — one per detection rule — that generate real
telemetry on Linux and Windows VMs to prove end-to-end detection coverage.
Each script is self-contained and self-cleaning (removes test users, dump files,
scheduled tasks).

Scenarios 10-11 are deliberate evasion pairs against scenarios 07 and 04: same
adversary goal, an alternate command line that the original rule's substring/
exact-case match misses, caught instead by the hardened rule (RULE-010/011).

After running scenarios, `validate.py` polls the SIEM and writes results to
[COVERAGE.md](COVERAGE.md).

---

## Scenarios

| # | Scenario | VM | Script | Rule | ATT&CK |
|---|----------|----|--------|------|--------|
| 01 | SSH Brute Force | Linux | `01-ssh-bruteforce/run.sh` | RULE-001 | T1110 |
| 02 | Sudo Shadow Edit | Linux | `02-sudo-shadow-edit/run.sh` | RULE-002 | T1548.003 |
| 03 | New Local User | Linux | `03-useradd/run.sh` | RULE-003 | T1136.001 |
| 04 | Encoded PowerShell | Windows | `04-encoded-powershell/run.ps1` | RULE-004 | T1059.001 |
| 05 | Office Spawns Shell | Windows | `05-office-spawns-shell/run.ps1` | RULE-005 | T1059 |
| 06 | Scheduled Task | Windows | `06-scheduled-task/run.ps1` | RULE-006 | T1053.005 |
| 07 | LSASS Memory Dump | Windows | `07-procdump-lsass/run.ps1` | RULE-007 | T1003.001 |
| 08 | C2 Port Connection | Windows | `08-c2-port/run.ps1` | RULE-008 | T1071 |
| 09 | Brute Force → Account Creation | Linux | `09-brute-then-persist/run.sh` | RULE-009 | T1136.001 |
| 10 | LSASS Dump via comsvcs.dll | Windows | `10-lsass-comsvcs-dump/run.ps1` | RULE-010 | T1003.001 |
| 11 | Encoded PowerShell Evasion | Windows | `11-encoded-powershell-evasion/run.ps1` | RULE-011 | T1059.001 |
| 12 | certutil Decode | Windows | `12-certutil-decode/run.ps1` | RULE-012 | T1140 |

---

## Prerequisites

### SIEM must be running and reachable

```bash
# Docker Compose (recommended for lab use)
docker-compose up --build

# Or locally
python run.py
```

Set environment variables on both VMs before running scripts or the forwarder:

```bash
export SIEM_URL="http://<siem-ip>:5000"
export INGEST_API_KEY=""   # set if configured in docker-compose; empty = no auth
```

### Linux VM

- Python 3, `requests` (`pip install requests`)
- `sudo` access for the test user
- Run the forwarder before starting scenarios:

```bash
python forwarders/linux_forwarder.py
```

The Linux forwarder tails `/var/log/auth.log` (SSH failures/successes) and the
sudo audit log (commands run via sudo) and POSTs normalized events to `/ingest`.

### Windows VM

- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed
  and running with a config that captures Event ID 1 (process creation) and
  Event ID 3 (network connection)
- Python 3 + pywin32:

```powershell
pip install -r forwarders/requirements-windows.txt
```

- Run the forwarder before starting scenarios:

```powershell
python forwarders/windows_forwarder.py
```

The Windows forwarder reads new Sysmon events from the Windows Event Log and
POSTs them to `/ingest` (process creations and network connections).

**Scenario 07 (LSASS dump) additionally requires:**
- `procdump.exe` (free, [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)) placed in the `07-procdump-lsass/` folder
- The script must be run as Administrator

**Scenario 10 (LSASS dump via comsvcs.dll) additionally requires:**
- The script must be run as Administrator (reading LSASS memory requires elevation)

---

## Running a scenario

Copy the scenario folder to the appropriate VM, then:

```bash
# Linux
bash run.sh

# Windows (PowerShell)
.\run.ps1
```

Each script prints what it's doing and cleans up after itself. The SIEM detection
cycle runs every ~30 seconds — the corresponding alert should appear on the
dashboard at `http://<siem-ip>:5000` within one cycle.

> **Scenario 09 note:** The sequence rule (RULE-009) requires `auth_success` followed
> by `useradd` on the same host within 10 minutes. The Linux forwarder doesn't watch
> SSH accepted-login lines directly, so `run.sh` POSTs the `auth_success` event via
> `curl`, then runs `sudo useradd` (which the forwarder picks up from the sudo log).

---

## Validating coverage

`validate.py` is a stdlib-only helper — no `pip install` needed:

```bash
# Run all 12 scenarios interactively
python attack-lab/validate.py --siem http://<siem-ip>:5000

# Run one scenario
python attack-lab/validate.py --siem http://<siem-ip>:5000 --scenario 01

# If INGEST_API_KEY is set in docker-compose:
python attack-lab/validate.py --siem http://<siem-ip>:5000 --api-key <key>
```

For each scenario it:
1. Prints the script path to run on the VM
2. Waits for you to press Enter (run the script on the VM first)
3. Polls `GET /api/alerts?rule_id=<RULE>&since=<timestamp>` every 5 s, up to 60 s
4. Prints `✅ RULE-NNN fired` or `❌ did not fire within 60s`
5. Rewrites [COVERAGE.md](COVERAGE.md) with the updated results

Until run on live VMs, `COVERAGE.md` shows ⏳ for all rows by design.
