# False Positive Analysis

Detection engineering is not just about writing rules that fire on attacks — it's equally
about ensuring they stay quiet on legitimate activity. This document catalogues the known
false positive exposure in each rule, explains why each FP occurs, and documents the
recommended tuning lever. Rules that have no realistic FP scenario are noted as such.

The true-negative test suite (`tests/test_false_positives.py`) validates the most common
benign cases programmatically. The residual FPs documented here are real-world scenarios
that require VM-level context (process trees, user identity, time-of-day) to suppress.

---

## RULE-001 — SSH Brute Force (T1110)

**Detection:** ≥ 5 `auth_failure` events from the same `src_ip` within 60 seconds.

**Realistic FP scenario:** An automated monitoring tool or login script that retries
SSH authentication rapidly (e.g., a misconfigured backup job cycling through expired
credentials). Also fires if a legitimate user mistypes their password 5 times within 60
seconds.

**Why it fires:** The rule is intentionally broad — it counts failures by source IP,
not by destination or user, and has no allowlist.

**Recommended tuning:**
- Allowlist known monitoring IPs (e.g., internal jump hosts, Ansible controllers).
- Raise the threshold to 10+ for environments with high retry rates.
- Scope to external (`!is_private`) source IPs only — internal failures are lower risk.

**Current status:** Acceptable for a first-pass rule. Threshold of 5 is industry-standard
for initial deployment.

---

## RULE-002 — Sudo Shadow Edit (T1548.003)

**Detection:** `command_execution` whose `command_line` matches regex `(shadow|visudo)`.

**Realistic FP scenario:** Any command containing the substring "shadow" — for example:
- `systemctl restart shadowsocks` (VPN/proxy service)
- `apt install shadow-utils`
- `cat /etc/shadow-` (shadow backup file)

**Why it fires:** Substring regex `(shadow|visudo)` is intentionally broad to catch
variants; it does not anchor to the path `/etc/shadow` or require an edit verb.

**Recommended tuning:**
- Anchor the shadow match: `regex: "(/etc/shadow|visudo)"` (require the full path).
- Or require both `sudo` in the command AND a write-mode verb (`-e`, `tee`, `echo.*>`).
- Allowlist `shadow-utils` package operations by requiring the matched command to contain `/etc/shadow` rather than `shadow` anywhere.

---

## RULE-003 — New Local User Created (T1136.001)

**Detection:** `command_execution` whose `command_line` contains "useradd".

**Realistic FP scenario:** Any legitimate admin user provisioning (e.g., `useradd -m
developer`, automated CI pipeline spinning up a service account). On a developer
workstation this fires on every new Docker container setup.

**Why it fires:** The rule cannot distinguish between an attacker creating a backdoor
account and a sysadmin following standard onboarding procedure.

**Recommended tuning:**
- Allowlist known admin users (e.g., `user not in ["ansible", "puppet", "jenkins"]`).
- Scope to off-hours execution (flag only if fired outside business hours).
- Correlate with source: if preceded by `auth_success` from an external IP → escalate
  (this is precisely what RULE-009 does — it is the high-fidelity counterpart to RULE-003).

---

## RULE-004 — Encoded PowerShell (T1059.001)

**Detection:** `process_creation` for `powershell.exe` with `-enc` in the command line.

**Realistic FP scenario:**
- SCCM/Endpoint Manager deployments frequently use `-EncodedCommand` to pass complex
  configuration payloads.
- Some monitoring agents (e.g., Azure Monitor) use encoded PowerShell for configuration
  bootstrap.

**Why it fires:** `-enc` is a substring match on `command_line` — it catches
`-EncodedCommand`, `-Encoding`, and any parameter abbreviation that starts with `-enc`.

**Recommended tuning:**
- Match on the full `-EncodedCommand` or `-enc` preceded by whitespace: `regex: "\\s-[Ee][Nn][Cc]"`.
- Allowlist known signed parent processes (SCCM, WMI, SYSTEM context).
- Pair with process reputation: only alert if `parent_process` is a suspicious user-space app.

---

## RULE-005 — Office Application Spawned a Shell (T1059)

**Detection:** `process_creation` for `cmd.exe` or `powershell.exe` whose `parent_process`
is `winword.exe` or `excel.exe`.

**Realistic FP scenario:** Very few. Office spawning a shell is almost always malicious
in a modern, hardened environment. The main FP vector is a legacy macro suite that
legitimately calls shell commands for business automation (uncommon in enterprises with
macro policies).

**Why it fires:** If your environment still relies on legitimate Office macros that
call cmd.exe or PowerShell for business functions.

**Recommended tuning:** This rule has low FP exposure — no tuning recommended for most
environments. If you have a legacy macro requirement, allowlist the specific script name
in `command_line`.

---

## RULE-006 — Scheduled Task Created (T1053.005)

**Detection:** `process_creation` for `schtasks.exe` with `/create` in the command line.

**Realistic FP scenario:** Almost every software installer creates scheduled tasks —
Windows Update, Google Chrome updater, backup agents (Veeam, Acronis), antivirus
definition updaters. This rule fires on any routine software install.

**Why it fires:** The rule matches all scheduled task creation, regardless of task
author, signing status, or task name.

**Recommended tuning:**
- Allowlist known installer parent processes (`msiexec.exe`, `setup.exe`).
- Require that `command_line` contains a suspicious task command (e.g., `%TEMP%`,
  `%APPDATA%`, `http://`, a UNC path).
- Filter by `user` — SYSTEM-context task creation is normal; user-context is suspicious.

---

## RULE-007 — Possible LSASS Memory Dump (T1003.001)

**Detection:** `process_creation` whose `command_line` contains "lsass".

**Realistic FP scenario:**
- `tasklist | findstr lsass` — any admin checking if LSASS is running
- `wmic process where name="lsass.exe" get pid` — scripted PID lookup
- Antivirus tools that enumerate LSASS in their own scanning

**Why it fires:** The rule matches the substring "lsass" anywhere in the command line,
not just dump tools.

**Recommended tuning:**
- Require dump-specific tool names: `regex: "(procdump|minidump|MiniDumpWriteDump|comsvcs)"`.
- Or match lsass + a dump flag: command_line contains "lsass" AND contains "-ma" or ".dmp".
- MITRE-aligned: restrict to `OpenProcess` handle requests on LSASS (requires EDR
  telemetry, not available with this forwarder).

---

## RULE-008 — Outbound Connection to Known C2 Port (T1071)

**Detection:** `network_connection` to `dest_port` 4444 or 4445.

**Realistic FP scenario:**
- Developer running a local service bound to port 4444 (common with Metasploit
  training labs, or tools like `localtunnel`).
- Legitimate applications using non-standard ports (uncommon but possible).

**Why it fires:** Port-only heuristic with no process or destination reputation check.

**Recommended tuning:**
- Pair with destination IP reputation: only alert if `!is_private` (external connection).
- Allowlist known internal hosts on that port.
- Add process context: flag only if the connecting process is not a known developer tool.

**Current status:** High fidelity on real attacker infrastructure; lowest-FP rule in the
set for non-developer environments.

---

## RULE-009 — Brute Force Followed by Account Creation (T1136.001)

**Detection:** Sequence: `auth_success` → `command_execution` containing "useradd" on
the same host within 10 minutes.

**Realistic FP scenario:** A sysadmin who logs in via SSH and then provisions a new
service account in the same 10-minute window. In a small team with ad-hoc provisioning
this fires regularly.

**Why it fires:** The rule correlates by host but has no `src_ip` filter on the
auth_success step — a login from an internal jump host followed by routine user
provisioning looks identical to a post-compromise persistence action.

**Recommended tuning:**
- Add a condition on step 1: `src_ip` must be external (`!is_private`) — a brute force
  from an internal IP is almost always a test or misconfiguration, not an attack.
- Or add a time-of-day gate: flag only if the sequence occurs outside business hours.
- Highest-value tuning: allowlist jump-host IPs and known provisioning users; alert
  only on unrecognised src_ip + useradd combinations.

---

## RULE-010 — LSASS Dump via comsvcs.dll (T1003.001)

**Detection:** `process_creation` for `rundll32.exe` whose `command_line` matches
`comsvcs\.dll.*minidump` (case-insensitive).

**Why this rule exists:** RULE-007 matches the literal substring "lsass", but the
built-in `rundll32.exe comsvcs.dll, MiniDump <pid> out.dmp full` LOLBin technique
targets a process ID, never the string "lsass" — it walks straight past RULE-007.
See `tests/test_false_positives.py::test_evasion_lsass_comsvcs_bypasses_rule007` for
the bypass and `test_evasion_lsass_comsvcs_caught_by_rule010` for the catch.

**Realistic FP scenario:** Legitimate software occasionally loads `comsvcs.dll` for
unrelated COM-surrogate exports (e.g. `ResolveTrustee`). The `minidump` anchor in the
regex keeps this rule narrow — only the dump export fires.

**Recommended tuning:**
- Add a condition on the target PID resolving to `lsass.exe` if process-tree
  telemetry is available (not currently in this forwarder's event schema).
- Allowlist EDR/AV processes that legitimately invoke `MiniDumpWriteDump` for
  crash-reporting purposes.

---

## RULE-011 — Encoded PowerShell, Case/Long-Form Evasion (T1059.001)

**Detection:** `process_creation` whose `process_name` matches `powershell\.exe`
and `command_line` matches `-enc`, both case-insensitively.

**Why this rule exists:** RULE-004 uses an exact-case `process_name` equality check
and an exact-case `contains: "-enc"` substring. Both are trivially bypassed by
case manipulation — `PowerShell.EXE -EnCoDedCommand ...` matches neither check.
RULE-011 is the case-insensitive counterpart that closes that gap; see
`test_evasion_encoded_powershell_case_bypasses_rule004` and
`test_evasion_encoded_powershell_case_caught_by_rule011`.

**Realistic FP scenario:** Same as RULE-004 — SCCM/Endpoint Manager and monitoring
agents that pass `-EncodedCommand` payloads, regardless of casing.

**Recommended tuning:**
- Same as RULE-004: allowlist known signed parent processes, pair with process
  reputation context.
- Run RULE-004 and RULE-011 together rather than replacing one with the other —
  RULE-004 stays cheap/specific for the common case, RULE-011 covers the evasion
  case.

---

## RULE-012 — certutil Used to Decode a File (T1140)

**Detection:** `process_creation` for `certutil.exe` whose `command_line` matches
`-decode` (case-insensitive).

**Realistic FP scenario:** `certutil -decode` has legitimate uses — decoding a
base64-armored certificate or CRL that was emailed or copy-pasted as text. This is
rare in most environments but not unheard of in PKI administration workflows.

**Why it fires:** The rule matches any use of `-decode`, regardless of what is being
decoded.

**Recommended tuning:**
- Pair with the file extension being written: flag only if the output path ends in
  `.exe`, `.dll`, or `.ps1` rather than `.cer`/`.crt`.
- Correlate with a preceding `certutil -urlcache` (download) on the same host —
  the download-then-decode pair is far more specific to payload staging than
  `-decode` alone.

---

## Summary

| Rule | FP Risk | Primary FP Cause | Priority Tuning |
|------|---------|------------------|-----------------|
| RULE-001 | Low-Medium | Automation retries | Allowlist internal IPs |
| RULE-002 | Medium | "shadow" substring | Anchor to `/etc/shadow` |
| RULE-003 | High | Routine admin provisioning | Allowlist admin users |
| RULE-004 | Medium | SCCM/agent deployments | Allowlist signed parents |
| RULE-005 | Very Low | Legacy macro suites | None for most envs |
| RULE-006 | High | Every software install | Filter by task command/context |
| RULE-007 | Medium | LSASS process lookups | Require dump tool names |
| RULE-008 | Low | Dev servers on 4444 | Require external dest IP |
| RULE-009 | Medium | Admin login + provisioning | Filter on src_ip is_private |
| RULE-010 | Low | Non-dump comsvcs.dll exports | Correlate target PID with lsass.exe |
| RULE-011 | Medium | SCCM/agent deployments (any case) | Allowlist signed parents |
| RULE-012 | Low-Medium | Legitimate cert/CRL decode | Gate on output file extension |

The true-negative tests in `tests/test_false_positives.py` validate the most common
benign cases. The residual FPs above require VM-level telemetry (process trees, user
context, IP reputation) to suppress, which is documented here as a tuning roadmap.

RULE-010 and RULE-011 are not new techniques — they are alternate-path coverage for
RULE-007 and RULE-004 respectively, added because the original substring/exact-case
matches have demonstrable evasion gaps (see the `test_evasion_*` tests in
`tests/test_false_positives.py`). Detection-in-depth here means running the original
and the hardened variant together, not replacing one with the other.
