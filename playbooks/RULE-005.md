# RULE-005 — Office Application Spawned a Shell

**Trigger:** `process_creation` for `cmd.exe` or `powershell.exe` whose
`parent_process` is `winword.exe` or `excel.exe`. **Severity:** High ·
**ATT&CK:** T1059 (Execution)

## Triage (first 5 minutes)

1. Open the alert — note the spawned process's `command_line` immediately.
   This almost always tells you the whole story in one read.
2. Identify the document that was open (check recent Office file access on
   the host, or ask the user what they opened) — this is the likely delivery
   vector (phishing attachment with a malicious macro).
3. Check whether the user actually clicked "Enable Content"/"Enable Macros"
   recently — most environments log this via Office trust-center telemetry
   if available outside this SIEM.

## Investigation

- Trace the spawned shell's own children — does it download a payload, spawn
  another encoded PowerShell (RULE-004/RULE-011), or create a scheduled task
  (RULE-006)? Office-macro droppers commonly chain straight into one of
  those.
- Identify the email or download source of the document if possible.

## Containment

- Isolate the host immediately — this rule has very low false-positive risk,
  so isolate-first is the right default while investigating.
- Quarantine the source document; do not let it propagate via shared drives
  or email.

## Escalation

Treat any fire of this rule as a likely true positive until proven
otherwise — escalate to lead/IR immediately rather than triaging solo.

## False positive check

See [RULE-005 in false-positives.md](../docs/false-positives.md#rule-005--office-application-spawned-a-shell-t1059) —
only legacy line-of-business macros that legitimately shell out are a
realistic FP, and they're rare.

## Closure

- **closed_fp:** Confirmed legitimate, documented macro-based business
  automation (rare — get a second reviewer to agree).
- **closed_tp:** Document the delivery vector, payload, and whether it was
  contained before execution completed.
