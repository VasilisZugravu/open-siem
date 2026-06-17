# RULE-007 — Possible LSASS Memory Dump (procdump)

**Trigger:** `process_creation` whose `command_line` contains `lsass`.
**Severity:** High · **ATT&CK:** T1003.001 (Credential Access)

## Triage (first 5 minutes)

1. Open the alert, read the full `command_line` and `process_name` of the
   triggering event.
2. Rule out the common benign cases immediately: `tasklist | findstr lsass`,
   `wmic process where name="lsass.exe"`, or an AV product enumerating LSASS
   as part of its own scan — these contain "lsass" but aren't dump attempts.
3. If the command line includes a known dump tool name (`procdump`,
   `-ma`, `.dmp` output path) — treat as a confirmed credential-dumping
   attempt and move to Containment immediately.

## Investigation

- Check whether a `.dmp` file was actually written to disk; if found,
  preserve it for evidence then delete it from the host.
- Identify who/what ran the command — is `process_name` a known
  EDR/monitoring tool, or an unexpected binary?
- Check whether this host also fired RULE-010 (comsvcs.dll variant) recently
  — an attacker who tries one LSASS-dump technique often tries another after
  the first is blocked or alerts.

## Containment

- Isolate the host — successful LSASS access means every credential cached
  on that machine should be considered compromised.
- Force a credential reset for every account that has logged into this host
  recently (not just the account that ran the dump).
- Hunt for use of the dumped credentials elsewhere in the environment
  (lateral movement) before closing the incident.

## Escalation

Escalate immediately on any confirmed dump tool invocation. This is one of
the highest-impact techniques in the rule set — don't triage solo.

## False positive check

See [RULE-007 in false-positives.md](../docs/false-positives.md#rule-007--possible-lsass-memory-dump-t1003001) —
admin LSASS lookups and AV scans are the common benign matches.

## Closure

- **closed_fp:** Confirmed benign enumeration (tasklist/wmic/AV), no dump
  file written.
- **closed_tp:** Document the tool used, whether a dump file was confirmed,
  and the credential-reset scope.
