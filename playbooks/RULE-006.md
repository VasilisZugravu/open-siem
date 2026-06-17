# RULE-006 — Scheduled Task Created

**Trigger:** `process_creation` for `schtasks.exe` with `/create` in the
command line. **Severity:** Medium · **ATT&CK:** T1053.005 (Persistence)

## Triage (first 5 minutes)

1. Open the alert, read the full `command_line` — the `/tn` (task name) and
   `/tr` (task run command) arguments tell you immediately whether this is a
   normal installer task or a persistence mechanism.
2. Check `parent_process` — `msiexec.exe`/`setup.exe` is a routine installer;
   `cmd.exe` or `powershell.exe` (especially following RULE-004/011) is far
   more suspicious.
3. Look at the `/tr` target path — does it point into `%TEMP%`, `%APPDATA%`,
   or an unusual location rather than `Program Files`?

## Investigation

- Resolve whether the task's target binary exists and what it does; pull it
  for analysis if unknown.
- Check the task's trigger (`/sc daily`, `/sc onlogon`, etc.) — recurring,
  frequent triggers are typical of persistence; one-shot tasks less so.
- Check for this rule firing immediately after RULE-004/RULE-005/RULE-011 on
  the same host — that chain (macro/encoded-PS → scheduled task) is a
  classic persistence pattern.

## Containment

- Delete the scheduled task (`schtasks /delete /tn <name> /f`) once you've
  captured its definition for evidence.
- Remove or quarantine the target binary referenced by `/tr`.

## Escalation

Escalate if the parent process is a shell (not an installer), the target
path is in a user-writable temp directory, or it chains from another alert.

## False positive check

See [RULE-006 in false-positives.md](../docs/false-positives.md#rule-006--scheduled-task-created-t1053005) —
nearly every software installer and updater creates scheduled tasks.

## Closure

- **closed_fp:** Task created by a known installer/updater with a benign
  target path.
- **closed_tp:** Document the task definition, target binary, and removal.
