# RULE-004 — Encoded PowerShell Command

**Trigger:** `process_creation` for `powershell.exe` with `-enc` in the
command line. **Severity:** High · **ATT&CK:** T1059.001 (Execution)

## Triage (first 5 minutes)

1. Open the alert, note `parent_process` (in event `details`) and the
   base64 blob in `command_line`.
2. Decode the base64 (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))`)
   to see the actual command before deciding anything else.
3. Check `parent_process` — `explorer.exe` or an Office app is far more
   suspicious than `wmiprvse.exe`/`ccmexec.exe` (SCCM) or a known monitoring
   agent.

## Investigation

- Did the decoded command download anything (`Invoke-WebRequest`,
  `Net.WebClient`), disable security tooling (AMSI bypass strings like
  `amsiutils`), or establish persistence (registry run keys, scheduled
  tasks)?
- Check for a RULE-006 (scheduled task) or RULE-008 (C2 port) alert on the
  same host immediately after — `-enc` PowerShell often precedes one.
- Also check whether the **same intent, different casing** evaded this rule
  by looking for RULE-011 alerts on the same host (see RULE-011 playbook) —
  RULE-004 and RULE-011 are meant to be reviewed together.

## Containment

- Isolate the host from the network if the decoded command shows
  download/persistence behavior.
- Kill the PowerShell process tree and capture a memory/process snapshot
  before remediation if forensic capability is available.

## Escalation

Escalate immediately if the decoded payload downloads a second-stage tool,
disables AMSI/Defender, or the parent process is an Office application
(chained with RULE-005).

## False positive check

See [RULE-004 in false-positives.md](../docs/false-positives.md#rule-004--encoded-powershell-t1059001) —
SCCM and some monitoring agents legitimately use `-EncodedCommand`.

## Closure

- **closed_fp:** Decoded payload is a known signed management-agent action.
- **closed_tp:** Document the decoded command and any follow-on activity.
