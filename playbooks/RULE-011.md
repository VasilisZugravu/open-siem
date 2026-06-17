# RULE-011 — Encoded PowerShell, Case/Long-Form Evasion

**Trigger:** `process_creation` whose `process_name` matches
`powershell\.exe` and `command_line` matches `-enc`, both case-insensitively.
**Severity:** High · **ATT&CK:** T1059.001 (Execution)

This is the evasion-hardened counterpart to RULE-004 — it catches case
manipulation (`PowerShell.EXE`, `-EnCoDedCommand`) that bypasses RULE-004's
exact-case checks. Run the RULE-004 playbook's investigation steps; the
only difference here is *why* this rule fired instead of (or alongside)
RULE-004.

## Triage (first 5 minutes)

Same as [RULE-004](RULE-004.md): decode the base64 payload first, then check
`parent_process`.

## Investigation

Same as RULE-004, plus one extra question: **why was the casing
non-standard?** Hand-typed or copy-pasted commands are normally consistent
case; deliberate case randomization (`PoWeRsHeLl.exe -EnCodedCommand`) is a
known technique specifically intended to dodge naive string-matching
detections (including this SIEM's own RULE-004) and is itself a signal of
attacker sophistication/awareness of detection tooling.

## Containment

Same as RULE-004.

## Escalation

Treat at least as seriously as RULE-004 — the case randomization itself is
evidence of deliberate evasion intent, which should raise your confidence
this is malicious rather than lower it.

## False positive check

See [RULE-011 in false-positives.md](../docs/false-positives.md#rule-011--encoded-powershell-caselong-form-evasion-t1059001) —
same FP causes as RULE-004 (SCCM, monitoring agents), regardless of case.

## Closure

Same closure criteria as RULE-004.
