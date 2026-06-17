# RULE-010 — LSASS Dump via comsvcs.dll (rundll32)

**Trigger:** `process_creation` for `rundll32.exe` whose `command_line`
matches `comsvcs\.dll.*minidump` (case-insensitive). **Severity:** High ·
**ATT&CK:** T1003.001 (Credential Access)

This is the alternate-path counterpart to RULE-007 — it catches the built-in
LOLBin technique (`rundll32.exe comsvcs.dll, MiniDump <pid> out.dmp full`)
that targets a process ID instead of the literal string "lsass", which is
why RULE-007 alone cannot detect it. See
[the evasion test pair](../tests/test_false_positives.py) for proof of the
gap this rule closes.

## Triage (first 5 minutes)

1. Open the alert, read the full `command_line` — confirm the PID argument
   and output path.
2. Resolve the PID referenced in the command line at the time of the event —
   if it corresponds to `lsass.exe`, this is a confirmed credential-dumping
   attempt, not a benign comsvcs.dll load.
3. Treat this with the same urgency as a RULE-007 true positive — it's the
   same impact via a different LOLBin.

## Investigation

- Same as RULE-007: check whether a `.dmp` file was actually written to
  disk, identify `process_name`/parent of `rundll32.exe`, and check for any
  preceding alert (RULE-004/005/011) that delivered the command.
- Check whether RULE-007 also fired around the same time on this host — an
  attacker pivoting between LSASS-dump techniques after one is blocked.

## Containment

Identical to RULE-007: isolate the host, treat all cached credentials on it
as compromised, force resets, and hunt for lateral movement using the
dumped credentials.

## Escalation

Escalate immediately on confirmation that the target PID was `lsass.exe`.

## False positive check

See [RULE-010 in false-positives.md](../docs/false-positives.md#rule-010--lsass-dump-via-comsvcsdll-t1003001) —
non-dump comsvcs.dll exports (e.g. `ResolveTrustee`) are the only realistic
benign match, and the `minidump` anchor in the regex already excludes most
of them.

## Closure

- **closed_fp:** Confirmed non-MiniDump comsvcs.dll export, or target PID
  was not `lsass.exe`.
- **closed_tp:** Same documentation requirements as RULE-007.
