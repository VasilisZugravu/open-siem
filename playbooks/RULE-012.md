# RULE-012 — certutil Used to Decode a File

**Trigger:** `process_creation` for `certutil.exe` whose `command_line`
matches `-decode`. **Severity:** Medium · **ATT&CK:** T1140 (Defense Evasion)

## Triage (first 5 minutes)

1. Open the alert, read the full `command_line` — note the input and output
   file paths.
2. Check the output file extension. `.cer`/`.crt`/`.pem` is consistent with
   legitimate certificate handling; `.exe`/`.dll`/`.ps1`/`.bat` is a strong
   signal of payload staging.
3. Check whether a matching `certutil -encode` or `certutil -urlcache`
   (download) ran beforehand on the same host — `-urlcache` followed by
   `-decode` is the classic two-step LOLBin payload-staging pattern.

## Investigation

- If the output is an executable: pull it for analysis before it's
  deleted/run, and check whether it was subsequently executed
  (`process_creation` for that file path shortly after).
- Identify `parent_process` — `cmd.exe`/`powershell.exe` chained from an
  earlier alert (RULE-004/005/011) is more concerning than an interactive
  admin session.

## Containment

- Quarantine the decoded output file before it executes if you catch it in
  time.
- Isolate the host if the decoded file was already executed.

## Escalation

Escalate if the output file extension is executable/script-type, or if this
follows a download (`-urlcache`) on the same host.

## False positive check

See [RULE-012 in false-positives.md](../docs/false-positives.md#rule-012--certutil-used-to-decode-a-file-t1140) —
legitimate certificate/CRL decoding is rare but does happen in PKI admin
workflows.

## Closure

- **closed_fp:** Output file is a certificate/CRL artifact, not an
  executable or script.
- **closed_tp:** Document the decoded file, whether it executed, and
  containment actions.
