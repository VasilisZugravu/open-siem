# Hunt: LOLBin Inventory

**Hypothesis:** Living-off-the-land binaries (`rundll32`, `certutil`,
`mshta`, `regsvr32`, `wmic`, `bitsadmin`, `cscript`, `wscript`, `msbuild`,
`installutil`) are being invoked with flag combinations the existing rules
don't check for. RULE-007/010/012 each match one specific technique per
binary — this hunt surfaces everything else those binaries are doing.

**Data source:** `events` where `event_type = 'process_creation'`.

```sql
SELECT
    host,
    process_name,
    command_line,
    details->>'parent_process' AS parent_process,
    "user",
    timestamp
FROM events
WHERE event_type = 'process_creation'
  AND lower(process_name) IN (
      'rundll32.exe', 'certutil.exe', 'mshta.exe', 'regsvr32.exe',
      'wmic.exe', 'bitsadmin.exe', 'cscript.exe', 'wscript.exe',
      'msbuild.exe', 'installutil.exe'
  )
  AND timestamp >= now() - interval '7 days'
ORDER BY host, process_name, timestamp;
```

**SQLite equivalent** (swap `details->>'parent_process'` and
`now() - interval '7 days'`):

```sql
SELECT host, process_name, command_line,
       json_extract(details, '$.parent_process') AS parent_process,
       user, timestamp
FROM events
WHERE event_type = 'process_creation'
  AND lower(process_name) IN ('rundll32.exe','certutil.exe','mshta.exe',
      'regsvr32.exe','wmic.exe','bitsadmin.exe','cscript.exe','wscript.exe',
      'msbuild.exe','installutil.exe')
  AND timestamp >= datetime('now', '-7 days')
ORDER BY host, process_name, timestamp;
```

## What a legitimate result looks like

- `wmic.exe` queries from monitoring/inventory agents (no file write, no
  network args).
- `regsvr32.exe` registering a legitimately-installed COM component during
  software install (parent is `msiexec.exe`).
- `cscript.exe`/`wscript.exe` running a known internal logon script.

## What to escalate on sight

- `regsvr32.exe /s /n /u /i:http://...` (Squiblydoo — remote script
  execution via a scriptlet URL).
- `mshta.exe` with an `http://`/`https://` argument (remote HTA execution).
- `bitsadmin.exe /transfer` downloading to a user-writable path.
- `rundll32.exe` invoking anything other than a small set of known-good DLL
  exports.

## Tuning

If a specific binary/parent-process combination is consistently benign in
your environment (e.g. a packaging tool that always calls `regsvr32.exe`
with the same arguments), add an explicit `AND NOT (...)` exclusion rather
than dropping the binary from the list entirely — you'd lose coverage for
every other use of that binary.
