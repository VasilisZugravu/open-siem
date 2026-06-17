# RULE-009 — Brute Force Followed by Account Creation

**Trigger:** Sequence: `auth_success` → `command_execution` containing
`useradd` on the **same host** within 10 minutes. **Severity:** Critical ·
**ATT&CK:** T1136.001 (Persistence)

This is the highest-fidelity correlation rule in the set — it chains a
login with the persistence step that typically follows a compromise. Treat
it with more urgency than RULE-001 or RULE-003 alone.

## Triage (first 5 minutes)

1. Open the alert — `details` contains both `step1_event` (the login) and
   `step2_event` (the useradd) IDs. Pull both from the Alert Detail page.
2. Check the login's `src_ip` — is it a known jump host / admin workstation,
   or unattributed/external?
3. Check whether the same `src_ip` also triggered RULE-001 (brute force)
   shortly before the successful login — that's strong corroborating
   evidence of a credential-stuffing → compromise → persistence chain.

## Investigation

- Resolve the new account's group membership (sudo/wheel) and whether it
  was used to log in after creation.
- Check whether the legitimate account owner (whoever's credentials logged
  in) actually performed this action, or whether their account was
  compromised and used by someone else.
- Audit all other commands run in the same session between login and
  useradd — what else did the attacker do in that 10-minute window?

## Containment

- Disable the newly created account immediately.
- Force a password reset and session invalidation for the account that
  logged in.
- Block the source IP if external/unattributed.
- Audit the host for other persistence mechanisms (cron jobs, SSH
  authorized_keys, systemd units) added in the same window.

## Escalation

This rule firing is itself an escalation trigger — loop in IR lead
immediately rather than triaging solo, regardless of initial read.

## False positive check

See [RULE-009 in false-positives.md](../docs/false-positives.md#rule-009--brute-force-followed-by-account-creation-t1136001) —
a sysadmin logging in and then provisioning a new account in the same
window is the realistic FP, common in small teams with ad-hoc workflows.

## Closure

- **closed_fp:** Confirmed legitimate admin login + provisioning, matches a
  known change/ticket.
- **closed_tp:** Document the full chain (source IP, account compromised,
  account created, other actions taken) and all containment steps.
