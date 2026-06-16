#!/usr/bin/env bash
# Scenario 09 — Brute Force Followed by Account Creation
# Triggers RULE-009: auth_success → useradd on same host within 10 min (T1136.001 / Persistence)
# Run on: Linux VM with linux_forwarder.py running
#
# The forwarder does not watch SSH auth logs, so we POST the auth_success
# event directly to the SIEM. The useradd event is captured by the forwarder
# via its auditd/command watch as usual.

set -euo pipefail

SIEM_URL="${SIEM_URL:-http://localhost:5000}"
HOST="$(hostname)"
TS="$(date -u +%Y-%m-%dT%H:%M:%S)"

echo "[09] Simulating SSH auth success on host ${HOST}..."
curl -sf -X POST "${SIEM_URL}/ingest" \
    -H "Content-Type: application/json" \
    -d "{\"timestamp\":\"${TS}\",\"host\":\"${HOST}\",\"event_type\":\"auth_success\",\"user\":\"attacker\",\"src_ip\":\"198.51.100.1\"}" \
    > /dev/null
echo "[09] auth_success posted. Waiting 5s before creating user..."

sleep 5

echo "[09] Creating and immediately deleting test user (persistence step)..."
sudo useradd attack-lab-persist 2>/dev/null || true
sudo userdel -r attack-lab-persist 2>/dev/null || sudo userdel attack-lab-persist 2>/dev/null || true

echo "[09] Done. RULE-009 should fire within one detection cycle (~30s)."
