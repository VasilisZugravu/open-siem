#!/usr/bin/env bash
# Scenario 01 — SSH Brute Force
# Triggers RULE-001: 5+ auth_failure events from the same src_ip within 60s
# Run on: Linux VM, with linux_forwarder.py running

set -euo pipefail

echo "[01] Sending 6 failed SSH login attempts to localhost..."
for i in $(seq 1 6); do
    ssh \
        -o BatchMode=yes \
        -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no \
        nonexistent@localhost 2>/dev/null || true
    sleep 1
done
echo "[01] Done."
