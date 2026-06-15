#!/usr/bin/env bash
# Scenario 03 — New Local User Created
# Triggers RULE-003: sudo command_line containing "useradd"
# Run on: Linux VM with sudo access, with linux_forwarder.py running

set -euo pipefail

echo "[03] Creating and immediately deleting test user..."
sudo useradd attack-lab-user 2>/dev/null || true
sudo userdel -r attack-lab-user 2>/dev/null || sudo userdel attack-lab-user 2>/dev/null || true
echo "[03] Done."
