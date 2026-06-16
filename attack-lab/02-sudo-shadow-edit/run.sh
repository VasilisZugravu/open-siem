#!/usr/bin/env bash
# Scenario 02 — Sudo Shadow File Access
# Triggers RULE-002: sudo command_line matching (shadow|visudo)
# Run on: Linux VM with sudo access, with linux_forwarder.py running

set -euo pipefail

echo "[02] Running sudo grep against /etc/shadow..."
sudo grep root /etc/shadow > /dev/null || true
echo "[02] Done."
