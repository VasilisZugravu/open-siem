# Run the host telemetry forwarder on this Windows machine.
# The SIEM stack must already be running (docker compose up -d).
#
# Usage: .\run-monitor.ps1
# Stop:  Ctrl+C

$ErrorActionPreference = "Stop"

# --- locate repo root (the directory this script lives in) ---
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- read SIEM_URL and INGEST_API_KEY from .env (if present) ---
$EnvFile = Join-Path $Root ".env"
$SiemUrl = "http://localhost:5000"   # default
$ApiKey  = ""

if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*SIEM_URL\s*=\s*(.+)$')        { $SiemUrl = $Matches[1].Trim() }
        if ($_ -match '^\s*INGEST_API_KEY\s*=\s*(.+)$')  { $ApiKey  = $Matches[1].Trim() }
    }
}

# Honour any values already in the environment (override .env)
if ($env:SIEM_URL)        { $SiemUrl = $env:SIEM_URL }
if ($env:INGEST_API_KEY)  { $ApiKey  = $env:INGEST_API_KEY }
if ($env:SIEM_API_KEY)    { $ApiKey  = $env:SIEM_API_KEY }

$Python = Join-Path $Root "venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    Write-Error "venv not found at $Python - run: python -m venv venv; venv\Scripts\pip install -r requirements.txt"
}

Write-Host "Monitoring $env:COMPUTERNAME -> $SiemUrl   (Ctrl+C to stop)" -ForegroundColor Cyan

$env:SIEM_URL        = $SiemUrl
$env:INGEST_API_KEY  = $ApiKey
$env:PYTHONPATH      = $Root

& $Python (Join-Path $Root "forwarders\host_forwarder.py")
