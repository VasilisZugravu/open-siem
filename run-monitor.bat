@echo off
title SIEM Machine Monitor
cd /d "%~dp0"

set SIEM_URL=http://localhost:5000
set INGEST_API_KEY=

for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
    if /i "%%A"=="INGEST_API_KEY" set "INGEST_API_KEY=%%B"
    if /i "%%A"=="SIEM_URL" set "SIEM_URL=%%B"
)

if not exist "venv\Scripts\python.exe" (
    echo ERROR: Save this file to your SIEM repo folder first.
    pause
    exit /b 1
)

echo Monitoring %COMPUTERNAME% -^> %SIEM_URL%   (Ctrl+C to stop)
set PYTHONPATH=%~dp0
"venv\Scripts\python.exe" "forwarders\host_forwarder.py"
pause
