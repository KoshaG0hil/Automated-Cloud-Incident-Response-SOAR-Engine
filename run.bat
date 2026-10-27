@echo off
setlocal
cd /d "%~dp0"
set PYTHONPATH=%~dp0

echo =================================================================
echo   AWS Cloud Incident Response & Threat Hunting SOAR Engine
echo =================================================================

if "%1"=="test" (
    echo [*] Executing Test Suite...
    python -m pytest tests/ -v
    goto :eof
)

if "%1"=="dashboard" (
    echo [*] Opening Dashboard...
    start index.html
    goto :eof
)

if "%1"=="playbooks" (
    python -m src.cli playbooks
    goto :eof
)

echo [*] Running Incident Simulation (Dry-Run Mode)...
python -m src.cli simulate --scenario all
