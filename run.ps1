# ==============================================================================
# Automated-Cloud-Incident-Response-SOAR-Engine One-Click Runner (PowerShell)
# ==============================================================================

param (
    [string]$Command = "simulate",
    [string]$Scenario = "all",
    [switch]$Live = $false,
    [switch]$Test = $false,
    [switch]$Dashboard = $false
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
$env:PYTHONPATH = $ScriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  AWS Cloud Incident Response & Threat Hunting SOAR Engine" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Test) {
    Write-Host "`n[*] Executing Test Suite (Pytest + Moto)..." -ForegroundColor Yellow
    python -m pytest tests/ -v
    exit $LASTEXITCODE
}

if ($Dashboard) {
    Write-Host "`n[*] Launching Live SOC Dashboard in default web browser..." -ForegroundColor Green
    Start-Process "$ScriptDir\index.html"
    exit 0
}

if ($Command -eq "playbooks") {
    python -m src.cli playbooks
    exit $LASTEXITCODE
}

Write-Host "`n[*] Running Incident Vector Simulation (Scenario: $Scenario)..." -ForegroundColor Yellow
if ($Live) {
    python -m src.cli simulate --scenario $Scenario --live
} else {
    python -m src.cli simulate --scenario $Scenario --dry-run
}
