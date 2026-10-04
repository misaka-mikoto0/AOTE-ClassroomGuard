# AOTE Guardian - Configure auto-start with administrator privileges
#
# Why a scheduled task instead of the registry Run key:
#   The HKCU/HKLM Run key always launches with the logon user's standard token.
#   Windows provides no way to request elevation from a Run entry, so AOTE would
#   start without administrator rights. A scheduled task with /RL HIGHEST is the
#   supported way to launch elevated at logon without a UAC prompt.
#
# Usage:
#   Right-click this file -> "Run with PowerShell" as Administrator, or
#   in an elevated PowerShell:  .\scripts\install_admin_autostart.ps1
$ErrorActionPreference = "Stop"

# ---- 1) Require administrator privileges ----
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "        Right-click it and choose 'Run as administrator'." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# ---- 2) Locate the deployed single-file executable ----
$exe = Join-Path $env:LOCALAPPDATA "AOTE\AOTE.exe"
if (-not (Test-Path $exe)) {
    Write-Host "[ERROR] Executable not found: $exe" -ForegroundColor Red
    Write-Host "        Run the build script first to package and deploy." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

$taskName = "AOTE_Guardian"
$tr = '"' + $exe + '"'

# ---- 3) Clean up any previous configuration ----
schtasks /Delete /TN $taskName /F 2>$null | Out-Null
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name $taskName -ErrorAction SilentlyContinue | Out-Null

# ---- 4) Create task: at logon, highest privileges ----
Write-Host "Creating scheduled task '$taskName' ..."
Write-Host "  Trigger   : At logon"
Write-Host "  Privileges: Highest (Administrator, no UAC prompt at startup)"
Write-Host "  Program   : $exe"
Write-Host ""
Write-Host "NOTE: Windows will ask for your account password to store the" -ForegroundColor Yellow
Write-Host "      task credentials (required for silent elevation at logon)." -ForegroundColor Yellow
Write-Host ""
schtasks /Create /TN $taskName /TR $tr /SC ONLOGON /RL HIGHEST /F

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to create task (exit=$LASTEXITCODE)" -ForegroundColor Red
    Write-Host "        If your account has no password, Windows may reject the task." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[OK] Auto-start configured with administrator privileges." -ForegroundColor Green
Write-Host ""

# ---- 5) Offer to start it right now ----
$start = Read-Host "Start AOTE now with administrator privileges? [Y/n]"
if ($start -ne "n" -and $start -ne "N") {
    schtasks /Run /TN $taskName
    Start-Sleep -Seconds 2
    Write-Host "Started. Check the tray icon for the AOTE shield." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Management commands (elevated PowerShell):"
Write-Host "  Query   : schtasks /Query /TN $taskName"
Write-Host "  Run now : schtasks /Run /TN $taskName"
Write-Host "  Stop    : Get-Process AOTE | Stop-Process -Force"
Write-Host "  Remove  : schtasks /Delete /TN $taskName /F"
Write-Host ""
Read-Host "Press Enter to exit"
