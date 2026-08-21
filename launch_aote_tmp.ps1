# Temporary launcher for main.py (background start + status check)
$ErrorActionPreference = "Stop"
$dir = "d:\HugoMoveData\User\seewo\Documents\All-in-One of the Elite"
Set-Location $dir
$env:PYTHONIOENCODING = "utf-8"

$outLog = Join-Path $dir "aote_console.log"
$errLog = Join-Path $dir "aote_console_err.log"
Remove-Item $outLog, $errLog -ErrorAction SilentlyContinue

$p = Start-Process -FilePath "python" -ArgumentList "main.py" -WorkingDirectory $dir `
    -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 8

if (-not $p.HasExited) {
    Write-Output ("AOTE_RUNNING PID=" + $p.Id)
} else {
    Write-Output ("AOTE_EXITED code=" + $p.ExitCode)
}
