# Create AOTE CDP debug browser shortcut on Desktop
$ErrorActionPreference = "Stop"

$paths = @(
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
)

$exe = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) {
    Write-Output "EDGE_NOT_FOUND"
    exit 1
}
Write-Output ("EDGE_FOUND: " + $exe)

$desktop = [Environment]::GetFolderPath("Desktop")
$lnkPath = Join-Path $desktop "AOTE CDP Debug Browser.lnk"

$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnkPath)
$sc.TargetPath = $exe
# 关键点：--user-data-dir 使用独立配置目录，确保即使有普通 Edge 正在运行，
# 也会启动独立调试实例并监听 9222 端口（否则 Edge 会把参数转发给旧实例而忽略）
$sc.Arguments = "--remote-debugging-port=9222 --user-data-dir=%LOCALAPPDATA%\AOTE\cdp_debug_profile --no-first-run --no-default-browser-check --disable-web-security --disable-blink-features=AutomationControlled"
$sc.Description = "AOTE CDP debug browser (port 9222, isolated profile), managed by BrowserSandbox"
$sc.Save()

if (Test-Path $lnkPath) {
    Write-Output ("SHORTCUT_CREATED: " + $lnkPath)
} else {
    Write-Output "SHORTCUT_FAILED"
    exit 1
}
