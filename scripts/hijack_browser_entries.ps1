# Hijack browser launch entries so Edge launched from ANY entry
# (taskbar / start menu / desktop / URL link) carries CDP debug params
# and can be controlled by AOTE BrowserSandbox.
#
# What it does:
#   1. Registry URL association (HKCR\MSEdgeHTM\shell\open\command via HKCU
#      override) - used when a link / URL is opened.
#   2. Taskbar pinned / start menu / desktop shortcuts - used when the
#      browser icon itself is clicked (this is the "taskbar launch" case).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\hijack_browser_entries.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\hijack_browser_entries.ps1 -Revert
#
# No administrator rights needed (HKCU + user-scope shortcuts only).

param(
    [switch]$Revert,
    [int]$Port = 9222,
    [string]$UserDataDir = "",
    # 额外接管 App Paths：部分客户端/新闻应用用 ShellExecute("msedge.exe") 拉起，
    # 该入口不经 ProgId 的 shell\open\command，只能靠 App Paths 覆盖。
    # 因需改写为包装脚本（可能影响依赖 exe 路径的程序），默认关闭。
    [switch]$AppPaths
)

$ErrorActionPreference = "Stop"

# ---------- defaults ----------
if (-not $UserDataDir) {
    $UserDataDir = Join-Path $env:LOCALAPPDATA "AOTE\cdp_debug_profile"
}
$backupRoot = Join-Path $env:LOCALAPPDATA "AOTE\lnk_backup"
$hijackKey  = "HKCU:\Software\AOTE\BrowserHijack"

function Find-BrowserExe {
    $candidates = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        (Join-Path $env:LOCALAPPDATA "Microsoft\Edge\Application\msedge.exe"),
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        (Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe")
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    return $null
}

function Find-ProgIds($exePath) {
    # MSEdgeHTM     : http/https 及 .html/.htm 网页文件关联
    # microsoft-edge: Windows 搜索框/小组件/资讯/Widgets 等系统入口专用协议
    # MSEdgePDF     : PDF 关联（Edge 为默认 PDF 阅读器时走此入口）
    if ($exePath -match "msedge\.exe") { return @("MSEdgeHTM", "microsoft-edge", "MSEdgePDF") }
    if ($exePath -match "chrome\.exe") { return @("ChromeHTML") }
    return @()
}

# ---------- 3. App Paths（可选，默认关闭） ----------
# ShellExecute("msedge.exe") 直接用 App Paths 定位可执行文件，完全绕过 ProgId 的
# command，因此这类入口不会带上调试参数，会被 watchdog 判为"未受管"而终止。
# App Paths 只能指向一个可执行文件、无法附加参数，故改写为指向静默包装脚本。
function Set-AppPaths($exePath) {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
    $wrapper = Join-Path (Split-Path $UserDataDir -Parent) "msedge_cdp_launcher.vbs"

    if ($Revert) {
        if (Test-Path $key) { Remove-Item -Path $key -Force -ErrorAction SilentlyContinue }
        if (Test-Path $wrapper) { Remove-Item -Path $wrapper -Force -ErrorAction SilentlyContinue }
        Write-Output "[restore] App Paths 已还原"
        return
    }

    # 单引号 here-string：VBScript 内容原样保留（VBS 的 "" 转义无需再按 PowerShell
    # 规则二次转义），变量改用占位符在生成后替换，避免引号嵌套导致的解析歧义。
    $vbs = @'
Set sh = CreateObject("WScript.Shell")
args = ""
For Each a In WScript.Arguments
    If InStr(a, " ") > 0 Then
        args = args & " """ & a & """"
    Else
        args = args & " " & a
    End If
Next
sh.Run """__EXE__"" --remote-debugging-port=__PORT__ --user-data-dir=""__UDD__"" --no-first-run --no-default-browser-check" & args, 1, False
'@
    $vbs = $vbs.Replace('__EXE__', $exePath).Replace('__PORT__', "$Port").Replace('__UDD__', $UserDataDir)
    Set-Content -Path $wrapper -Value $vbs -Encoding ASCII
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name "(default)" -Value $wrapper
    Write-Output "[ok] App Paths 已接管 -> $wrapper"
    Write-Output "     注意: 该入口改为包装脚本启动，若发现某些程序异常可用 -Revert 还原"
}

function Add-CdpArgs($existing) {
    $existing = ($existing -replace '^--single-argument\s*', '').Trim()
    $args = "--remote-debugging-port=$Port --user-data-dir=`"$UserDataDir`" " +
            "--no-first-run --no-default-browser-check --disable-blink-features=AutomationControlled"
    if ($existing) { return "$existing $args" }
    return $args
}

# ---------- 1. registry URL association ----------
function Set-UrlAssociation($exePath) {
    $progIds = Find-ProgIds $exePath
    if ($progIds.Count -eq 0) {
        Write-Output ("[skip] 未知浏览器 ProgId: " + $exePath)
        return
    }
    foreach ($progId in $progIds) {
        $key = "HKCU:\Software\Classes\$progId\shell\open\command"
        # 注意：--single-argument %1 必须保持 Edge 原生格式（%1 不加引号），
        # 否则 URL 会被引号污染，Edge 无法识别 microsoft-edge: 等协议。
        $cmd = "`"$exePath`" --remote-debugging-port=$Port --user-data-dir=`"$UserDataDir`" " +
               "--no-first-run --no-default-browser-check --disable-blink-features=AutomationControlled " +
               "--single-argument %1"

        if ($Revert) {
            $old = (Get-ItemProperty -Path $hijackKey -Name "UrlCmd_$progId" -ErrorAction SilentlyContinue)."UrlCmd_$progId"
            if ($old) {
                Set-ItemProperty -Path $key -Name "(default)" -Value $old
                Write-Output ("[restore] URL 关联已还原: HKCR\" + $progId + "\shell\open\command")
            } else {
                # no original saved - remove our override so HKLM value shines through
                Remove-Item -Path $key -Force -ErrorAction SilentlyContinue
                Write-Output ("[restore] 已删除 HKCU 覆盖: " + $key)
            }
            continue
        }

        # save original (first run only)
        $orig = (Get-ItemProperty -Path $key -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
        if (-not (Get-ItemProperty -Path $hijackKey -Name "UrlCmd_$progId" -ErrorAction SilentlyContinue)) {
            if (-not (Test-Path $hijackKey)) { New-Item -Path $hijackKey -Force | Out-Null }
            New-ItemProperty -Path $hijackKey -Name "UrlCmd_$progId" -Value $orig -Force | Out-Null
        }
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name "(default)" -Value $cmd
        Write-Output ("[ok] URL 关联已接管: HKCR\" + $progId + "\shell\open\command")
        Write-Output ("      -> " + $cmd)
    }
}

# ---------- 2. pinned shortcuts (taskbar / start menu / desktop) ----------
function Get-LnkDirs {
    $dirs = @()
    $taskbar = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    $impl    = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts"
    $startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    $desktop = [Environment]::GetFolderPath("Desktop")
    foreach ($d in @($taskbar, $impl, $startMenu, $desktop)) {
        if (Test-Path -LiteralPath $d) { $dirs += $d }
    }
    return $dirs
}

function Is-BrowserLnk($shortcut) {
    $t = $shortcut.TargetPath.ToLower()
    return ($t -like "*msedge.exe" -or $t -like "*chrome.exe" -or
            $t -like "*360se*" -or $t -like "*360chrome*" -or
            $t -like "*qqbrowser*" -or $t -like "*sogou*" -or
            $t -like "*liebao*" -or $t -like "*opera.exe")
}

function Set-PinnedShortcuts($exePath) {
    $ws = New-Object -ComObject WScript.Shell
    $count = 0
    foreach ($dir in Get-LnkDirs) {
        Get-ChildItem -LiteralPath $dir -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $sc = $ws.CreateShortcut($_.FullName)
            } catch { return }
            if (-not (Is-BrowserLnk $sc)) { return }

            if ($Revert) {
                $rel = $_.FullName.Substring((Resolve-Path (Split-Path $_.FullName -Parent)).Path.Length + 1)
                $safe = ($rel -replace '[\\/:*?"<>|]', '_')
                $bak = Join-Path $backupRoot $safe
                if (Test-Path -LiteralPath $bak) {
                    Copy-Item -LiteralPath $bak -Destination $_.FullName -Force
                    Write-Output ("[restore] 快捷方式已还原: " + $_.FullName)
                }
                $count++
                return
            }

            if ($sc.Arguments -match "remote-debugging-port") {
                Write-Output ("[skip] 已带调试参数: " + $_.FullName)
                return
            }
            # backup original (first run only)
            $rel = $_.FullName.Substring((Resolve-Path (Split-Path $_.FullName -Parent)).Path.Length + 1)
            $safe = ($rel -replace '[\\/:*?"<>|]', '_')
            $bak = Join-Path $backupRoot $safe
            if (-not (Test-Path -LiteralPath $bak)) {
                if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null }
                Copy-Item -LiteralPath $_.FullName -Destination $bak -Force
            }
            $sc.Arguments = Add-CdpArgs $sc.Arguments
            $sc.Save()
            Write-Output ("[ok] 已注入 CDP 参数: " + $_.FullName)
            Write-Output ("      args -> " + $sc.Arguments)
            $count++
        }
    }
    if ($count -eq 0) { Write-Output "[warn] 未找到浏览器快捷方式（可手动把 Edge 固定到任务栏后重试）" }
}

# ---------- main ----------
$exe = Find-BrowserExe
if (-not $exe) {
    Write-Output "ERROR: 未找到 Edge/Chrome，请先安装浏览器。"
    exit 1
}
Write-Output ("浏览器: " + $exe)
Write-Output ("调试端口: " + $Port)
Write-Output ("独立 profile: " + $UserDataDir)

if ($Revert) {
    Write-Output "===== 开始还原 ====="
    Set-UrlAssociation $exe
    Set-PinnedShortcuts $exe
    Set-AppPaths $exe
    Write-Output "还原完成。已覆盖的 URL 关联、快捷方式、App Paths 均恢复原状。"
} else {
    Write-Output "===== 开始接管 ====="
    Set-UrlAssociation $exe
    Set-PinnedShortcuts $exe
    if ($AppPaths) { Set-AppPaths $exe }
    Write-Output ""
    Write-Output "完成。现在从任务栏/开始菜单/桌面点击浏览器，或点击任意网页链接，"
    Write-Output "Edge 都会以调试端口 $Port 启动并纳入 AOTE 管控。"
    Write-Output "若 Edge 正在运行，请先完全退出再重新打开（否则参数会被已有实例忽略）。"
    if (-not $AppPaths) {
        Write-Output ""
        Write-Output "提示: 若从某些客户端/新闻应用打开链接时浏览器仍被终止，说明该入口走的是"
        Write-Output "      App Paths（不经 ProgId command），可加 -AppPaths 参数一并接管。"
    }
    Write-Output ""
    Write-Output ("备份位置: " + $backupRoot)
    Write-Output ("还原命令: powershell -ExecutionPolicy Bypass -File scripts\hijack_browser_entries.ps1 -Revert")
}
