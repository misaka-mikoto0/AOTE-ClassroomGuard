# AOTE 管控系统 - 一键打包 exe + 设置开机自启动
# 用法:
#   .\scripts\build_exe.ps1               # 仅打包（单文件，全环境+配置内嵌）
#   .\scripts\build_exe.ps1 -SetAutostart # 打包并设置开机自启动
#   .\scripts\build_exe.ps1 -NoBuild      # 跳过打包，仅执行自启动相关操作
#   .\scripts\build_exe.ps1 -RemoveAutostart  # 取消开机自启动
#   .\scripts\build_exe.ps1 -AutostartStatus   # 查询开机自启动状态
param(
    [switch]$SetAutostart,
    [switch]$NoBuild,
    [switch]$RemoveAutostart,
    [switch]$AutostartStatus
)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist"
$Exe  = Join-Path $Dist "AOTE.exe"

Write-Output "======================================================"
Write-Output " AOTE 管控系统 - 打包/自启动"
Write-Output "======================================================"

# ---------- 自启动操作 ----------
function Get-Autostart {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    try {
        $val = (Get-ItemProperty -Path $runKey -Name "AOTE_Guardian" -ErrorAction Stop)."AOTE_Guardian"
        return $val
    } catch { return $null }
}

if ($AutostartStatus) {
    $val = Get-Autostart
    if ($val) { Write-Output "✅ 开机自启动已启用: $val" }
    else      { Write-Output "❌ 开机自启动未启用" }
    exit 0
}

if ($RemoveAutostart) {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Path $runKey -Name "AOTE_Guardian" -ErrorAction SilentlyContinue
    Write-Output "✅ 已取消开机自启动"
    exit 0
}

# ---------- 打包 ----------
if (-not $NoBuild) {
    Write-Output "`n[1/3] 清理旧产物..."
    Remove-Item -Path (Join-Path $Root "build") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $Dist -Recurse -Force -ErrorAction SilentlyContinue

    Write-Output "[2/3] PyInstaller 打包中（单文件，全环境+配置内嵌，约 1-3 分钟）..."
    Push-Location $Root
    try {
        & pyinstaller aote.spec --noconfirm --clean
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller 打包失败 (exit=$LASTEXITCODE)" }
    } finally { Pop-Location }

    if (-not (Test-Path $Exe)) { throw "打包失败：未生成 $Exe" }
    Write-Output "✅ 打包完成: $Exe"
} else {
    if (-not (Test-Path $Exe)) {
        Write-Output "❌ 未找到 $Exe，请先执行打包（去掉 -NoBuild 参数）"
        exit 1
    }
    Write-Output "[1/3] 跳过打包（-NoBuild）"
}

# ---------- 复制 config 到 exe 旁（可选覆盖：用户可编辑，优先级高于内嵌配置）----------
Write-Output "[3/3] 复制 config 目录到 exe 旁（可编辑覆盖）..."
$DistConfig = Join-Path $Dist "config"
if (Test-Path $DistConfig) { Remove-Item -Path $DistConfig -Recurse -Force }
Copy-Item -Path (Join-Path $Root "config") -Destination $DistConfig -Recurse
if (-not (Test-Path (Join-Path $DistConfig "config.yaml"))) {
    Write-Output "❌ config 复制失败"
    exit 1
}
Write-Output "✅ config 已复制: $DistConfig"

# ---------- 自启动 ----------
if ($SetAutostart) {
    Write-Output "`n设置开机自启动..."
    & $Exe --install-autostart
    Start-Sleep -Milliseconds 500
    $val = Get-Autostart
    if ($val) {
        Write-Output "✅ 开机自启动已设置: $val"
    } else {
        Write-Output "❌ 开机自启动设置失败，请手动执行: $Exe --install-autostart"
    }
}

Write-Output "`n======================================================"
Write-Output " 🎉 完成！单文件产物: $Exe"
Write-Output " 启动方式: $Exe"
Write-Output " 配置覆盖: $DistConfig（删除后回退到内嵌配置）"
Write-Output " 开机自启动: 查询 $Exe --autostart-status"
Write-Output "======================================================"
