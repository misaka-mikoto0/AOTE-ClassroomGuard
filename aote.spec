# -*- mode: python ; coding: utf-8 -*-
"""AOTE 管控系统 - PyInstaller 打包配置（单文件 onefile）

打包命令（在项目根目录执行）:
    pyinstaller aote.spec --noconfirm --clean

产物: dist/AOTE.exe（单文件，Python 运行时/全部依赖/playwright 驱动/config 全部内嵌）

运行时配置优先级（见 aote/config.py aote_config_path）:
    1. exe 所在目录 config/config.yaml（可编辑，热重载生效）
    2. 打包内嵌 config/config.yaml（_MEIPASS 解压）
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(SPECPATH).resolve()

# ---- playwright 驱动收集（node.exe + package），必须完整收集 ----
from PyInstaller.utils.hooks import collect_all

playwright_datas, playwright_binaries, playwright_hiddenimports = collect_all("playwright")

datas = [
    (str(PROJECT_ROOT / "config" / "config.yaml"), "config"),
] + playwright_datas

binaries = playwright_binaries
hiddenimports = playwright_hiddenimports + [
    # pystray 的 Windows 后端
    "pystray._win32",
    # keyboard 依赖
    "keyboard",
    # yaml 安全加载
    "yaml",
]

a = Analysis(
    [str(PROJECT_ROOT / "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AOTE",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # 无控制台窗口（托盘应用）
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
