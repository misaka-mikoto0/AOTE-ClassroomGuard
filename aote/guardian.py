r"""
AOTE 管控系统 - 进程守护与后台运行支持

职责（全部为"可见、可审计"的常规做法，不含任何隐藏进程/内核级手段）：
1. 进程存活检测：复用 main.py 的命名互斥体，判断主进程是否在跑
2. 未授权终止后的自动重启：由 Windows 计划任务按周期调用 --ensure-running 完成，
   不额外常驻进程（任务管理器里始终能看到 AOTE 条目与其被拉起的时间点）
3. 授权退出标记：密码/热键退出后写入标记，守护不再自动拉起，直到下次登录
4. 终止/重启事件的审计日志（guardian_audit.log）
5. 开机自启与防关停：HKCU Run 键（登录即启动）+ 每 N 分钟的守护计划任务
   （/SC ONLOGON 在非管理员上下文会被拒绝，故不用它做登录触发）

守护检查为什么用"轻量脚本 + wscript"而不是再调一次本 exe：
- 本程序是 onefile 打包（约 60MB），每次调用都要重新解压，实测从进程创建
  到完成检查约 30~50 秒；若每分钟跑一次，等于持续占用磁盘与 CPU。
- 轻量脚本只做"查进程 + 必要时拉起"，单次不到 1 秒，且能看到 onefile
  引导进程刚建立的那一瞬间（不会因启动窗口期而重复拉起）。

为什么宿主是 wscript 而不是 PowerShell / cmd：
- powershell.exe 与 cmd.exe 都是**控制台子系统**程序，即使加 -WindowStyle
  Hidden，任务计划启动时仍会先创建控制台再隐藏，导致每分钟闪一次黑窗。
- wscript.exe 是**GUI 子系统**宿主（PE Subsystem=2），执行 VBScript 时
  根本不会创建控制台；被拉起的本程序也是 GUI 子系统，因此全链路零窗口。
- 脚本由本模块在安装时落盘到 <程序目录>\scripts\aote_watchdog.vbs，
  内容刻意保持纯 ASCII（wscript 对非 BOM 文件按 ANSI 解析，含中文会乱码），
  脚本只读不写，审计记录一律由主程序（Python，UTF-8）落笔，编码口径统一。
- 策略（是否允许拉起、是否尊重授权退出）由主程序写进 guardian_state.json，
  脚本只做子串判断，不解析 YAML，两者不会出现配置口径不一致。

设计约束：
- 一律不申请管理员权限（计划任务创建于当前用户，schtasks 无需提权）
- 所有状态与审计文件都放在程序目录（部署后即 %LOCALAPPDATA%\AOTE），便于查看
"""
import ctypes
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Tuple

# 与 main.py 的单实例互斥体同名：判断"是否已有实例在跑"必须用同一个名字
MUTEX_NAME = "Local\\AOTE_Guardian_SingleInstance"

# 计划任务名
# 只用一个"周期守护"任务：它既是防关停，也顺带承担登录后拉起
# （登录后 1 分钟内必然执行一次）。登录时的"立即启动"由 HKCU Run 键负责。
# 注：/SC ONLOGON 在多数非管理员上下文会返回"拒绝访问"，故不采用。
TASK_WATCHDOG = "AOTE_Guardian_Watchdog"  # 周期检查并拉起（防关停 + 登录兜底）
TASK_LOGON = "AOTE_Guardian_Logon"        # 历史版本遗留任务名，仅用于清理

# 回退用的注册表自启项（与旧版本保持一致，便于平滑升级）
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "AOTE_Guardian"

STATE_FILE = "guardian_state.json"
AUDIT_FILE = "guardian_audit.log"
WATCHDOG_SCRIPT = "scripts/aote_watchdog.vbs"
# 历史遗留：早期版本用的是 PowerShell 版（会闪控制台窗口），安装时顺手清理
WATCHDOG_SCRIPT_LEGACY = "scripts/aote_watchdog.ps1"

# subprocess 静默标志（避免计划任务/守护检查时闪出控制台窗口）
_CREATE_NO_WINDOW = 0x08000000
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_ERROR_ALREADY_EXISTS = 183

# 两次拉起的最大间隔保护（秒）：防止计划任务/人工连续触发导致重复启动
_SPAWN_COOLDOWN_SECONDS = 30

# 轻量守护脚本（安装计划任务时落盘到 <程序目录>\scripts\aote_watchdog.vbs）
# 单次不到 1 秒：只查进程 + 必要时拉起；由 wscript.exe（GUI 宿主）执行，零窗口。
# 内容刻意保持纯 ASCII：wscript 对非 BOM 文件按 ANSI 解析，写中文会乱码；
# 审计记录一律由主程序（Python，UTF-8）负责，脚本只读不写。
WATCHDOG_VBS = r'''Option Explicit
' AOTE lightweight process watchdog (kept ASCII-only on purpose: wscript
' parses non-BOM script files as ANSI, so non-ASCII text would be garbled).
' Run by Windows Task Scheduler every N minutes. No console window is ever
' created: wscript.exe is a GUI-subsystem host (PE Subsystem=2), and the
' application it launches is GUI-subsystem too.
' The script only READS state and never writes files: all audit lines are
' written by the main application, keeping one single text encoding.

Dim fso, shell, scriptPath, appDir, exePath, stateFile
Dim running, raw, lowered, ts, wmi, procs, p

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

' <App>\scripts\aote_watchdog.vbs  ->  <App>
scriptPath = WScript.ScriptFullName
appDir = fso.GetParentFolderName(fso.GetParentFolderName(scriptPath))
exePath = fso.BuildPath(appDir, "AOTE.exe")
stateFile = fso.BuildPath(appDir, "guardian_state.json")

' Target missing (moved/uninstalled but the task survived): exit quietly
If Not fso.FileExists(exePath) Then WScript.Quit 0

' ---- 1) already running? match by full executable path ----
' A full-path match avoids mistaking another copy for this one, and it sees the
' onefile bootloader process the very moment it appears, so the startup window
' can never cause a duplicate launch.
running = False
On Error Resume Next
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set procs = wmi.ExecQuery("SELECT ExecutablePath FROM Win32_Process WHERE Name='AOTE.exe'")
If Err.Number = 0 Then
  For Each p In procs
    If Not IsNull(p.ExecutablePath) Then
      If LCase(p.ExecutablePath) = LCase(exePath) Then
        running = True
        Exit For
      End If
    End If
  Next
Else
  ' WMI unavailable: fall back to process-name match (prefer skipping a
  ' restart over launching a duplicate)
  Err.Clear
  Set procs = wmi.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE Name='AOTE.exe'")
  If Err.Number = 0 Then
    If procs.Count > 0 Then running = True
  End If
End If
Err.Clear
On Error GoTo 0

If running Then WScript.Quit 0

' ---- 2) policy from guardian_state.json (substring test; spaces stripped) ----
If fso.FileExists(stateFile) Then
  On Error Resume Next
  Set ts = fso.OpenTextFile(stateFile, 1)
  raw = ts.ReadAll
  ts.Close
  Err.Clear
  On Error GoTo 0
  lowered = LCase(Replace(raw, " ", ""))
  ' Authorized exit (admin password / hotkey): never auto restart
  If InStr(lowered, """authorized_exit"":true") > 0 Then WScript.Quit 0
  ' Restart disabled by configuration
  If InStr(lowered, """restart_on_unexpected_exit"":false") > 0 Then WScript.Quit 0
End If

' ---- 3) start the application hidden and do not wait ----
shell.Run """" & exePath & """", 0, False
WScript.Quit 0
'''


def base_dir() -> Path:
    """程序目录：冻结时取 exe 所在目录，否则取项目根目录（与 main.py 一致）"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _state_path() -> Path:
    return base_dir() / STATE_FILE


def _audit_path() -> Path:
    return base_dir() / AUDIT_FILE


# ======================================================
# 审计日志
# ======================================================
def audit(message: str) -> None:
    """写入守护审计日志（失败静默，绝不影响主流程）。"""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(_audit_path(), "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
            f.flush()
    except Exception:
        pass


# ======================================================
# 状态文件（跨进程共享：主程序写、守护读）
# ======================================================
def read_state() -> dict:
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_state(**kwargs) -> None:
    """合并写入状态字段（读-改-写，失败静默）。"""
    try:
        state = read_state()
        state.update(kwargs)
        tmp = _state_path().with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.replace(tmp, _state_path())
    except Exception:
        pass


# ======================================================
# 进程存活检测
# ======================================================
def is_running() -> bool:
    """是否已有 AOTE 主进程在运行（基于命名互斥体，进程崩溃时由系统自动释放）。

    注意：本函数创建同名互斥体后立即关闭句柄，不长期持有，
    否则会反过来把主程序的单实例判定挤掉。
    """
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        ctypes.set_last_error(0)
        handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        err = ctypes.get_last_error()
        if handle:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
        return err == _ERROR_ALREADY_EXISTS
    except Exception:
        # 探测失败时保守认为"在运行"，避免误拉起第二个实例
        return True


# ======================================================
# 授权退出标记（主程序调用）
# ======================================================
def mark_started(restart: bool = True, respect_authorized_exit: bool = True) -> None:
    """主程序启动完成：清除授权退出标记，登记本次运行。

    同时把守护策略写进状态文件：轻量守护脚本据此判断"要不要拉起"，
    避免脚本再去解析 config.yaml（口径只有一处，不会不一致）。

    另外这里顺带做"异常终止"审计：上一次状态若是"运行中"且未标记授权退出，
    说明进程是被强杀或崩溃掉的——这条记录由主程序自己落笔（UTF-8），
    守护脚本只读不写，因此审计日志的编码口径始终统一。
    """
    prev = read_state()
    abnormal = bool(prev.get("running")) and not bool(prev.get("authorized_exit"))
    if abnormal:
        audit("检测到上次运行被非授权终止（或崩溃），已由守护自动拉起")
    write_state(
        running=True,
        pid=os.getpid(),
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        authorized_exit=False,
        exit_reason="",
        # 键名与 config 中 guardian.* 保持一致，便于对照排查
        restart_on_unexpected_exit=bool(restart),
        respect_authorized_exit=bool(respect_authorized_exit),
    )
    audit(f"主进程启动 PID={os.getpid()}")


def mark_authorized_exit(reason: str) -> None:
    """经由密码/热键授权退出：标记后守护不再自动拉起（直到下次登录）。"""
    write_state(
        running=False,
        authorized_exit=True,
        exit_reason=reason,
        exited_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    audit(f"授权退出（{reason}）：守护将不再自动拉起，下次登录恢复")


# ======================================================
# 拉起主程序
# ======================================================
def _launch_command() -> list:
    """主程序启动命令：冻结时为 exe 本身，源码运行时用 pythonw（无控制台）。"""
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve())]
    pyw = Path(sys.executable).with_name("pythonw.exe")
    python = str(pyw) if pyw.exists() else sys.executable
    return [python, str(base_dir() / "main.py")]


def _launch_command_str(extra: str = "") -> str:
    """计划任务 /TR 使用的命令行字符串（带引号）。"""
    cmd = " ".join(f'"{p}"' for p in _launch_command())
    return f"{cmd} {extra}".strip()


def spawn_main() -> bool:
    """以脱离当前进程的方式拉起主程序（无窗口）。成功返回 True。"""
    try:
        flags = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
        subprocess.Popen(
            _launch_command() + ["--main"],
            creationflags=flags,
            close_fds=True,
            cwd=str(base_dir()),
        )
        return True
    except Exception as e:
        audit(f"拉起主程序失败: {e}")
        return False


def ensure_running(restart: bool = True,
                   respect_authorized_exit: bool = True) -> Tuple[bool, str]:
    """守护检查入口（供 --ensure-running 调用）。

    返回 (当前是否在运行, 动作说明)：
      already_running   已有实例，未做任何操作
      authorized_exit   上次为授权退出，按策略跳过拉起
      restarted         进程缺失且非授权退出 -> 已拉起并记审计
      spawn_failed      拉起失败
      cooldown          距上次拉起过近，跳过（防重复启动）
    """
    if is_running():
        state = read_state()
        if not state.get("running"):
            write_state(running=True)
        return True, "already_running"

    state = read_state()
    if respect_authorized_exit and state.get("authorized_exit"):
        return False, "authorized_exit"

    if not restart:
        return False, "restart_disabled"

    last = float(state.get("last_spawn_at") or 0)
    if time.time() - last < _SPAWN_COOLDOWN_SECONDS:
        return False, "cooldown"

    # 上一次状态是"运行中"却已消失 -> 判定为非授权终止/崩溃，这是审计的重点
    reason = "进程已消失（未授权终止或崩溃）" if state.get("running") else "进程未在运行"
    audit(f"检测到 AOTE 未在运行（{reason}），执行自动重启")
    write_state(last_spawn_at=time.time(), authorized_exit=False)
    if spawn_main():
        return True, "restarted"
    return False, "spawn_failed"


# ======================================================
# 计划任务（开机自启 + 周期守护）
# ======================================================
def _run_schtasks(args: list, timeout: float = 15.0) -> Tuple[int, str]:
    """执行 schtasks（无窗口），返回 (returncode, 输出)。"""
    try:
        proc = subprocess.run(
            ["schtasks"] + args,
            capture_output=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
        out = (proc.stdout or b"").decode("utf-8", "replace").strip()
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        return proc.returncode, (out or err)
    except Exception as e:
        return -1, str(e)


def ensure_watchdog_script() -> str:
    """把轻量守护脚本落盘（内容有变化才重写），返回脚本路径；失败返回空串。

    由程序自己生成而不是依赖打包附带：即使只拷贝了 exe，也能拿到轻量守护路径，
    不会悄悄退化成"每分钟重新解压一次 60MB exe"的重方案。
    """
    try:
        path = base_dir() / WATCHDOG_SCRIPT
        path.parent.mkdir(parents=True, exist_ok=True)
        # 纯 ASCII 写盘：wscript 对非 BOM 的 .vbs 按 ANSI 解析，
        # 一旦混入中文就会乱码（encode("ascii") 失败即视为配置错误，
        # 此时返回空串由调用方回退到 exe 自检，保证不会静默失效）。
        expected = WATCHDOG_VBS.encode("ascii")
        need_write = True
        if path.exists():
            try:
                need_write = path.read_bytes() != expected
            except Exception:
                need_write = True
        if need_write:
            path.write_bytes(expected)
        # 清理早期 PowerShell 版本（会闪控制台窗口，避免残留被误用）
        legacy = base_dir() / WATCHDOG_SCRIPT_LEGACY
        if legacy.exists():
            try:
                legacy.unlink()
            except Exception:
                pass
        return str(path)
    except Exception as e:
        audit(f"守护脚本落盘失败: {e}")
        return ""


def _wscript_path() -> str:
    """wscript.exe 的绝对路径（GUI 宿主，执行脚本时不创建控制台）。

    取不到时返回空串，由调用方回退到 exe 自检——绝不回退到 powershell/cmd，
    那两个是控制台程序，会闪黑窗，正是本次要消除的问题。
    """
    try:
        root = os.environ.get("SystemRoot") or r"C:\Windows"
        for rel in ("System32", "SysWOW64"):
            candidate = Path(root) / rel / "wscript.exe"
            if candidate.exists():
                return str(candidate)
    except Exception:
        pass
    return ""


def _exe_path() -> str:
    """主程序可执行文件路径（冻结=exe 本身；源码运行=pythonw），供守护脚本比对进程。"""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    return _launch_command()[0]


def _watchdog_command() -> str:
    """守护计划任务 /TR 命令行：wscript 跑轻量 VBS；不可用时回退 exe 自检。

    - wscript.exe 是 GUI 子系统宿主，全程不创建控制台，因此每分钟执行
      也不会有任何窗口闪现（powershell.exe / cmd.exe 做不到这一点）。
    - 命令很短（约 110 字符），远低于 schtasks 对 /TR 的 261 字符上限；
      脚本目录由脚本自身按 WScript.ScriptFullName 推导，无需传参。
    """
    script = ensure_watchdog_script()
    wscript = _wscript_path()
    if script and wscript:
        cmd = f'"{wscript}" //B //Nologo "{script}"'
        if len(cmd) <= 261:
            return cmd
    return _launch_command_str("--ensure-running")


def install_tasks(interval_minutes: int = 1) -> Tuple[bool, str]:
    """注册周期守护计划任务（当前用户、无需提权）。返回 (是否成功, 说明)。

    任务执行的是轻量守护脚本（单次约 1 秒），而不是重新调用本 exe——
    后者会因 onefile 解压产生 30~50 秒/次的开销。
    """
    interval = max(int(interval_minutes), 1)
    if not getattr(sys, "frozen", False):
        # 守护任务只在打包运行（AOTE.exe）时注册：源码模式下进程是 pythonw，
        # 既无法按 exe 全路径精确匹配（会误判其他 python 进程），
        # 也不适合作为交付形态。源码模式请直接运行程序。
        return False, "源码运行模式不注册守护任务，请用打包后的 AOTE.exe 安装"
    watch_cmd = _watchdog_command()
    rc, out = _run_schtasks(["/Create", "/TN", TASK_WATCHDOG, "/SC", "MINUTE",
                             "/MO", str(interval), "/TR", watch_cmd, "/F"])
    if rc == 0:
        mode = "轻量守护脚本" if WATCHDOG_SCRIPT.split("/")[-1] in watch_cmd else "exe 自检（回退）"
        return True, f"守护任务已注册（{mode}，每 {interval} 分钟检查一次）"
    return False, f"watchdog=(rc={rc}) {out}"


def remove_tasks() -> Tuple[bool, str]:
    """移除守护任务（连同历史遗留的登录任务名一起清理）。"""
    ok = True
    detail = []
    for name in (TASK_WATCHDOG, TASK_LOGON):
        rc, out = _run_schtasks(["/Delete", "/TN", name, "/F"])
        if rc != 0 and "找不到" not in out and "cannot find" not in out.lower():
            ok = False
            detail.append(f"{name}: {out}")
    return ok, "; ".join(detail) or "计划任务已移除"


def tasks_status() -> dict:
    """查询守护任务是否已注册。"""
    rc, _ = _run_schtasks(["/Query", "/TN", TASK_WATCHDOG])
    return {TASK_WATCHDOG: (rc == 0)}


# ======================================================
# HKCU Run 键（计划任务不可用时的回退方案）
# ======================================================
def _write_run_value() -> bool:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ,
                              _launch_command_str())
        return True
    except Exception:
        return False


def _remove_run_value() -> bool:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, RUN_VALUE)
            except FileNotFoundError:
                pass
        return True
    except Exception:
        return False


def run_value_present() -> bool:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_QUERY_VALUE) as key:
            winreg.QueryValueEx(key, RUN_VALUE)
            return True
    except Exception:
        return False


# ======================================================
# 对外统一入口（main.py 的 --install-autostart 等参数使用）
# ======================================================
def install_autostart(interval_minutes: int = 1) -> Tuple[bool, str]:
    """安装开机自启与防关停，双通道（都无需管理员权限）：

      1. HKCU Run 键     —— 登录后立即启动（旧版本沿用，平滑升级）
      2. 周期守护计划任务 —— 每 N 分钟检查，进程缺失即拉起（防关停 + 登录兜底）

    两者互为补充：Run 键负责"立刻起来"，计划任务负责"起不来就再拉"。
    同时存在不会造成多实例（main.py 有命名互斥体单实例保护）。
    """
    run_ok = _write_run_value()
    task_ok, task_detail = install_tasks(interval_minutes)
    audit(f"开机自启安装：Run键={run_ok} 守护任务={task_ok}（{task_detail}）")
    if run_ok or task_ok:
        parts = []
        if run_ok:
            parts.append("HKCU Run 键（登录即启动）")
        if task_ok:
            parts.append(task_detail)
        return True, "；".join(parts)
    return False, f"Run 键与守护任务均失败: {task_detail}"


def remove_autostart() -> bool:
    """移除开机自启（守护任务 + Run 键都清掉）。"""
    ok, _ = remove_tasks()
    ok = _remove_run_value() and ok
    audit("开机自启已移除")
    return ok


def autostart_status() -> dict:
    """返回自启状态详情，便于 --autostart-status 打印与排障。"""
    tasks = tasks_status()
    run = run_value_present()
    return {
        "tasks": tasks,
        "run_value": run,
        "enabled": any(tasks.values()) or run,
    }
