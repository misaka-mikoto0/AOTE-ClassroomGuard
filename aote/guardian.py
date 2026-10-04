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

# subprocess 静默标志（避免计划任务/守护检查时闪出控制台窗口）
_CREATE_NO_WINDOW = 0x08000000
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_ERROR_ALREADY_EXISTS = 183

# 两次拉起的最大间隔保护（秒）：防止计划任务/人工连续触发导致重复启动
_SPAWN_COOLDOWN_SECONDS = 30


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
def mark_started() -> None:
    """主程序启动完成：清除授权退出标记，登记本次运行。"""
    write_state(
        running=True,
        pid=os.getpid(),
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        authorized_exit=False,
        exit_reason="",
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


def install_tasks(interval_minutes: int = 1) -> Tuple[bool, str]:
    """注册周期守护计划任务（当前用户、无需提权）。返回 (是否成功, 说明)。"""
    interval = max(int(interval_minutes), 1)
    watch_cmd = _launch_command_str("--ensure-running")
    rc, out = _run_schtasks(["/Create", "/TN", TASK_WATCHDOG, "/SC", "MINUTE",
                             "/MO", str(interval), "/TR", watch_cmd, "/F"])
    if rc == 0:
        return True, f"守护任务已注册（每 {interval} 分钟检查一次）"
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
