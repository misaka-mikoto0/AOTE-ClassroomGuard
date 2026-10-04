
"""
AOTE 管控系统 - 主程序入口（纯浏览器内容管控架构）

管控方式：通过 Playwright 在 CDP 接管的浏览器实例内进行内容管控
（路由拦截、JS 注入、响应捕获、CDP 报文级操作）。

进程层面只做三件"可见、可审计"的事（见 aote/guardian.py）：
- 单实例保护：命名互斥体，避免多实例竞争 CDP 端口
- 防关停：计划任务按周期调用 --ensure-running，被非授权终止后自动拉起
- 授权退出：密码/热键退出后写入标记，守护不再自动拉起（直到下次登录）
不包含任何隐藏进程、冻结进程或内核级手段；进程在任务管理器中始终可见。

命令行参数：
  --main / --daemon        以主进程模式启动（默认）
  --ensure-running         守护检查：已在运行则静默退出，否则拉起主程序
  --install-autostart      设置开机自启（计划任务，失败回退 HKCU Run）
  --remove-autostart       取消开机自启
  --autostart-status       查询开机自启状态
"""
import os
import sys
import time
import signal
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# 程序根目录：PyInstaller 冻结时取 exe 所在目录，否则取项目根目录
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent
# 将项目根目录加入 path
sys.path.insert(0, str(BASE_DIR))

try:
    import winreg
except ImportError:  # 非 Windows 平台：自启动相关功能不可用
    winreg = None

# === 安全加固：boot_trace（仅写文件，不重定向stdout/stderr，不干扰AOTELogger）===
_BOOT_TRACE = os.path.join(BASE_DIR, "boot_trace.log")
_CRASH_LOG = os.path.join(BASE_DIR, "crash.log")


def boot_trace(msg: str):
    """启动关键路径轻量追踪（文件 IO 成功/失败都静默）"""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(_BOOT_TRACE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] PID={os.getpid()} exe={os.path.basename(sys.executable)} argv={str(sys.argv[1:])} | {msg}\n")
            f.flush()
    except Exception:
        pass


try:
    boot_trace("ENTRY")
except Exception:
    pass


def _write_crash(exc_type, exc_value, exc_tb):
    try:
        with open(_CRASH_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] UNCAUGHT EXCEPTION:\n")
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception:
        pass


sys.excepthook = _write_crash
try:
    threading.excepthook = lambda args: _write_crash(args.exc_type, args.exc_value, args.exc_traceback)
except Exception:
    pass

# 控制台 UTF-8 输出（Windows GBK 控制台打印 emoji 会 UnicodeEncodeError 崩溃）
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from aote.config import ConfigManager
from aote.logger import AOTELogger
from aote.time_guard import TimeGuard
from aote.usb_guard import USBGuard, USBModeSelector
from aote.anti_tamper import AntiTamper
from aote.http_server import AOTEHTTPServer
from aote.system_tray import SystemTray
from aote import guardian
from aote.browser_sandbox import (
    BrowserSandbox,
    MODE_RELAXED,
    MODE_STRICT,
)

# 定时解锁模式的内置兜底时长（配置中未配置或无效时使用）
_FALLBACK_UNLOCK_SECONDS = {"30分钟": 1800, "1小时": 3600, "2小时": 7200}


# ======================================================
# Guardian 主类（单进程：主控 + 浏览器沙盒）
# ======================================================
class GuardianApp:
    """主控应用（浏览器内容管控 Orchestrator）"""

    def __init__(self):
        # 核心组件
        self.config: Optional[ConfigManager] = None
        self.logger: Optional[AOTELogger] = None
        self.time_guard: Optional[TimeGuard] = None
        self.usb_guard: Optional[USBGuard] = None
        self.anti_tamper: Optional[AntiTamper] = None
        self.http_server: Optional[AOTEHTTPServer] = None
        self.system_tray: Optional[SystemTray] = None
        self.browser_sandbox: Optional[BrowserSandbox] = None

        # 控制
        self._shutdown = threading.Event()

    # ============ 初始化 ============
    def init(self):
        self._init_config_and_logger()
        self._init_guard_components()
        self._init_tray_and_hotkey()

    def _init_config_and_logger(self):
        """初始化配置、日志与时间调度（其余组件依赖它们）"""
        self.config = ConfigManager()
        log_cfg = self.config.get("logging", {})
        self.logger = AOTELogger(
            log_path=log_cfg.get("path", r"C:\ProgramData\ClassroomGuard\logs"),
            retention_days=log_cfg.get("retention_days", 30),
            rotate_when=self.config.get("time_settings.log_rotate_when", "midnight")
        )
        self.logger.info("=" * 60)
        self.logger.info("🚀 AOTE 一体机管控系统 启动（纯浏览器内容管控）")
        self.logger.info(f"   PID: {os.getpid()}")
        self.logger.info("=" * 60)

        # 时间调度
        self.time_guard = TimeGuard(self.config, self.logger)
        self.time_guard.set_on_mode_change(self._on_mode_change)

    def _init_guard_components(self):
        """初始化浏览器沙盒与各管控组件（按依赖顺序注入回调）"""
        # 浏览器控制沙盒（Playwright）：浏览器内容管控核心
        if self.config.get("browser_sandbox.enabled", False):
            self.browser_sandbox = BrowserSandbox(self.config, self.logger)
            self.browser_sandbox.set_on_violation(self._on_browser_violation)
        else:
            self.logger.warning("[Sandbox] 已按配置禁用（browser_sandbox.enabled=false），浏览器内容管控不可用")

        # 防绕过（浏览器沙盒心跳监控 + 管理员密码验证；无任何进程操作）
        self.anti_tamper = AntiTamper(self.config, self.logger, self.time_guard)
        self.anti_tamper.set_browser_sandbox(self.browser_sandbox)
        self.anti_tamper.set_on_emergency_exit(self._emergency_exit)
        self.anti_tamper.set_on_sandbox_heartbeat_lost(self._on_sandbox_heartbeat_lost)

        # HTTP服务（浏览器内容上报）
        self.http_server = AOTEHTTPServer(self.config, self.logger, self.browser_sandbox)
        self.http_server.set_on_violation(self._on_browser_violation)

        # U盘授权
        self.usb_guard = USBGuard(self.config, self.logger)
        self.usb_guard.set_on_authorized_usb(self._on_authorized_usb)
        self.usb_guard.set_on_eject_unplug(self._on_eject_unplug)
        self.usb_guard.set_admin_verifier(self.anti_tamper.verify_admin_password)

    def _init_tray_and_hotkey(self):
        """初始化系统托盘与紧急热键"""
        self.system_tray = SystemTray(
            self.config, self.logger, self.time_guard, self.browser_sandbox
        )
        self.system_tray.on_emergency_exit_request = self._tray_emergency_exit

        # 注册紧急热键 Ctrl+Shift+Alt+G
        self._register_hotkey()

    # ============ 热键 ============
    def _register_hotkey(self):
        """Ctrl+Shift+Alt+G 紧急退出热键"""
        try:
            import keyboard

            def _on_hotkey():
                self.logger.warning("[Hotkey] 收到紧急退出快捷键 Ctrl+Shift+Alt+G")
                self._tray_emergency_exit()

            hotkey = self.config.get("emergency.hotkey", "ctrl+shift+alt+g")
            keyboard.add_hotkey(hotkey, _on_hotkey, suppress=False)
            self.logger.info(f"[Hotkey] 已注册紧急退出热键: {hotkey}")
        except Exception as e:
            self.logger.debug(f"热键注册失败（可选功能）: {e}")

    # ============ 模式变更回调 ============
    def _on_mode_change(self, old_mode: str, new_mode: str):
        """时间守卫模式切换 -> 同步浏览器沙盒管控模式"""
        if self.browser_sandbox is None:
            return
        try:
            if new_mode == TimeGuard.MODE_EXEMPT:
                # 豁免时间段：所有限制暂停（沙盒内部走"等同解锁"通道）
                self.browser_sandbox.set_exempt(True)
            elif new_mode == TimeGuard.MODE_RELAXED:
                # 上课时间：宽松放行（先退出豁免态，避免豁免与课表互相覆盖）
                self.browser_sandbox.set_exempt(False)
                self.browser_sandbox.set_control_mode(MODE_RELAXED)
            else:
                # 严格模式 / 紧急模式：退出豁免态并立即恢复严格管控
                self.browser_sandbox.set_exempt(False)
                self.browser_sandbox.restore_strict_mode()
        except Exception as e:
            self.logger.error(f"[Main] 模式切换同步沙盒失败: {e}")

    # ============ 浏览器内容违规回调 ============
    def _on_browser_violation(self, url: str, reason: str, level: int = 1):
        """浏览器内检测到违禁内容 -> 记录违规日志并确认弱网已切换。
        黑名单命中后沙盒已自动切换弱网；用户可按热键（密码验证）豁免。"""
        self.logger.warning(f"[管控] 浏览器违规: {url} reason={reason} level={level}")
        if self.browser_sandbox is None:
            return
        self.logger.log_browser_intercept(url, reason, self.browser_sandbox.current_mode())
        wn = self.browser_sandbox.weak_network_status()
        if wn.get("active"):
            self.logger.warning(
                f"[管控] 已自动切换弱网: {wn.get('host')} "
                f"(延迟 {wn.get('latency_ms')}ms / "
                f"下载 {wn.get('download_kbps')}KB/s / "
                f"上传 {wn.get('upload_kbps')}KB/s)"
            )

    # ============ U盘回调 ============
    def _timer_seconds_for(self, mode: str) -> int:
        """解析定时解锁模式的时长（秒）：优先取配置，未配置或无效则回退内置映射。"""
        seconds = 0
        for m in self.config.get("unlock_modes") or []:
            if m.get("name") == mode and m.get("type") == "timer":
                seconds = m.get("seconds", 1800)
                break
        if not isinstance(seconds, (int, float)) or seconds <= 0:
            return _FALLBACK_UNLOCK_SECONDS.get(mode, 1800)
        return int(seconds)

    def _on_authorized_usb(self) -> Optional[str]:
        """U盘认证成功 -> 弹出模式选择窗口 -> 对浏览器沙盒执行对应解锁"""
        selector = USBModeSelector(self.config, self.logger)
        # 注入与AntiTamper一致的密码校验器
        selector._verify_admin_callback = self.anti_tamper.verify_admin_password
        mode = selector.show_and_wait()
        if not mode:
            return None

        self.logger.log_usb_event("authorized_mode_selected", drive_letter="", is_authorized=True)
        if self.browser_sandbox is None:
            self.logger.error("[USB] 浏览器沙盒不可用，无法执行解锁")
            return mode

        # 根据解锁模式执行（全部作用于浏览器沙盒）
        if mode == "即拔即禁":
            self.browser_sandbox.permanent_unlock()
            self.logger.info("[USB] 已进入「即拔即禁」模式，U盘拔出后自动恢复")
        elif mode == "永久解锁（维护模式）":
            self.browser_sandbox.permanent_unlock()
            self.logger.info("[USB] 已进入维护模式（永久解锁）")
        else:
            # 定时模式
            seconds = self._timer_seconds_for(mode)
            self.browser_sandbox.temporary_unlock(seconds)
            self.logger.info(f"[USB] 定时解锁模式: {mode} ({seconds}秒)")

        return mode

    def _on_eject_unplug(self):
        """即拔即禁U盘已拔出"""
        self.logger.warning("[USB] 即拔即禁U盘已拔出，恢复严格模式")
        if self.browser_sandbox is not None:
            self.browser_sandbox.restore_strict_mode()
        # 如果是宽松模式外的时间，强制切回严格模式
        # 豁免时间段（含"上课时间视为豁免"）不在此处打断：由 TimeGuard 统一调度，
        # 否则 U盘拔出这一瞬间会泄漏一段受限状态出来
        if not (self.time_guard.is_relaxed_mode or self.time_guard.is_exempt_mode):
            if hasattr(self.time_guard, "_emergency_forced"):
                self.time_guard._emergency_forced = False
            self.time_guard._set_mode(TimeGuard.MODE_STRICT, "usb_ejected")

    # ============ 托盘/热键 退出 ============
    def _tray_emergency_exit(self):
        """通过托盘/热键触发紧急退出或临时解锁"""
        if self.anti_tamper:
            should_exit, unlock_seconds = self.anti_tamper.show_emergency_exit_dialog()
            if should_exit:
                self.logger.log_admin_action("emergency_exit", True)
                self._emergency_exit()
            elif unlock_seconds > 0:
                self.logger.log_admin_action("temporary_unlock", True)
                if self.browser_sandbox is not None:
                    self.browser_sandbox.temporary_unlock(unlock_seconds)

    def _emergency_exit(self):
        """实际执行退出操作（授权退出：写标记后守护不再自动拉起）"""
        self.logger.warning("⚠ 执行系统紧急退出")
        try:
            # 先写授权退出标记，再关停：否则守护会把这次退出判定为"被强杀"而拉起
            guardian.mark_authorized_exit("password_hotkey")
        except Exception:
            pass
        try:
            self.stop()
        except Exception:
            pass
        self.logger.info("👋 系统已完全退出")
        os._exit(0)

    def _on_sandbox_heartbeat_lost(self):
        """浏览器沙盒心跳丢失：尝试重启沙盒"""
        self.logger.warning("[Main] 浏览器沙盒心跳丢失，尝试重启...")
        if self.browser_sandbox is None:
            return
        try:
            self.browser_sandbox.stop()
        except Exception:
            pass
        try:
            self.browser_sandbox.start()
        except Exception as e:
            self.logger.error(f"[Main] 浏览器沙盒重启失败: {e}")

    # ============ 启动/运行/停止 ============
    def start_components(self):
        """启动所有子组件。

        各组件独立容错：任一组件启动失败只记录错误并跳过，不影响其余组件，
        避免单点故障（如托盘不可用、HTTP 端口被占用）拖垮整个管控进程。
        """
        for name, component in (
            ("TimeGuard", self.time_guard),
            ("AntiTamper", self.anti_tamper),
            ("HTTPServer", self.http_server),
            ("USBGuard", self.usb_guard),
            ("SystemTray", self.system_tray),
        ):
            self._start_component(name, component)
        # 浏览器控制沙盒（CDP 接管外部浏览器）；失败不影响主控核心功能
        if self.browser_sandbox is not None:
            self._start_browser_sandbox()
        else:
            self.logger.warning("[Main] 浏览器沙盒不可用，浏览器内容管控未启用")

    def _start_component(self, name: str, component) -> bool:
        """启动单个组件；失败只记录日志并返回 False，不向上抛异常。"""
        if component is None:
            self.logger.warning(f"[Main] 组件 {name} 未初始化，跳过启动")
            return False
        try:
            component.start()
            return True
        except Exception as e:
            self.logger.error(f"[Main] 组件 {name} 启动失败（已跳过）: {e}")
            return False

    def _start_browser_sandbox(self):
        """启动浏览器沙盒并按当前时间模式同步管控强度"""
        try:
            self.browser_sandbox.start()
            # 启动后按时间守卫当前模式同步管控（豁免窗口优先）
            if self.time_guard.is_exempt_mode:
                self.browser_sandbox.set_exempt(True)
            elif self.time_guard.is_relaxed_mode:
                self.browser_sandbox.set_control_mode(MODE_RELAXED)
            else:
                self.browser_sandbox.restore_strict_mode()
        except Exception as e:
            self.logger.error(f"[Sandbox] 启动异常（已跳过）: {e}")

    def run(self):
        """阻塞运行直到退出"""
        self.start_components()
        self.logger.info("[主进程] 所有组件已就绪，进入主循环")
        try:
            interval = float(self.config.get("time_settings.main_loop_interval", 1))
            while not self._shutdown.is_set():
                time.sleep(max(interval, 0.1))
        except KeyboardInterrupt:
            self.logger.warning("收到键盘中断，准备退出")
        finally:
            self.stop()

    def stop(self):
        """停止所有组件并清理"""
        self.logger.info("🛑 正在关闭系统...")
        try:
            # 先关闭浏览器沙盒（CDP 模式仅断开连接，外部浏览器保持运行）
            if self.browser_sandbox:
                try:
                    self.browser_sandbox.stop()
                except Exception as e:
                    self.logger.debug(f"[Sandbox] 关闭异常: {e}")
            if self.system_tray: self.system_tray.stop()
            if self.usb_guard: self.usb_guard.stop()
            if self.http_server: self.http_server.stop()
            if self.anti_tamper: self.anti_tamper.stop()
            if self.time_guard: self.time_guard.stop()
            if self.config: self.config.stop_hot_reload()
        except Exception as e:
            self.logger.error(f"关闭组件异常: {e}")
        self.logger.info("👋 AOTE 系统已完全退出")
        self.logger.info("")


# ======================================================
# 开机自启动
# 实现已统一收敛到 aote/guardian.py：优先计划任务（登录启动 + 周期守护），
# 计划任务不可用时回退 HKCU Run 键。此处保留同名函数作为对外接口，
# 避免其他地方（托盘/脚本）引用的函数名失效。
# ======================================================
AUTOSTART_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "AOTE_Guardian"


def _current_launch_command() -> str:
    """当前程序的自启动命令：
    - 冻结（exe）：直接指向 exe 本身
    - 源码：pythonw main.py（隐藏控制台窗口）
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if os.path.exists(pyw):
        return f'"{pyw}" "{os.path.join(BASE_DIR, "main.py")}"'
    return f'"{sys.executable}" "{os.path.join(BASE_DIR, "main.py")}"'


def _open_run_key(access: int):
    """打开开机自启动注册表项句柄（HKCU\\...\\Run）"""
    return winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_KEY, 0, access)


def install_autostart() -> bool:
    """设置开机自启：优先计划任务（登录启动 + 周期守护），失败回退 Run 键。"""
    ok, detail = guardian.install_autostart(
        guardian_interval_minutes()
    )
    print(f"{'✅ 开机自启已设置' if ok else '❌ 开机自启设置失败'}：{detail}")
    return ok


def remove_autostart() -> bool:
    """取消开机自启（计划任务与 Run 键一并清理）。"""
    ok = guardian.remove_autostart()
    print("✅ 开机自启已取消" if ok else "❌ 开机自启取消失败")
    return ok


def autostart_status() -> bool:
    """检查开机自启是否已启用（计划任务或 Run 键任一在册即视为启用）。"""
    status = guardian.autostart_status()
    tasks = status["tasks"]
    print("开机自启状态：")
    for name, enabled in tasks.items():
        print(f"  - 计划任务 {name}: {'已注册' if enabled else '未注册'}")
    print(f"  - 注册表 Run 键 {AUTOSTART_NAME}: "
          f"{'已写入' if status['run_value'] else '未写入'}")
    print(f"总体：{'✅ 已启用' if status['enabled'] else '❌ 未启用'}")
    return status["enabled"]


def guardian_interval_minutes() -> int:
    """守护检查周期（分钟）——从配置读取，配置不可用时取默认 1 分钟。"""
    try:
        cfg = ConfigManager()
        return max(int(cfg.get("guardian.watchdog_interval_minutes", 1)), 1)
    except Exception:
        return 1


# ======================================================
# 单实例保护
# ======================================================
_SINGLE_INSTANCE_HANDLE = None


def _acquire_single_instance() -> bool:
    """确保同一用户会话内只有一个 AOTE 实例。

    多实例会导致 CDP 端口竞争、watchdog 重复接管同一浏览器、日志交错错乱。
    这里用内核命名互斥体：由系统持有，进程崩溃时自动释放，
    不会像文件锁那样留下需要手工清理的死锁。

    非 Windows 平台或创建失败时返回 True（降级为允许多实例，不阻塞启动）。
    """
    global _SINGLE_INSTANCE_HANDLE
    try:
        import ctypes
        from ctypes import wintypes

        # Local\\ 前缀：仅当前用户会话可见，避免跨用户会话误判
        mutex_name = "Local\\AOTE_Guardian_SingleInstance"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, ctypes.c_wchar_p]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        handle = kernel32.CreateMutexW(None, False, mutex_name)
        if not handle:
            return True
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            ctypes.windll.kernel32.CloseHandle(handle)
            return False
        # 持有句柄直到进程退出
        _SINGLE_INSTANCE_HANDLE = handle
        return True
    except Exception:
        return True


# ======================================================
# 主入口
# ======================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="AOTE 实力主义至上一体机管控系统")
    parser.add_argument("--main", action="store_true", help="以主进程模式启动（默认）")
    parser.add_argument("--daemon", action="store_true", help="后台模式（等同 --main）")
    parser.add_argument("--ensure-running", action="store_true",
                        help="守护检查：已在运行则静默退出，否则拉起主程序")
    parser.add_argument("--install-autostart", action="store_true", help="设置开机自启动")
    parser.add_argument("--remove-autostart", action="store_true", help="取消开机自启动")
    parser.add_argument("--autostart-status", action="store_true", help="查询开机自启动状态")
    args = parser.parse_args()

    # ---- 守护检查（计划任务周期调用；无窗口、静默）----
    if args.ensure_running:
        boot_trace("ensure-running")
        try:
            cfg = ConfigManager()
            enabled = bool(cfg.get("guardian.enabled", True))
            restart = enabled and bool(
                cfg.get("guardian.restart_on_unexpected_exit", True))
            respect = bool(cfg.get("guardian.respect_authorized_exit", True))
        except Exception:
            restart, respect = True, True
        running, action = guardian.ensure_running(
            restart=restart, respect_authorized_exit=respect
        )
        boot_trace(f"ensure-running -> running={running} action={action}")
        return

    if args.install_autostart:
        install_autostart()
        return
    if args.remove_autostart:
        remove_autostart()
        return
    if args.autostart_status:
        autostart_status()
        return

    boot_trace("enter main")
    if not _acquire_single_instance():
        # 已有实例在跑：直接退出，避免多实例竞争同一浏览器与 CDP 端口
        boot_trace("already running - exit")
        print("AOTE 已在运行中（单实例保护），本次启动退出。")
        return

    # 登记本次运行：清除"授权退出"标记，守护重新进入保护状态
    guardian.mark_started()

    app = GuardianApp()
    app.init()

    # 注册 Ctrl+C/SIGTERM
    def _signal_handler(signum, frame):
        print(f"收到信号 {signum}，准备退出")
        app._shutdown.set()
    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except Exception:
        pass
    app.run()


if __name__ == "__main__":
    main()
