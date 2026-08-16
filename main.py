"""
AOTE 管控系统 - 主程序入口
整合所有模块：时间调度、进程监控、数学挑战、U盘授权、防绕过、HTTP服务、系统托盘
支持命令行参数：
  --main       以主进程模式启动（默认，带UI）
  --watchdog   以守护进程模式启动（无UI，监控主进程）
  --daemon     后台运行（无托盘？仍保留托盘）
  --respawn-check  计划任务用：检查主进程是否存在，不在则启动
"""
import os
import sys
import time
import signal
import threading
import subprocess
import argparse
from pathlib import Path
from typing import Optional

# 将项目根目录加入 path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from aote.config import ConfigManager
from aote.logger import AOTELogger
from aote.time_guard import TimeGuard
from aote.process_hunter import ProcessHunter
from aote.math_challenge import MathChallengeWindow
from aote.usb_guard import USBGuard, USBModeSelector
from aote.anti_tamper import AntiTamper
from aote.http_server import AOTEHTTPServer
from aote.system_tray import SystemTray


# ======================================================
# 权限检查
# ======================================================
def is_admin() -> bool:
    """检查是否为管理员权限"""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """如果不是管理员，UAC提升重启"""
    if is_admin():
        return
    try:
        import ctypes
        params = " ".join([f'"{a}"' for a in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)
    except Exception as e:
        print(f"[错误] 本系统必须以管理员权限运行: {e}")
        sys.exit(1)


# ======================================================
# Guardian 主类（主进程）
# ======================================================
class GuardianApp:
    """主控应用（主进程）"""

    def __init__(self):
        # 核心组件
        self.config: Optional[ConfigManager] = None
        self.logger: Optional[AOTELogger] = None
        self.time_guard: Optional[TimeGuard] = None
        self.process_hunter: Optional[ProcessHunter] = None
        self.usb_guard: Optional[USBGuard] = None
        self.anti_tamper: Optional[AntiTamper] = None
        self.http_server: Optional[AOTEHTTPServer] = None
        self.system_tray: Optional[SystemTray] = None

        # 控制
        self._shutdown = threading.Event()
        self._watchdog_pid: Optional[int] = None
        self._math_active_lock = threading.Lock()
        self._math_active = False

    # ============ 初始化 ============
    def init(self):
        # 配置 & 日志
        self.config = ConfigManager()
        log_cfg = self.config.get("logging", {})
        self.logger = AOTELogger(
            log_path=log_cfg.get("path", r"C:\ProgramData\ClassroomGuard\logs"),
            retention_days=log_cfg.get("retention_days", 30)
        )
        self.logger.info("=" * 60)
        self.logger.info("🚀 AOTE 一体机管控系统 启动")
        self.logger.info(f"   PID: {os.getpid()}  |  管理员: {is_admin()}")
        self.logger.info("=" * 60)

        # 时间调度
        self.time_guard = TimeGuard(self.config, self.logger)
        self.time_guard.set_on_mode_change(self._on_mode_change)

        # 进程监控
        self.process_hunter = ProcessHunter(self.config, self.logger, self.time_guard)
        self.process_hunter.set_on_target_detected(self._on_target_process_detected)

        # 防绕过
        self.anti_tamper = AntiTamper(self.config, self.logger, self.time_guard)
        self.anti_tamper.set_on_emergency_exit(self._emergency_exit)
        self.anti_tamper.set_on_force_kill(self._on_force_killed)

        # HTTP服务（扩展通信）
        self.http_server = AOTEHTTPServer(
            self.config, self.logger, self.anti_tamper, self.process_hunter
        )

        # U盘授权
        self.usb_guard = USBGuard(self.config, self.logger, self.process_hunter)
        self.usb_guard.set_on_authorized_usb(self._on_authorized_usb)
        self.usb_guard.set_on_eject_unplug(self._on_eject_unplug)
        self.usb_guard.set_admin_verifier(self.anti_tamper.verify_admin_password)

        # 系统托盘
        self.system_tray = SystemTray(
            self.config, self.logger, self.time_guard, self.process_hunter
        )
        self.system_tray.on_emergency_exit_request = self._tray_emergency_exit
        self.system_tray.on_show_math_challenge = self._show_math_challenge_from_tray

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
        """模式切换时的额外处理"""
        # 紧急模式：立刻清空临时解锁
        if new_mode == TimeGuard.MODE_EMERGENCY:
            self.process_hunter.restore_strict_mode()

    # ============ 进程监控回调 ============
    def _on_target_process_detected(self, new_procs):
        """
        当检测到新的目标进程运行时触发
        -> 弹出数学挑战窗口
        """
        # 宽松模式下不弹数学挑战
        if self.time_guard.is_relaxed_mode:
            return
        # 如果已经有数学窗口显示中，不重复弹
        with self._math_active_lock:
            if self._math_active:
                return
            self._math_active = True

        try:
            self._show_math_challenge_sync(level=1)
        finally:
            with self._math_active_lock:
                self._math_active = False

    def _show_math_challenge_sync(self, level: int = 1):
        """同步显示数学挑战（阻塞直到答对或被关闭）"""
        def _on_success(unlock_seconds: int):
            self.logger.info(f"[Math] 答题成功，临时解锁 {unlock_seconds} 秒")
            self.process_hunter.temporary_unlock(unlock_seconds)

        window = MathChallengeWindow(
            self.config, self.logger, self.process_hunter, _on_success
        )
        window.show_and_wait(level=level)

    def _show_math_challenge_from_tray(self):
        """托盘菜单触发（异步）"""
        threading.Thread(
            target=self._show_math_challenge_sync,
            args=(1,),
            daemon=True,
            name="TrayMathChallenge"
        ).start()

    # ============ U盘回调 ============
    def _on_authorized_usb(self) -> Optional[str]:
        """U盘认证成功 -> 弹出模式选择窗口 -> 执行对应解锁"""
        selector = USBModeSelector(self.config, self.logger, self.process_hunter)
        mode = selector.show_and_wait()
        if not mode:
            return None

        self.logger.log_usb_event("authorized_mode_selected", drive_letter="", is_authorized=True)

        # 根据解锁模式执行
        if mode == "即拔即禁":
            # 永久解锁，等待拔出触发
            self.process_hunter.permanent_unlock()
            self.logger.info("[USB] 已进入「即拔即禁」模式，U盘拔出后自动恢复")
        elif mode == "永久解锁（维护模式）":
            self.process_hunter.permanent_unlock()
            self.logger.info("[USB] 已进入维护模式（永久解锁）")
        else:
            # 定时模式
            modes_cfg = self.config.get("unlock_modes", [])
            seconds = 0
            for m in modes_cfg:
                if m.get("name") == mode and m.get("type") == "timer":
                    seconds = m.get("seconds", 1800)
                    break
            if seconds <= 0:
                # 按模式名解析
                mapping = {"30分钟": 1800, "1小时": 3600, "2小时": 7200}
                seconds = mapping.get(mode, 1800)
            self.process_hunter.temporary_unlock(seconds)
            self.logger.info(f"[USB] 定时解锁模式: {mode} ({seconds}秒)")

        return mode

    def _on_eject_unplug(self):
        """即拔即禁U盘已拔出"""
        self.logger.warning("[USB] 即拔即禁U盘已拔出，恢复严格模式")
        self.process_hunter.restore_strict_mode()
        # 如果是宽松模式外的时间，强制切回严格模式
        if not self.time_guard.is_relaxed_mode:
            if hasattr(self.time_guard, "_emergency_forced"):
                self.time_guard._emergency_forced = False
            self.time_guard._set_mode(TimeGuard.MODE_STRICT, "usb_ejected")

    # ============ 托盘/热键 退出 ============
    def _tray_emergency_exit(self):
        """通过托盘/热键触发紧急退出"""
        if self.anti_tamper and self.anti_tamper.show_emergency_exit_dialog():
            self.logger.log_admin_action("emergency_exit", True)
            self._emergency_exit()

    def _emergency_exit(self):
        """实际执行退出操作"""
        self.logger.warning("⚠ 执行系统紧急退出")
        # 停止 watchdog
        self._kill_watchdog()
        self._shutdown.set()

    def _on_force_killed(self):
        """对方进程被杀并复活的回调"""
        pass  # 复活逻辑在 AntiTamper 内部

    # ============ 双进程守护 ============
    def spawn_watchdog(self) -> Optional[int]:
        """启动守护子进程"""
        try:
            script = os.path.abspath(sys.argv[0])
            if getattr(sys, "frozen", False):
                target = sys.executable
                args = [target, "--watchdog"]
            else:
                target = sys.executable
                args = [target, script, "--watchdog"]

            DETACHED_PROCESS = 0x00000008 if sys.platform == "win32" else 0
            CREATE_NEW_PROCESS_GROUP = 0x00000200 if sys.platform == "win32" else 0
            flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

            proc = subprocess.Popen(
                args, creationflags=flags, close_fds=True
            )
            self._watchdog_pid = proc.pid
            self.logger.info(f"[Watchdog] 已启动守护进程，PID={proc.pid}")
            return proc.pid
        except Exception as e:
            self.logger.error(f"[Watchdog] 启动守护进程失败: {e}")
            return None

    def _kill_watchdog(self):
        """退出时杀掉watchdog子进程"""
        if not self._watchdog_pid:
            return
        try:
            import psutil
            if psutil.pid_exists(self._watchdog_pid):
                psutil.Process(self._watchdog_pid).terminate()
                self.logger.info(f"[Watchdog] 已终止守护进程 PID={self._watchdog_pid}")
        except Exception:
            pass

    # ============ 启动/运行/停止 ============
    def start_components(self):
        """启动所有子组件"""
        self.time_guard.start()
        self.process_hunter.start()
        self.anti_tamper.start()
        self.http_server.start()
        self.usb_guard.start()
        self.system_tray.start()
        # 自启动安装
        try:
            self.anti_tamper.install_autostart()
        except Exception as e:
            self.logger.debug(f"安装自启动失败: {e}")

    def run(self):
        """阻塞运行直到退出"""
        self.start_components()
        # 启动 watchdog 子进程
        wpid = self.spawn_watchdog()
        if self.anti_tamper:
            self.anti_tamper.set_partner_pid(wpid)
            self.anti_tamper.mark_as_watchdog(False)

        self.logger.info("[主进程] 所有组件已就绪，进入主循环")
        # 主循环（替代Tk主循环）
        try:
            while not self._shutdown.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.warning("收到键盘中断，准备退出")
        finally:
            self.stop()

    def stop(self):
        """停止所有组件并清理"""
        self.logger.info("🛑 正在关闭系统...")
        self._kill_watchdog()
        try:
            if self.system_tray: self.system_tray.stop()
            if self.usb_guard: self.usb_guard.stop()
            if self.http_server: self.http_server.stop()
            if self.anti_tamper: self.anti_tamper.stop()
            if self.process_hunter: self.process_hunter.stop()
            if self.time_guard: self.time_guard.stop()
            if self.config: self.config.stop_hot_reload()
        except Exception as e:
            self.logger.error(f"关闭组件异常: {e}")
        self.logger.info("👋 AOTE 系统已完全退出")
        self.logger.info("")


# ======================================================
# Watchdog 守护进程（无UI，纯监控）
# ======================================================
def run_watchdog():
    """独立守护进程入口：监控主进程，死亡则复活"""
    # 初始化最小依赖
    cfg = ConfigManager()
    log_cfg = cfg.get("logging", {})
    logger = AOTELogger(
        log_path=log_cfg.get("path", r"C:\ProgramData\ClassroomGuard\logs"),
        retention_days=log_cfg.get("retention_days", 30)
    )
    logger.info(f"[Watchdog] 守护进程启动 PID={os.getpid()}")

    # 最小化的监控：扫描主进程，如果不存在则启动
    tg = TimeGuard(cfg, logger)
    anti = AntiTamper(cfg, logger, tg)
    anti.mark_as_watchdog(True)

    # 记录我们要监控的主进程：先看是否已存在
    import psutil
    main_pid = None
    script_basename = os.path.basename(sys.argv[0]).lower()
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if ("--main" in cmd) or (script_basename in cmd.lower() and "--watchdog" not in cmd):
                if p.pid != os.getpid():
                    main_pid = p.pid
                    break
        except Exception:
            pass

    # 如果没找到，尝试复活
    if main_pid is None:
        logger.info("[Watchdog] 未发现主进程，立即复活")
        main_pid = _respawn_main(logger)

    anti.set_partner_pid(main_pid)
    anti.start()

    logger.info(f"[Watchdog] 已绑定主进程 PID={main_pid}，监控中...")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("[Watchdog] 守护进程停止")


def _respawn_main(logger) -> Optional[int]:
    """复活主进程"""
    try:
        script = os.path.abspath(sys.argv[0])
        if getattr(sys, "frozen", False):
            target = sys.executable
            args = [target, "--main"]
        else:
            target = sys.executable
            args = [target, script, "--main"]
        DETACHED_PROCESS = 0x00000008 if sys.platform == "win32" else 0
        CREATE_NEW_PROCESS_GROUP = 0x00000200 if sys.platform == "win32" else 0
        flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(args, creationflags=flags, close_fds=True)
        logger.info(f"[Watchdog] 主进程复活成功，新PID={proc.pid}")
        return proc.pid
    except Exception as e:
        logger.error(f"[Watchdog] 主进程复活失败: {e}")
        return None


def run_respawn_check():
    """计划任务入口：检查进程是否存在，不在则启动"""
    import psutil
    script_basename = os.path.basename(sys.argv[0]).lower()
    main_found = False
    watchdog_found = False
    for p in psutil.process_iter(["pid", "cmdline", "name"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if script_basename in cmd.lower() or "AOTE" in (p.info.get("name") or ""):
                if "--watchdog" in cmd:
                    watchdog_found = True
                else:
                    main_found = True
        except Exception:
            pass
    if not main_found and not watchdog_found:
        print("[Respawn] 进程不存在，启动主程序")
        script = os.path.abspath(sys.argv[0])
        if getattr(sys, "frozen", False):
            target = sys.executable
            args = [target, "--daemon"]
        else:
            target = sys.executable
            args = [target, script, "--daemon"]
        DETACHED_PROCESS = 0x00000008 if sys.platform == "win32" else 0
        subprocess.Popen(args, creationflags=DETACHED_PROCESS, close_fds=True)
    else:
        print(f"[Respawn] 主进程={main_found}, 守护进程={watchdog_found}，无需复活")


# ======================================================
# 主入口
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="AOTE 实力主义至上一体机管控系统")
    parser.add_argument("--main", action="store_true", help="以主进程模式启动（默认）")
    parser.add_argument("--watchdog", action="store_true", help="以守护进程模式启动")
    parser.add_argument("--daemon", action="store_true", help="后台模式（等同 --main）")
    parser.add_argument("--respawn-check", action="store_true", help="计划任务复活检查")
    args = parser.parse_args()

    # respawn-check 不需要管理员（避免UAC弹窗卡死计划任务）
    if args.respawn_check:
        run_respawn_check()
        return

    # 其他模式强制管理员权限
    require_admin()

    if args.watchdog:
        run_watchdog()
    else:
        # 主进程模式
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
