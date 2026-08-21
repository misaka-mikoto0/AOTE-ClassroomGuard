
"""
AOTE 管控系统 - 主程序入口（纯浏览器内容管控架构）

新架构完全基于浏览器层面实现，不再包含任何进程操作逻辑：
- 无 watchdog 守护进程、无进程复活
- 无进程冻结/终止（不操作任何操作系统进程）
- 无 UAC 提升、无进程互斥锁
- 无注册表/计划任务自启动

管控方式：通过 Playwright 在独立 Chromium 实例内进行浏览器内容管控
（路由拦截、JS 注入、响应捕获、CDP 报文级操作）。

命令行参数：
  --main / --daemon   以主进程模式启动（默认）
"""
import os
import sys
import time
import signal
import threading
import traceback
from pathlib import Path
from typing import Optional

# 将项目根目录加入 path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# === 安全加固：boot_trace（仅写文件，不重定向stdout/stderr，不干扰AOTELogger）===
_BOOT_TRACE = os.path.join(BASE_DIR, "boot_trace.log")

def boot_trace(msg: str):
    """启动关键路径轻量追踪（文件 IO 成功/失败都静默）"""
    try:
        from datetime import datetime
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
        with open(os.path.join(BASE_DIR, "crash.log"), "a", encoding="utf-8") as f:
            import time as _t
            f.write(f"\n[{_t.strftime('%Y-%m-%d %H:%M:%S')}] UNCAUGHT EXCEPTION:\n")
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
from aote.browser_sandbox import (
    BrowserSandbox,
    MODE_RELAXED,
    MODE_STRICT,
)


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
        # 配置 & 日志
        self.config = ConfigManager()
        log_cfg = self.config.get("logging", {})
        self.logger = AOTELogger(
            log_path=log_cfg.get("path", r"C:\ProgramData\ClassroomGuard\logs"),
            retention_days=log_cfg.get("retention_days", 30)
        )
        self.logger.info("=" * 60)
        self.logger.info("🚀 AOTE 一体机管控系统 启动（纯浏览器内容管控）")
        self.logger.info(f"   PID: {os.getpid()}")
        self.logger.info("=" * 60)

        # 时间调度
        self.time_guard = TimeGuard(self.config, self.logger)
        self.time_guard.set_on_mode_change(self._on_mode_change)

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

        # 系统托盘
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
            if new_mode == TimeGuard.MODE_RELAXED:
                # 上课时间：宽松放行
                self.browser_sandbox.set_control_mode(MODE_RELAXED)
            elif new_mode == TimeGuard.MODE_EMERGENCY:
                # 紧急模式：立即恢复严格管控
                self.browser_sandbox.restore_strict_mode()
            else:
                # 严格模式：恢复严格管控
                self.browser_sandbox.restore_strict_mode()
        except Exception as e:
            self.logger.error(f"[Main] 模式切换同步沙盒失败: {e}")

    # ============ 浏览器内容违规回调 ============
    def _on_browser_violation(self, url: str, reason: str, level: int = 1):
        """浏览器内检测到违禁内容 -> 记录违规日志并确认弱网已切换。
        黑名单命中后沙盒已自动切换弱网；用户可按热键（密码验证）豁免。"""
        self.logger.warning(f"[管控] 浏览器违规: {url} reason={reason} level={level}")
        if self.browser_sandbox is not None:
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
            modes_cfg = self.config.get("unlock_modes", [])
            seconds = 0
            for m in modes_cfg:
                if m.get("name") == mode and m.get("type") == "timer":
                    seconds = m.get("seconds", 1800)
                    break
            if seconds <= 0:
                mapping = {"30分钟": 1800, "1小时": 3600, "2小时": 7200}
                seconds = mapping.get(mode, 1800)
            self.browser_sandbox.temporary_unlock(seconds)
            self.logger.info(f"[USB] 定时解锁模式: {mode} ({seconds}秒)")

        return mode

    def _on_eject_unplug(self):
        """即拔即禁U盘已拔出"""
        self.logger.warning("[USB] 即拔即禁U盘已拔出，恢复严格模式")
        if self.browser_sandbox is not None:
            self.browser_sandbox.restore_strict_mode()
        # 如果是宽松模式外的时间，强制切回严格模式
        if not self.time_guard.is_relaxed_mode:
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
        """实际执行退出操作（纯关闭，无任何进程操作）"""
        self.logger.warning("⚠ 执行系统紧急退出")
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
        """启动所有子组件"""
        self.time_guard.start()
        self.anti_tamper.start()
        self.http_server.start()
        self.usb_guard.start()
        self.system_tray.start()
        # 浏览器控制沙盒（独立浏览器 / CDP 接管外部浏览器）；失败不影响主控核心功能
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.start()
                # 启动后按时间守卫当前模式同步管控
                if self.time_guard.is_relaxed_mode:
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
            while not self._shutdown.is_set():
                time.sleep(1)
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
# 主入口
# ======================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="AOTE 实力主义至上一体机管控系统")
    parser.add_argument("--main", action="store_true", help="以主进程模式启动（默认）")
    parser.add_argument("--daemon", action="store_true", help="后台模式（等同 --main）")
    args = parser.parse_args()

    boot_trace("enter main")
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
