"""
AOTE 管控系统 - 系统托盘（Systray）
使用 pystray 显示状态图标、提供菜单入口
"""
import threading
from typing import Callable, Optional, Tuple

from .config import ConfigManager
from .logger import AOTELogger
from .time_guard import TimeGuard
from .browser_sandbox import BrowserSandbox


class SystemTray:
    """系统托盘图标与菜单"""

    def __init__(self, config: ConfigManager, logger: AOTELogger,
                 time_guard: TimeGuard, browser_sandbox: BrowserSandbox):
        self.config = config
        self.logger = logger
        self.time_guard = time_guard
        self.browser_sandbox = browser_sandbox

        self._icon = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # 菜单回调
        self.on_emergency_exit_request: Optional[Callable[[], None]] = None

    # ============ 图标生成 ============
    def _generate_icon_image(self):
        """生成托盘图标（使用PIL，避免外部图片）
        Minor 12 修复：
        - 捕获 PIL/ImageDraw/text 不存在或 Pillow 版本过低（font_size 参数无效）的所有异常
        - 即使所有绘制步骤失败，最后 fallback 一定返回纯色图或 None，绝不崩溃
        """
        try:
            from PIL import Image, ImageDraw
        except Exception as e:
            self.logger.debug(f"PIL 不可用，跳过图标: {e}")
            return None
        try:
            # 一个蓝色盾牌 + 白色字母A
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            # 背景圆（某些老版 Pillow outline 的 width 参数可能不支持）
            try:
                draw.ellipse((4, 4, 60, 60), fill=(0, 120, 215, 255), outline=(0, 80, 160, 255), width=3)
            except Exception:
                draw.ellipse((4, 4, 60, 60), fill=(0, 120, 215, 255), outline=(0, 80, 160, 255))
            # 字母A：老版 Pillow 可能不支持 font_size= 关键字参数，降级为默认字体
            try:
                draw.text((18, 8), "A", fill=(255, 255, 255, 255), font_size=40)
            except Exception:
                draw.text((22, 12), "A", fill=(255, 255, 255, 255))
            # 盾牌角标
            try:
                draw.rectangle((2, 2, 14, 14), fill=(0, 180, 0, 255))
            except Exception:
                pass
            return img
        except Exception as e:
            self.logger.debug(f"生成图标失败: {e}")
            # Fallback: 简单图像
            try:
                return Image.new("RGB", (64, 64), (0, 120, 215))
            except Exception:
                return None

    # ============ 状态采集 ============
    def _sandbox_state(self) -> Tuple[str, bool, dict]:
        """采集浏览器沙盒状态：返回 (mode, unlocked, weak_network)
        沙盒不可用或查询异常时返回安全默认值，不影响托盘展示。"""
        try:
            sb = self.browser_sandbox
            mode = sb.current_mode() if sb else "未启用"
            unlocked = sb.is_unlocked() if sb else False
        except Exception:
            mode, unlocked = "未知", False
        try:
            weak = self.browser_sandbox.weak_network_status() if self.browser_sandbox else {}
        except Exception:
            weak = {}
        return mode, unlocked, weak

    def _get_status(self) -> str:
        """菜单标题后缀：模式 + 解锁状态 + 弱网提示"""
        mode_short = {
            TimeGuard.MODE_STRICT: "[严格]",
            TimeGuard.MODE_RELAXED: "[宽松]",
            TimeGuard.MODE_EMERGENCY: "[紧急]",
            TimeGuard.MODE_EXEMPT: "[豁免]",
        }
        mode = mode_short.get(self.time_guard.current_mode, "")
        _mode, unlocked, weak = self._sandbox_state()
        unlock = "✓已解锁" if unlocked else "✗管控中"
        weak_mark = " ⚠弱网" if weak.get("active") else ""
        return f"{mode} {unlock}{weak_mark}"

    # ============ 菜单动作 ============
    def _switch_mode(self, mode: str, reason: str, error_hint: str):
        """切换时间守卫模式并同步浏览器沙盒管控"""
        if hasattr(self.time_guard, "_emergency_forced"):
            self.time_guard._emergency_forced = False
        self.time_guard._set_mode(mode, reason)
        if self.browser_sandbox is not None:
            try:
                if mode == TimeGuard.MODE_RELAXED:
                    self.browser_sandbox.set_control_mode("relaxed")
                else:
                    self.browser_sandbox.restore_strict_mode()
            except Exception as e:
                self.logger.debug(f"[Tray] {error_hint}: {e}")

    def _menu_strict_mode(self, *args):
        """切换到严格模式"""
        self._switch_mode(TimeGuard.MODE_STRICT, "tray_strict", "恢复浏览器严格管控失败")

    def _menu_relaxed_mode(self, *args):
        """切换到宽松模式（调试用）"""
        self._switch_mode(TimeGuard.MODE_RELAXED, "tray_relaxed", "切换浏览器宽松模式失败")

    def _temp_unlock(self, config_key: str, default_seconds: float):
        """按配置读取时长并对浏览器沙盒执行临时解锁"""
        seconds = float(self.config.get(config_key, default_seconds))
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.temporary_unlock(seconds)
            except Exception as e:
                self.logger.debug(f"[Tray] 浏览器临时解锁失败: {e}")

    def _menu_temp_unlock_5min(self, *args):
        """临时解锁5分钟（时长从 time_settings.tray_unlock_5min 读取）"""
        self._temp_unlock("time_settings.tray_unlock_5min", 300)

    def _menu_temp_unlock_30min(self, *args):
        """临时解锁30分钟（时长从 time_settings.tray_unlock_30min 读取）"""
        self._temp_unlock("time_settings.tray_unlock_30min", 1800)

    def _menu_status(self, *args):
        """显示当前状态（弹消息）"""
        mode_cn = {
            TimeGuard.MODE_STRICT: "严格模式（管控浏览器内容）",
            TimeGuard.MODE_RELAXED: "宽松模式（上课时间）",
            TimeGuard.MODE_EMERGENCY: "紧急模式（安全威胁）",
            TimeGuard.MODE_EXEMPT: "豁免状态（所有限制已暂停）",
        }
        mode = mode_cn.get(self.time_guard.current_mode, "未知")
        sandbox_mode, unlocked, weak = self._sandbox_state()
        unlock_status = "已解锁" if unlocked else "管控中"

        # 弱网状态
        weak_txt = "未启用"
        try:
            if weak.get("enabled"):
                if weak.get("active"):
                    weak_txt = (f"已生效 → {weak.get('host')} "
                                f"(延迟 {weak.get('latency_ms')}ms / "
                                f"下载 {weak.get('download_kbps')}KB/s)")
                else:
                    weak_txt = "监控中（未触发）"
        except Exception:
            weak_txt = "未知"

        msg = (f"AOTE 实力主义一体机管控系统\n\n"
               f"当前模式: {mode}\n"
               f"浏览器: {sandbox_mode} ({unlock_status})\n"
               f"弱网管控: {weak_txt}\n"
               f"豁免方式: 按热键输入管理员密码")
        try:
            import tkinter as tk
            from tkinter import messagebox

            def _show():
                r = tk.Tk()
                r.withdraw()
                r.attributes("-topmost", True)
                messagebox.showinfo("AOTE 系统状态", msg)
                r.destroy()

            threading.Thread(target=_show, daemon=True).start()
        except Exception:
            pass

    def _menu_emergency_exit(self, *args):
        """紧急退出（触发密码验证）"""
        if self.on_emergency_exit_request:
            threading.Thread(target=self.on_emergency_exit_request, daemon=True).start()

    # ============ 主循环 ============
    def _build_menu(self, pystray_module):
        """构建托盘菜单"""
        Menu = pystray_module.Menu
        Item = pystray_module.MenuItem
        return Menu(
            Item(lambda *a: f"📊 系统状态 {self._get_status()}", self._menu_status),
            Menu.SEPARATOR,
            Item("🔒 切回严格模式", self._menu_strict_mode),
            Item("🔓 切到宽松模式(调试)", self._menu_relaxed_mode),
            Menu.SEPARATOR,
            Item("⏱  临时解锁 5 分钟", self._menu_temp_unlock_5min),
            Item("⏱  临时解锁 30 分钟", self._menu_temp_unlock_30min),
            Item("🔑 密码豁免（热键验证）", self._menu_emergency_exit),
            Menu.SEPARATOR,
            Item("🚪 紧急退出系统...", self._menu_emergency_exit),
        )

    def _start_menu_updater(self):
        """启动菜单刷新线程（刷新间隔从 time_settings.tray_refresh_interval 读取）"""
        interval = max(float(self.config.get("time_settings.tray_refresh_interval", 3)), 0.5)

        def _updater():
            while not self._stop_event.is_set():
                try:
                    if self._icon and self._icon.visible:
                        self._icon.update_menu()
                except Exception:
                    pass
                self._stop_event.wait(interval)

        threading.Thread(target=_updater, daemon=True).start()

    def is_hidden(self) -> bool:
        """是否以"静默后台"方式运行（不显示托盘图标）。

        配置项 guardian.hide_tray_icon，默认 false（保持托盘可见，行为不变）。
        隐藏后唯一的管理入口是热键 Ctrl+Shift+Alt+G（仍需管理员密码），
        进程本身在任务管理器中始终可见，可随时查看与结束。
        """
        return bool(self.config.get("guardian.hide_tray_icon", False))

    def _run(self):
        """托盘线程主循环（pystray 不可用时静默降级）"""
        if self.is_hidden():
            # 静默后台：不创建托盘图标，也就没有通知区域条目
            self.logger.warning(
                "[Tray] 静默后台模式：未显示托盘图标（guardian.hide_tray_icon=true）。"
                "管理入口：热键 Ctrl+Shift+Alt+G（需管理员密码）"
            )
            return

        try:
            import pystray
        except Exception as e:
            self.logger.error(f"[Tray] pystray 不可用: {e}")
            return

        image = self._generate_icon_image()
        if image is None:
            self.logger.error("[Tray] 无法创建图标，托盘功能禁用")
            return

        self._icon = pystray.Icon(
            "AOTE_Guardian",
            image,
            "AOTE 一体机管控系统",
            self._build_menu(pystray)
        )
        self._start_menu_updater()

        try:
            self._icon.run()
        except Exception as e:
            self.logger.error(f"[Tray] 运行异常: {e}")

    def start(self):
        """启动托盘"""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="SystemTray")
        self._thread.start()
        self.logger.info("[Tray] 系统托盘已启动")

    def stop(self):
        """停止托盘"""
        self._stop_event.set()
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
        self.logger.info("[Tray] 系统托盘已停止")
