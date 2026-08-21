"""
AOTE 管控系统 - 系统托盘（Systray）
使用 pystray 显示状态图标、提供菜单入口
"""
import threading
import time
import sys
import os
from typing import Optional, Callable

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

    # ============ 菜单动作 ============
    def _menu_strict_mode(self, *args):
        """切换到严格模式"""
        if hasattr(self.time_guard, "_emergency_forced"):
            self.time_guard._emergency_forced = False
        self.time_guard._set_mode(TimeGuard.MODE_STRICT, "tray_strict")
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.restore_strict_mode()
            except Exception as e:
                self.logger.debug(f"[Tray] 恢复浏览器严格管控失败: {e}")

    def _menu_relaxed_mode(self, *args):
        """切换到宽松模式（调试用）"""
        if hasattr(self.time_guard, "_emergency_forced"):
            self.time_guard._emergency_forced = False
        self.time_guard._set_mode(TimeGuard.MODE_RELAXED, "tray_relaxed")
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.set_control_mode("relaxed")
            except Exception as e:
                self.logger.debug(f"[Tray] 切换浏览器宽松模式失败: {e}")

    def _menu_temp_unlock_5min(self, *args):
        """临时解锁5分钟"""
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.temporary_unlock(300)
            except Exception as e:
                self.logger.debug(f"[Tray] 浏览器临时解锁失败: {e}")

    def _menu_temp_unlock_30min(self, *args):
        """临时解锁30分钟"""
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.temporary_unlock(1800)
            except Exception as e:
                self.logger.debug(f"[Tray] 浏览器临时解锁失败: {e}")

    def _menu_status(self, *args):
        """显示当前状态（弹消息）"""
        mode_cn = {
            TimeGuard.MODE_STRICT: "严格模式（管控浏览器内容）",
            TimeGuard.MODE_RELAXED: "宽松模式（上课时间）",
            TimeGuard.MODE_EMERGENCY: "紧急模式（安全威胁）",
        }
        mode = mode_cn.get(self.time_guard.current_mode, "未知")
        try:
            sandbox_mode = self.browser_sandbox.current_mode() if self.browser_sandbox else "未启用"
            unlocked = self.browser_sandbox.is_unlocked() if self.browser_sandbox else False
        except Exception:
            sandbox_mode, unlocked = "未知", False
        unlock_status = "已解锁" if unlocked else "管控中"
        # 弱网状态
        weak_txt = "未启用"
        try:
            wn = self.browser_sandbox.weak_network_status() if self.browser_sandbox else {}
            if wn.get("enabled"):
                if wn.get("active"):
                    weak_txt = (f"已生效 → {wn.get('host')} "
                                f"(延迟 {wn.get('latency_ms')}ms / "
                                f"下载 {wn.get('download_kbps')}KB/s)")
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
    def _run(self):
        try:
            import pystray
            from pystray import MenuItem as Item, Menu
        except Exception as e:
            self.logger.error(f"[Tray] pystray 不可用: {e}")
            return

        image = self._generate_icon_image()
        if image is None:
            self.logger.error("[Tray] 无法创建图标，托盘功能禁用")
            return

        def _checked(prefix):
            """返回带状态前缀的菜单文本（兼容多版本 pystray：(icon,item) / (item,) / 无参）"""
            return lambda *a: f"{prefix} {_get_status()}"

        def _get_status():
            mode_short = {
                TimeGuard.MODE_STRICT: "[严格]",
                TimeGuard.MODE_RELAXED: "[宽松]",
                TimeGuard.MODE_EMERGENCY: "[紧急]",
            }
            mode = mode_short.get(self.time_guard.current_mode, "")
            try:
                unlocked = self.browser_sandbox.is_unlocked() if self.browser_sandbox else False
            except Exception:
                unlocked = False
            unlock = "✓已解锁" if unlocked else "✗管控中"
            try:
                wn = self.browser_sandbox.weak_network_status() if self.browser_sandbox else {}
                weak = " ⚠弱网" if wn.get("active") else ""
            except Exception:
                weak = ""
            return f"{mode} {unlock}{weak}"

        # 构建菜单
        menu = Menu(
            Item(lambda *a: f"📊 系统状态 {_get_status()}", self._menu_status),
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

        self._icon = pystray.Icon(
            "AOTE_Guardian",
            image,
            "AOTE 一体机管控系统",
            menu
        )

        # 更新图标的定时线程
        def _updater():
            while not self._stop_event.is_set():
                try:
                    if self._icon and self._icon.visible:
                        self._icon.update_menu()
                except Exception:
                    pass
                self._stop_event.wait(3)

        threading.Thread(target=_updater, daemon=True).start()

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
