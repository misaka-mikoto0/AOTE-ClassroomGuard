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
from .process_hunter import ProcessHunter


class SystemTray:
    """系统托盘图标与菜单"""

    def __init__(self, config: ConfigManager, logger: AOTELogger,
                 time_guard: TimeGuard, process_hunter: ProcessHunter):
        self.config = config
        self.logger = logger
        self.time_guard = time_guard
        self.process_hunter = process_hunter

        self._icon = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # 菜单回调
        self.on_emergency_exit_request: Optional[Callable[[], None]] = None
        self.on_show_math_challenge: Optional[Callable[[], None]] = None

    # ============ 图标生成 ============
    def _generate_icon_image(self):
        """生成托盘图标（使用PIL，避免外部图片）"""
        try:
            from PIL import Image, ImageDraw
            # 一个蓝色盾牌 + 白色字母A
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            # 背景圆
            draw.ellipse((4, 4, 60, 60), fill=(0, 120, 215, 255), outline=(0, 80, 160, 255), width=3)
            # 字母A
            draw.text((18, 8), "A", fill=(255, 255, 255, 255),
                      font_size=40)
            # 盾牌角标
            draw.rectangle((2, 2, 14, 14), fill=(0, 180, 0, 255))
            return img
        except Exception as e:
            self.logger.debug(f"生成图标失败: {e}")
            # Fallback: 简单图像
            try:
                from PIL import Image
                return Image.new("RGB", (64, 64), (0, 120, 215))
            except Exception:
                return None

    # ============ 菜单动作 ============
    def _menu_strict_mode(self, icon, item):
        """切换到严格模式"""
        if hasattr(self.time_guard, "_emergency_forced"):
            self.time_guard._emergency_forced = False
        self.time_guard._set_mode(TimeGuard.MODE_STRICT, "tray_strict")
        self.process_hunter.restore_strict_mode()

    def _menu_relaxed_mode(self, icon, item):
        """切换到宽松模式（调试用）"""
        if hasattr(self.time_guard, "_emergency_forced"):
            self.time_guard._emergency_forced = False
        self.time_guard._set_mode(TimeGuard.MODE_RELAXED, "tray_relaxed")

    def _menu_temp_unlock_5min(self, icon, item):
        """临时解锁5分钟"""
        self.process_hunter.temporary_unlock(300)

    def _menu_temp_unlock_30min(self, icon, item):
        """临时解锁30分钟"""
        self.process_hunter.temporary_unlock(1800)

    def _menu_math_challenge(self, icon, item):
        """显示数学挑战"""
        if self.on_show_math_challenge:
            threading.Thread(target=self.on_show_math_challenge, daemon=True).start()

    def _menu_status(self, icon, item):
        """显示当前状态（弹消息）"""
        mode_cn = {
            TimeGuard.MODE_STRICT: "严格模式（冻结目标）",
            TimeGuard.MODE_RELAXED: "宽松模式（上课时间）",
            TimeGuard.MODE_EMERGENCY: "紧急模式（安全威胁）",
        }
        mode = mode_cn.get(self.time_guard.current_mode, "未知")
        unlock_status = "已解锁" if self.process_hunter.is_unlocked else "管控中"
        msg = f"AOTE 实力主义一体机管控系统\n\n当前模式: {mode}\n进程: {unlock_status}\n\nPID: {os.getpid()}"
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

    def _menu_emergency_exit(self, icon, item):
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
            """返回带状态前缀的菜单文本"""
            return lambda item: f"{prefix} {_get_status()}"

        def _get_status():
            mode_short = {
                TimeGuard.MODE_STRICT: "[严格]",
                TimeGuard.MODE_RELAXED: "[宽松]",
                TimeGuard.MODE_EMERGENCY: "[紧急]",
            }
            mode = mode_short.get(self.time_guard.current_mode, "")
            unlock = "✓已解锁" if self.process_hunter.is_unlocked else "✗管控中"
            return f"{mode} {unlock}"

        # 构建菜单
        menu = Menu(
            Item(lambda icon: f"📊 系统状态 {_get_status()}", self._menu_status),
            Menu.SEPARATOR,
            Item("🔒 切回严格模式", self._menu_strict_mode),
            Item("🔓 切到宽松模式(调试)", self._menu_relaxed_mode),
            Menu.SEPARATOR,
            Item("⏱  临时解锁 5 分钟", self._menu_temp_unlock_5min),
            Item("⏱  临时解锁 30 分钟", self._menu_temp_unlock_30min),
            Item("🧮 触发数学挑战", self._menu_math_challenge),
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
