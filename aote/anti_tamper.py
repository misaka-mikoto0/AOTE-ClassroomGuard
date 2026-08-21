"""
AOTE 管控系统 - 防绕过与自保护模块（Anti-Tamper）
功能：
- 浏览器沙盒心跳检测（沙盒运行即心跳，超时记录/提示重启）
- 紧急退出快捷键 + 管理员密码验证
- 不再包含任何进程操作：无自启动安装、无双进程守护、无进程冻结/复活
"""
import time
import hashlib
import threading
from typing import Callable, Optional

from .config import ConfigManager
from .logger import AOTELogger
from .time_guard import TimeGuard


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class AntiTamper:
    """防绕过与自保护模块（纯浏览器层面）"""

    def __init__(self, config: ConfigManager, logger: AOTELogger, time_guard: TimeGuard):
        self.config = config
        self.logger = logger
        self.time_guard = time_guard

        # 心跳超时（浏览器沙盒）
        self._heartbeat_timeout = int(config.get("http_server.heartbeat_timeout", 30))

        # 控制
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

        # 浏览器沙盒引用（由主程序注入）
        self._browser_sandbox: Optional[object] = None

        # 紧急退出回调
        self._on_emergency_exit: Optional[Callable[[], None]] = None

        # 沙盒失活时回调（提示重启沙盒）
        self._on_sandbox_heartbeat_lost: Optional[Callable[[], None]] = None

    # ============ 外部接口 ============
    def set_browser_sandbox(self, sandbox) -> None:
        """注入浏览器沙盒引用（心跳来源）"""
        self._browser_sandbox = sandbox

    def set_on_emergency_exit(self, cb: Callable[[], None]):
        """设置紧急退出回调（管理员快捷键）"""
        self._on_emergency_exit = cb

    def set_on_sandbox_heartbeat_lost(self, cb: Callable[[], None]):
        """设置浏览器沙盒失活回调（用于提示/重启沙盒）"""
        self._on_sandbox_heartbeat_lost = cb

    def verify_admin_password(self, password: str) -> bool:
        """校验管理员密码
        回文验证：正确密码必须完整出现在用户输入的任意位置（作为连续子串）
        但限制子串长度 ≥ 8 位，防止暴力枚举短子串的安全放大效应，同时保持便利性
        """
        expected = self.config.get("emergency.admin_password_hash", "").lower()
        if not expected:
            return False
        n = len(password)
        # 只检查长度 ≥ 8 的子串（正确密码通常为8位以上）
        # 同时从完整输入精确匹配开始，快速路径优先
        if sha256_str(password).lower() == expected:
            self.logger.log_admin_action("password_verify", True)
            return True
        # 再检查子串（长度 8~n）
        MIN_SUBSTR_LEN = 8
        for i in range(n):
            # 剩余长度不足 MIN_SUBSTR_LEN 就不再枚举
            max_j = min(n, i + max(n, 100))
            for j in range(max(i + MIN_SUBSTR_LEN, i + 1), max_j + 1):
                substr = password[i:j]
                if len(substr) < MIN_SUBSTR_LEN:
                    continue
                if sha256_str(substr).lower() == expected:
                    self.logger.log_admin_action("password_verify", True)
                    return True
        self.logger.log_admin_action("password_verify", False)
        return False

    # ============ 监控循环（浏览器沙盒心跳） ============
    def _monitor_loop(self):
        interval = int(self.config.get("watchdog.monitor_interval", 2))
        if interval <= 0:
            interval = 2

        while not self._stop_event.is_set():
            try:
                self._check_sandbox_heartbeat()
            except Exception as e:
                self.logger.error(f"[AntiTamper] 监控异常: {e}")
            self._stop_event.wait(interval)

    def _check_sandbox_heartbeat(self):
        """检查浏览器沙盒心跳：沙盒进程存活并刷新心跳视为正常"""
        if self._browser_sandbox is None:
            return
        try:
            if not self._browser_sandbox.is_running:
                # 沙盒未在运行：允许一段时间自动恢复（如正在启动中）
                self.logger.log_anti_tamper(
                    "sandbox_not_running",
                    "浏览器沙盒未运行"
                )
                return
            age = self._browser_sandbox.heartbeat()
            if age > self._heartbeat_timeout:
                self.logger.log_anti_tamper(
                    "sandbox_heartbeat_lost",
                    f"浏览器沙盒心跳超时 {int(age)}s"
                )
                if self._on_sandbox_heartbeat_lost:
                    try:
                        self._on_sandbox_heartbeat_lost()
                    except Exception:
                        pass
        except Exception as e:
            self.logger.debug(f"[AntiTamper] 沙盒心跳检查异常: {e}")

    # ============ 紧急退出验证 ============
    def show_emergency_exit_dialog(self) -> tuple:
        """弹出管理员密码验证框，通过后提供时间选择
        :return: (should_exit: bool, unlock_seconds: int)
                 should_exit=True → 完全退出系统
                 unlock_seconds>0 → 临时解锁N秒
                 (False, 0) → 用户取消
        """
        import tkinter as tk
        from tkinter import ttk, messagebox

        result = {"should_exit": False, "unlock_seconds": 0}

        def _show_password_dialog():
            dlg = tk.Tk()
            dlg.title("管理员验证 - AOTE")
            dlg.attributes("-topmost", True)
            dlg.geometry("420x240")
            dlg.resizable(False, False)
            dlg.configure(bg="#1a73e8")

            tk.Label(
                dlg, text="🔐 管理员验证",
                font=("Microsoft YaHei", 16, "bold"),
                fg="white", bg="#1a73e8"
            ).pack(pady=(20, 5))
            tk.Label(
                dlg, text="请输入管理员密码",
                font=("Microsoft YaHei", 10),
                fg="#e8f0fe", bg="#1a73e8"
            ).pack(pady=(0, 12))

            entry = ttk.Entry(dlg, show="*", font=("Consolas", 14), width=24, justify=tk.CENTER)
            entry.pack(pady=5)
            entry.focus_set()

            def _ok():
                pwd = entry.get()
                if self.verify_admin_password(pwd):
                    dlg.destroy()
                    _show_time_selection()
                else:
                    messagebox.showerror("验证失败", "密码错误！", parent=dlg)
                    entry.delete(0, tk.END)

            def _cancel():
                dlg.destroy()

            btn_frame = tk.Frame(dlg, bg="#1a73e8")
            btn_frame.pack(pady=18)
            tk.Button(
                btn_frame, text="确认", font=("Microsoft YaHei", 11, "bold"),
                bg="white", fg="#1a73e8", relief=tk.FLAT,
                padx=20, pady=6, command=_ok
            ).pack(side=tk.LEFT, padx=10)
            tk.Button(
                btn_frame, text="取消", font=("Microsoft YaHei", 11),
                bg="#e8f0fe", fg="#1a73e8", relief=tk.FLAT,
                padx=20, pady=6, command=_cancel
            ).pack(side=tk.LEFT, padx=10)

            entry.bind("<Return>", lambda e: _ok())
            entry.bind("<Escape>", lambda e: _cancel())
            dlg.mainloop()

        def _show_time_selection():
            dlg2 = tk.Tk()
            dlg2.title("管理员操作面板 - AOTE")
            dlg2.attributes("-topmost", True)
            dlg2.geometry("400x440")
            dlg2.resizable(False, False)
            dlg2.configure(bg="#f0f2f5")

            tk.Label(
                dlg2, text="✅ 验证成功",
                font=("Microsoft YaHei", 16, "bold"),
                fg="#1a73e8", bg="#f0f2f5"
            ).pack(pady=(20, 5))
            tk.Label(
                dlg2, text="请选择操作",
                font=("Microsoft YaHei", 11),
                fg="#595959", bg="#f0f2f5"
            ).pack(pady=(0, 15))

            def _choose_unlock(seconds):
                result["unlock_seconds"] = seconds
                dlg2.destroy()

            def _choose_exit():
                result["should_exit"] = True
                dlg2.destroy()

            for text, secs in [
                ("⏱  临时解锁 5 分钟", 300),
                ("⏱  临时解锁 10 分钟", 600),
                ("⏱  临时解锁 30 分钟", 1800),
                ("⏱  临时解锁 60 分钟", 3600),
            ]:
                tk.Button(
                    dlg2, text=text,
                    font=("Microsoft YaHei", 12, "bold"),
                    bg="white", fg="#1a73e8",
                    relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                    highlightbackground="#d9d9d9", highlightthickness=1,
                    command=lambda s=secs: _choose_unlock(s)
                ).pack(fill=tk.X, padx=40, pady=4)

            custom_frame = tk.Frame(dlg2, bg="#f0f2f5")
            custom_frame.pack(fill=tk.X, padx=40, pady=4)
            tk.Label(custom_frame, text="自定义(分钟):",
                     font=("Microsoft YaHei", 11), bg="#f0f2f5", fg="#595959"
                     ).pack(side=tk.LEFT)
            custom_entry = ttk.Entry(custom_frame, font=("Consolas", 12), width=8, justify=tk.CENTER)
            custom_entry.pack(side=tk.LEFT, padx=8)

            # 自定义解锁时间上限（防止超长解锁）
            MAX_CUSTOM_MINUTES = 180  # 3 小时

            def _custom_ok():
                val = custom_entry.get().strip()
                if not val.isdigit():
                    messagebox.showwarning("输入无效", "请输入正整数分钟数", parent=dlg2)
                    return
                minutes = int(val)
                if minutes <= 0:
                    messagebox.showwarning("输入无效", "解锁时长必须大于 0 分钟", parent=dlg2)
                    return
                if minutes > MAX_CUSTOM_MINUTES:
                    messagebox.showwarning(
                        "超过上限",
                        f"自定义解锁时长不能超过 {MAX_CUSTOM_MINUTES} 分钟（3 小时）",
                        parent=dlg2
                    )
                    return
                _choose_unlock(minutes * 60)

            tk.Button(
                custom_frame, text="确认",
                font=("Microsoft YaHei", 10, "bold"),
                bg="#1a73e8", fg="white", relief=tk.FLAT,
                padx=12, pady=4, cursor="hand2",
                command=_custom_ok
            ).pack(side=tk.LEFT)

            tk.Button(
                dlg2, text="🚪 完全退出管控系统",
                font=("Microsoft YaHei", 12, "bold"),
                bg="#ff4d4f", fg="white",
                relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                command=_choose_exit
            ).pack(fill=tk.X, padx=40, pady=(15, 4))

            dlg2.mainloop()

        t = threading.Thread(target=_show_password_dialog, daemon=True)
        t.start()
        t.join(timeout=120)
        return result["should_exit"], result["unlock_seconds"]

    # ============ 生命周期 ============
    def start(self):
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="AntiTamper"
        )
        self._monitor_thread.start()
        self.logger.info("[AntiTamper] 防绕过模块已启动（浏览器沙盒心跳监控）")

    def stop(self):
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)
        self.logger.info("[AntiTamper] 防绕过模块已停止")
