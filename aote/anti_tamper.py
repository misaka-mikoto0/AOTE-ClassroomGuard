"""
AOTE 管控系统 - 防绕过与自保护模块（Anti-Tamper）
功能：
- 浏览器沙盒心跳检测（沙盒运行即心跳，超时记录/提示重启）
- 紧急退出快捷键 + 管理员密码验证
- 不再包含任何进程操作：无自启动安装、无双进程守护、无进程冻结/复活
"""
import hashlib
import threading
from typing import Callable, Optional, Tuple

from .config import ConfigManager
from .logger import AOTELogger
from .time_guard import TimeGuard

# 回文验证时允许枚举的最短子串长度：
# 防止暴力枚举短子串带来的安全放大效应，同时保持正常使用便利
MIN_PASSWORD_SUBSTR_LEN = 8

# 密码校验的输入长度上限：子串枚举为 O(n^2)，不设上限时误粘贴大段文本
# 会让校验耗时呈平方级增长并卡死主线程。正常密码输入远短于此值。
MAX_PASSWORD_INPUT_LEN = 512

# 管理员验证对话框的 UI 主题色
_THEME_BLUE = "#1a73e8"
_THEME_BLUE_LIGHT = "#e8f0fe"
_THEME_BG = "#f0f2f5"
_THEME_GRAY = "#595959"
_THEME_RED = "#ff4d4f"


def sha256_str(s: str) -> str:
    """计算字符串的 SHA-256 十六进制摘要"""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def password_matches_hash(password: str, expected_hash: str) -> bool:
    """回文匹配校验：正确密码需作为连续子串完整出现在输入的任意位置。

    仅枚举长度 ≥ MIN_PASSWORD_SUBSTR_LEN 的子串，防止暴力枚举短子串带来的
    安全放大效应，同时保持正常输入时的便利性。纯函数，不写日志。

    子串枚举为 O(n^2)，故对超长输入截断，避免误粘贴大段文本时卡死主线程。
    """
    if not expected_hash:
        return False
    if len(password) > MAX_PASSWORD_INPUT_LEN:
        password = password[:MAX_PASSWORD_INPUT_LEN]
    expected = expected_hash.lower()

    # 快速路径：完整输入精确匹配
    if sha256_str(password).lower() == expected:
        return True

    # 慢路径：枚举长度足够的连续子串
    n = len(password)
    for i in range(n):
        for j in range(i + MIN_PASSWORD_SUBSTR_LEN, n + 1):
            if sha256_str(password[i:j]).lower() == expected:
                return True
    return False


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

        matched = password_matches_hash(password, expected)
        self.logger.log_admin_action("password_verify", matched)
        return matched

    # ============ 监控循环（浏览器沙盒心跳） ============
    def _monitor_loop(self):
        interval = int(self.config.get("anti_tamper.monitor_interval", 2))
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
    def show_emergency_exit_dialog(self) -> Tuple[bool, int]:
        """弹出管理员密码验证框，通过后提供时间选择
        :return: (should_exit: bool, unlock_seconds: int)
                 should_exit=True → 完全退出系统
                 unlock_seconds>0 → 临时解锁N秒
                 (False, 0) → 用户取消
        """
        result = {"should_exit": False, "unlock_seconds": 0}
        dialog = threading.Thread(
            target=self._build_password_dialog,
            args=(lambda: self._build_action_dialog(result),),
            daemon=True,
        )
        dialog.start()
        timeout = float(self.config.get("time_settings.password_dialog_timeout", 120))
        dialog.join(timeout=max(timeout, 1))
        return result["should_exit"], result["unlock_seconds"]

    def _build_password_dialog(self, on_success: Callable[[], None]):
        """密码验证对话框（阻塞至窗口关闭，验证通过后调用 on_success）"""
        import tkinter as tk
        from tkinter import ttk, messagebox

        dlg = tk.Tk()
        dlg.title("管理员验证 - AOTE")
        dlg.attributes("-topmost", True)
        dlg.geometry("420x240")
        dlg.resizable(False, False)
        dlg.configure(bg=_THEME_BLUE)

        tk.Label(
            dlg, text="🔐 管理员验证",
            font=("Microsoft YaHei", 16, "bold"),
            fg="white", bg=_THEME_BLUE
        ).pack(pady=(20, 5))
        tk.Label(
            dlg, text="请输入管理员密码",
            font=("Microsoft YaHei", 10),
            fg=_THEME_BLUE_LIGHT, bg=_THEME_BLUE
        ).pack(pady=(0, 12))

        entry = ttk.Entry(dlg, show="*", font=("Consolas", 14), width=24, justify=tk.CENTER)
        entry.pack(pady=5)
        entry.focus_set()

        def _ok():
            pwd = entry.get()
            if self.verify_admin_password(pwd):
                dlg.destroy()
                on_success()
            else:
                messagebox.showerror("验证失败", "密码错误！", parent=dlg)
                entry.delete(0, tk.END)

        def _cancel():
            dlg.destroy()

        btn_frame = tk.Frame(dlg, bg=_THEME_BLUE)
        btn_frame.pack(pady=18)
        tk.Button(
            btn_frame, text="确认", font=("Microsoft YaHei", 11, "bold"),
            bg="white", fg=_THEME_BLUE, relief=tk.FLAT,
            padx=20, pady=6, command=_ok
        ).pack(side=tk.LEFT, padx=10)
        tk.Button(
            btn_frame, text="取消", font=("Microsoft YaHei", 11),
            bg=_THEME_BLUE_LIGHT, fg=_THEME_BLUE, relief=tk.FLAT,
            padx=20, pady=6, command=_cancel
        ).pack(side=tk.LEFT, padx=10)

        entry.bind("<Return>", lambda e: _ok())
        entry.bind("<Escape>", lambda e: _cancel())
        dlg.mainloop()

    def _build_action_dialog(self, result: dict):
        """管理员操作面板：选择临时解锁时长或完全退出系统"""
        import tkinter as tk
        from tkinter import ttk, messagebox

        dlg = tk.Tk()
        dlg.title("管理员操作面板 - AOTE")
        dlg.attributes("-topmost", True)
        dlg.geometry("400x440")
        dlg.resizable(False, False)
        dlg.configure(bg=_THEME_BG)

        tk.Label(
            dlg, text="✅ 验证成功",
            font=("Microsoft YaHei", 16, "bold"),
            fg=_THEME_BLUE, bg=_THEME_BG
        ).pack(pady=(20, 5))
        tk.Label(
            dlg, text="请选择操作",
            font=("Microsoft YaHei", 11),
            fg=_THEME_GRAY, bg=_THEME_BG
        ).pack(pady=(0, 15))

        def _choose_unlock(seconds):
            result["unlock_seconds"] = seconds
            dlg.destroy()

        def _choose_exit():
            result["should_exit"] = True
            dlg.destroy()

        # 解锁时长选项从 time_settings.unlock_options 读取（秒）
        unlock_options = (self.config.get("time_settings.unlock_options",
                                          [300, 600, 1800, 3600])
                          or [300, 600, 1800, 3600])
        for secs in unlock_options:
            try:
                secs = int(secs)
            except (TypeError, ValueError):
                continue
            minutes = secs // 60
            tk.Button(
                dlg, text=f"⏱  临时解锁 {minutes} 分钟",
                font=("Microsoft YaHei", 12, "bold"),
                bg="white", fg=_THEME_BLUE,
                relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                highlightbackground="#d9d9d9", highlightthickness=1,
                command=lambda s=secs: _choose_unlock(s)
            ).pack(fill=tk.X, padx=40, pady=4)

        custom_frame = tk.Frame(dlg, bg=_THEME_BG)
        custom_frame.pack(fill=tk.X, padx=40, pady=4)
        tk.Label(custom_frame, text="自定义(分钟):",
                 font=("Microsoft YaHei", 11), bg=_THEME_BG, fg=_THEME_GRAY
                 ).pack(side=tk.LEFT)
        custom_entry = ttk.Entry(custom_frame, font=("Consolas", 12), width=8, justify=tk.CENTER)
        custom_entry.pack(side=tk.LEFT, padx=8)

        # 自定义解锁时间上限（防止超长解锁），从 time_settings.max_custom_unlock_minutes 读取
        max_custom_minutes = int(
            self.config.get("time_settings.max_custom_unlock_minutes", 180)
        )

        def _custom_ok():
            val = custom_entry.get().strip()
            if not val.isdigit():
                messagebox.showwarning("输入无效", "请输入正整数分钟数", parent=dlg)
                return
            minutes = int(val)
            if minutes <= 0:
                messagebox.showwarning("输入无效", "解锁时长必须大于 0 分钟", parent=dlg)
                return
            if minutes > max_custom_minutes:
                messagebox.showwarning(
                    "超过上限",
                    f"自定义解锁时长不能超过 {max_custom_minutes} 分钟（3 小时）",
                    parent=dlg
                )
                return
            _choose_unlock(minutes * 60)

        tk.Button(
            custom_frame, text="确认",
            font=("Microsoft YaHei", 10, "bold"),
            bg=_THEME_BLUE, fg="white", relief=tk.FLAT,
            padx=12, pady=4, cursor="hand2",
            command=_custom_ok
        ).pack(side=tk.LEFT)

        tk.Button(
            dlg, text="🚪 完全退出管控系统",
            font=("Microsoft YaHei", 12, "bold"),
            bg=_THEME_RED, fg="white",
            relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
            command=_choose_exit
        ).pack(fill=tk.X, padx=40, pady=(15, 4))

        dlg.mainloop()

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
            timeout = float(self.config.get("time_settings.component_stop_timeout", 3))
            self._monitor_thread.join(timeout=max(timeout, 0.1))
        self.logger.info("[AntiTamper] 防绕过模块已停止")
