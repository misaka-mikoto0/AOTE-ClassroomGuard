"""
AOTE 管控系统 - 防绕过与自保护模块（Anti-Tamper）
功能：
- 双进程守护（互相监控，3秒内复活）
- 多重自启动（注册表、计划任务）
- 扩展心跳检测（30秒超时进入紧急模式）
- 紧急退出快捷键 + 密码验证
"""
import os
import sys
import time
import json
import hashlib
import subprocess
import threading
import ctypes
import tempfile
from pathlib import Path
from typing import Callable, Optional

from .config import ConfigManager
from .logger import AOTELogger
from .time_guard import TimeGuard


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class AntiTamper:
    """防绕过与自保护模块"""

    def __init__(self, config: ConfigManager, logger: AOTELogger, time_guard: TimeGuard):
        self.config = config
        self.logger = logger
        self.time_guard = time_guard

        # 心跳
        self._last_extension_heartbeat = time.time()
        self._heartbeat_timeout = int(config.get("http_server.extension_heartbeat_timeout", 30))

        # 控制
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

        # 紧急退出回调
        self._on_emergency_exit: Optional[Callable[[], None]] = None
        # 强制退出（非管理员方式）回调
        self._on_force_kill_detected: Optional[Callable[[], None]] = None

        # 本进程标识
        self._is_watchdog = False  # 是否为守护进程（主/副区分）
        self._partner_pid: Optional[int] = None

    # ============ 外部接口 ============
    def set_on_emergency_exit(self, cb: Callable[[], None]):
        """设置紧急退出回调（管理员快捷键）"""
        self._on_emergency_exit = cb

    def set_on_force_kill(self, cb: Callable[[], None]):
        """设置检测到对方进程被杀时的回调（复活对方）"""
        self._on_force_kill_detected = cb

    def set_partner_pid(self, pid: Optional[int]):
        """设置对端进程ID（双进程守护）"""
        self._partner_pid = pid

    def mark_as_watchdog(self, is_watchdog: bool):
        self._is_watchdog = is_watchdog

    def report_extension_heartbeat(self):
        """浏览器扩展上报心跳"""
        self._last_extension_heartbeat = time.time()

    def verify_admin_password(self, password: str) -> bool:
        """校验管理员密码（回文验证：正确密码作为用户输入的子字符串即通过）"""
        expected = self.config.get("emergency.admin_password_hash", "").lower()
        if not expected:
            return False
        n = len(password)
        for i in range(n):
            for j in range(i + 1, n + 1):
                if sha256_str(password[i:j]).lower() == expected:
                    self.logger.log_admin_action("password_verify", True)
                    return True
        self.logger.log_admin_action("password_verify", False)
        return False

    # ============ 自启动安装 ============
    def install_autostart(self):
        """安装多重自启动保险"""
        script_path = self._get_self_script_path()
        if not script_path:
            return
        self._install_registry_run(script_path)
        self._install_registry_runonce(script_path)
        self._install_scheduled_task()

    def uninstall_autostart(self):
        """卸载所有自启动机制（紧急退出时调用）"""
        if sys.platform != "win32":
            return
        # 1. 删除计划任务
        try:
            subprocess.run(
                ["schtasks", "/Delete", "/TN", "AOTE Guardian", "/F"],
                capture_output=True, timeout=10,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            self.logger.info("[AntiTamper] 已删除计划任务 AOTE Guardian")
        except Exception as e:
            self.logger.debug(f"删除计划任务失败: {e}")
        # 2. 删除注册表 Run
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.DeleteValue(key, "AOTE_Guardian")
            winreg.CloseKey(key)
            self.logger.info("[AntiTamper] 已删除注册表 Run 项")
        except Exception:
            pass
        # 3. 删除注册表 RunOnce
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                0, winreg.KEY_SET_VALUE
            )
            winreg.DeleteValue(key, "AOTE_Respawn")
            winreg.CloseKey(key)
            self.logger.info("[AntiTamper] 已删除注册表 RunOnce 项")
        except Exception:
            pass
        self.logger.info("[AntiTamper] 所有自启动机制已卸载")

    def _get_self_script_path(self) -> Optional[str]:
        """获取当前启动脚本路径"""
        try:
            if getattr(sys, "frozen", False):
                # PyInstaller 打包
                return os.path.abspath(sys.executable)
            else:
                return os.path.abspath(sys.argv[0])
        except Exception:
            return None

    def _install_registry_run(self, target: str):
        """注册表 HKLM\\...\\Run 自启动"""
        if sys.platform != "win32":
            return
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "AOTE_Guardian", 0, winreg.REG_SZ, f'"{target}" --daemon')
            winreg.CloseKey(key)
        except Exception as e:
            self.logger.debug(f"注册表Run安装失败: {e}")

    def _install_registry_runonce(self, target: str):
        """注册表 RunOnce（复活备用）"""
        if sys.platform != "win32":
            return
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "AOTE_Respawn", 0, winreg.REG_SZ, f'"{target}" --daemon')
            winreg.CloseKey(key)
        except Exception as e:
            self.logger.debug(f"注册表RunOnce安装失败: {e}")

    def _install_scheduled_task(self):
        """安装计划任务（每5分钟检查进程）"""
        if sys.platform != "win32":
            return
        target = self._get_self_script_path()
        if not target:
            return
        # 创建 schtasks 命令
        task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>AOTE Guardian Respawn</Description></RegistrationInfo>
  <Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><Duration>P1D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>"{target}"</Command><Arguments>--respawn-check</Arguments></Exec></Actions>
</Task>"""
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-16") as f:
                f.write(task_xml)
                xml_path = f.name
            subprocess.run(
                ["schtasks", "/Create", "/TN", "AOTE Guardian", "/XML", xml_path, "/F"],
                capture_output=True, timeout=15,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            os.unlink(xml_path)
        except Exception as e:
            self.logger.debug(f"计划任务安装失败: {e}")

    # ============ 监控循环 ============
    def _monitor_loop(self):
        interval = int(self.config.get("watchdog.monitor_interval", 2))

        while not self._stop_event.is_set():
            try:
                # 1. 扩展心跳超时检查
                self._check_extension_heartbeat()

                # 2. 对方进程存活检查（双进程守护）
                self._check_partner_alive()

            except Exception as e:
                self.logger.error(f"[AntiTamper] 监控异常: {e}")

            self._stop_event.wait(interval)

    def _check_extension_heartbeat(self):
        """检查扩展心跳，超时则进入紧急模式"""
        elapsed = time.time() - self._last_extension_heartbeat
        if elapsed > self._heartbeat_timeout:
            if self.time_guard.current_mode != TimeGuard.MODE_EMERGENCY:
                self.logger.log_anti_tamper(
                    "extension_heartbeat_lost",
                    f"扩展心跳超时 {int(elapsed)}s，进入紧急模式"
                )
                self.time_guard.enter_emergency_mode("extension_heartbeat_lost")

    def _check_partner_alive(self):
        """检查对端进程是否存活"""
        if not self._partner_pid:
            return
        try:
            import psutil
            if not psutil.pid_exists(self._partner_pid):
                raise psutil.NoSuchProcess(self._partner_pid)
            # 再确认
            proc = psutil.Process(self._partner_pid)
            if not proc.is_running():
                raise Exception("not running")
        except Exception:
            # 对端进程已死
            self.logger.log_anti_tamper(
                "partner_killed",
                f"对端进程 {self._partner_pid} 已死亡，准备复活"
            )
            # 重启延迟
            delay = int(self.config.get("watchdog.restart_delay", 1))
            threading.Timer(delay, self._respawn_partner).start()

    def _respawn_partner(self):
        """复活对端进程"""
        try:
            script = self._get_self_script_path()
            if not script:
                return
            target = sys.executable if script.endswith(".py") else script
            args = [target]
            if script.endswith(".py"):
                args.append(script)
            # 如果我是watchdog，则复活主进程；反之复活watchdog
            if self._is_watchdog:
                args.append("--main")
            else:
                args.append("--watchdog")

            CREATE_NO_WINDOW = 0x08000000
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            creationflags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP

            proc = subprocess.Popen(
                args,
                creationflags=creationflags,
                close_fds=True
            )
            self._partner_pid = proc.pid
            self.logger.log_anti_tamper(
                "partner_respawned",
                f"已复活对端进程，新PID={proc.pid}"
            )
            if self._on_force_kill_detected:
                try:
                    self._on_force_kill_detected()
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"复活对端进程失败: {e}")

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

            def _custom_ok():
                val = custom_entry.get().strip()
                if val.isdigit() and int(val) > 0:
                    _choose_unlock(int(val) * 60)

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
        self._last_extension_heartbeat = time.time()  # 启动即算一次心跳
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="AntiTamper"
        )
        self._monitor_thread.start()
        self.logger.info("[AntiTamper] 防绕过模块已启动")

    def stop(self):
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)
        self.logger.info("[AntiTamper] 防绕过模块已停止")
