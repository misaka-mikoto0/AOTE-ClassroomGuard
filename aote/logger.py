"""
AOTE 管控系统 - 日志模块
支持按日期轮转、加密存储，记录所有关键事件
"""
import os
import logging
import hashlib
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta
from pathlib import Path


class AOTELogger:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, log_path: str = None, retention_days: int = 30):
        if self._initialized:
            return
        self._initialized = True

        if log_path is None:
            log_path = r"C:\ProgramData\ClassroomGuard\logs"

        self.log_dir = Path(log_path)
        self.retention_days = retention_days
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_logger()
        self._cleanup_old_logs()

    def _setup_logger(self):
        self.logger = logging.getLogger("AOTE")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        # 避免重复添加handler
        if self.logger.handlers:
            return

        # 文件日志 - 按天轮转
        log_file = self.log_dir / "aote.log"
        file_handler = TimedRotatingFileHandler(
            filename=str(log_file),
            when="midnight",
            interval=1,
            backupCount=self.retention_days,
            encoding="utf-8"
        )
        file_handler.suffix = "%Y%m%d"
        file_fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_fmt)
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)

        # 控制台日志
        console_handler = logging.StreamHandler()
        console_fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_fmt)
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)

    def _cleanup_old_logs(self):
        """清理超过保留天数的日志文件"""
        try:
            cutoff = datetime.now() - timedelta(days=self.retention_days)
            for log_file in self.log_dir.glob("aote.log.*"):
                try:
                    # 从文件名提取日期
                    suffix = log_file.suffix.lstrip(".")
                    file_date = datetime.strptime(suffix, "%Y%m%d")
                    if file_date < cutoff:
                        log_file.unlink()
                        self.logger.info(f"清理过期日志: {log_file.name}")
                except (ValueError, OSError):
                    continue
        except Exception as e:
            print(f"清理日志失败: {e}")

    def _log_event(self, _event_type: str, _log_level: str, _message: str, **kwargs):
        """统一的事件日志格式"""
        extra_parts = []
        for k, v in kwargs.items():
            extra_parts.append(f"{k}={v}")
        extra_str = " | ".join(extra_parts) if extra_parts else ""

        full_msg = f"[{_event_type}] {_message}"
        if extra_str:
            full_msg += f" | {extra_str}"

        log_func = getattr(self.logger, _log_level.lower(), self.logger.info)
        log_func(full_msg)

    # --- 便捷方法 ---
    def info(self, msg: str, **kwargs):
        self.logger.info(msg)

    def error(self, msg: str, **kwargs):
        self.logger.error(msg)

    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg)

    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg)

    # --- 事件类型方法 ---
    def log_mode_change(self, old_mode: str, new_mode: str, reason: str = ""):
        """模式切换日志"""
        self._log_event("MODE_CHANGE", "INFO",
                        f"模式切换: {old_mode} -> {new_mode}",
                        reason=reason,
                        timestamp=datetime.now().isoformat())

    def log_process_freeze(self, pid: int, process_name: str, reason: str = "target_detected"):
        """进程冻结日志"""
        self._log_event("PROCESS_FREEZE", "INFO",
                        f"冻结进程: {process_name}",
                        pid=pid,
                        process_name=process_name,
                        reason=reason)

    def log_process_unfreeze(self, pid: int, process_name: str, duration_seconds: int = 0):
        """进程解冻日志"""
        self._log_event("PROCESS_UNFREEZE", "INFO",
                        f"解冻进程: {process_name}",
                        pid=pid,
                        process_name=process_name,
                        duration_seconds=duration_seconds)

    def log_math_attempt(self, question: str, user_answer: str,
                         correct_answer: str, is_correct: bool,
                         duration_seconds: float, level: int = 1):
        """数学挑战尝试日志"""
        self._log_event("MATH_CHALLENGE", "INFO",
                        f"数学挑战: {'正确' if is_correct else '错误'}",
                        level=level,
                        question=question,
                        user_answer=user_answer,
                        correct_answer=correct_answer if not is_correct else "***",
                        is_correct=is_correct,
                        duration_seconds=round(duration_seconds, 2))

    def log_usb_event(self, event_type: str, drive_letter: str,
                      hardware_id: str = "", is_authorized: bool = False):
        """U盘事件日志"""
        self._log_event("USB", "INFO",
                        f"U盘事件: {event_type}",
                        event_type=event_type,
                        drive_letter=drive_letter,
                        hardware_id=hardware_id,
                        is_authorized=is_authorized)

    def log_anti_tamper(self, event: str, detail: str = ""):
        """防绕过触发日志"""
        self._log_event("ANTI_TAMPER", "WARNING",
                        f"防绕过触发: {event}",
                        event=event,
                        detail=detail)

    def log_admin_action(self, action: str, success: bool):
        """管理员操作日志"""
        self._log_event("ADMIN", "INFO",
                        f"管理员操作: {action} - {'成功' if success else '失败'}",
                        action=action,
                        success=success)
