"""
AOTE 管控系统 - 日志模块
支持按日期轮转、加密存储，记录所有关键事件
"""
import os
import time
import logging
import hashlib
import threading
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta
from pathlib import Path


class _ResilientTimedRotatingFileHandler(TimedRotatingFileHandler):
    """TimedRotatingFileHandler 子类：在轮转失败（如 admin 进程遗留日志文件被非 admin 进程访问时
    os.rename 报 WinError 5）时不抛错，避免每条日志都触发 handleError 噪声。"""

    def rotate(self, source, dest):
        try:
            super().rotate(source, dest)
        except (PermissionError, OSError):
            # 轮转失败则放弃这次滚动，继续向当前文件追加，后续进程有权限时再补偿
            pass

    def shouldRollover(self, record):
        # 即使应该轮转，若上次轮转失败，本轮也不再尝试（避免每条日志都触发 PermissionError 噪声）
        try:
            return super().shouldRollover(record)
        except (PermissionError, OSError):
            return False


class AOTELogger:
    _instance = None
    _initialized = False
    _singleton_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        # 双重检查锁定：线程安全的单例创建
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, log_path: str = None, retention_days: int = 30):
        if self._initialized:
            return
        with self._singleton_lock:
            if self._initialized:
                return
            self._initialized = True

        # 日志写入锁：多线程 flush 避免日志交叉错乱
        self._write_lock = threading.Lock()

        if log_path is None:
            log_path = r"C:\ProgramData\ClassroomGuard\logs"

        self.retention_days = retention_days
        self._fallback_reason = None
        # 候选日志目录：按优先级尝试，第一个能成功写入 aote.log 的就用
        project_logs = Path(__file__).resolve().parent.parent / "logs"
        candidate_dirs = [
            Path(log_path),
            Path(os.path.expandvars(r"%LOCALAPPDATA%\ClassroomGuard\logs")),
            project_logs,
        ]
        # 直接探测 aote.log 的可写性（不是 .write_test），避免 sandbox 拦截差异
        # 注意：mkdir 必须在 try 内！否则目录存在但无访问权限（如 admin 创建的
        # %LOCALAPPDATA%\ClassroomGuard 被非 admin 进程访问）时，
        # PermissionError 会逃逸导致主程序启动即崩溃。
        self.log_dir = None
        for cand in candidate_dirs:
            try:
                cand.mkdir(parents=True, exist_ok=True)
                log_file = cand / "aote.log"
                # 尝试以追加模式打开实际日志文件
                with open(log_file, "a", encoding="utf-8") as f:
                    f.flush()
                self.log_dir = cand
                if cand != Path(log_path):
                    self._fallback_reason = f"主日志目录 {log_path} 不可写，回退到 {cand}"
                break
            except (PermissionError, OSError):
                continue
        if self.log_dir is None:
            # 终极兜底：系统临时目录（任何用户均可写），保证日志模块永不导致主程序崩溃
            try:
                import tempfile
                tmp_cand = Path(tempfile.gettempdir()) / "ClassroomGuard" / "logs"
                tmp_cand.mkdir(parents=True, exist_ok=True)
                with open(tmp_cand / "aote.log", "a", encoding="utf-8") as f:
                    f.flush()
                self.log_dir = tmp_cand
                self._fallback_reason = f"候选日志目录均不可写，回退到临时目录 {tmp_cand}"
            except Exception:
                self.log_dir = None
                self._fallback_reason = "所有日志路径均不可用，仅使用控制台输出"
        self._setup_logger()
        self._cleanup_old_logs()

    def _setup_logger(self):
        self.logger = logging.getLogger("AOTE")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if self.logger.handlers:
            return

        if self.log_dir is None:
            # 所有磁盘路径均不可用：仅控制台输出，保证日志模块绝不崩溃主程序
            stream_handler = logging.StreamHandler()
            stream_fmt = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            stream_handler.setFormatter(stream_fmt)
            stream_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(stream_handler)
            import sys
            print(f"[AOTELogger] {self._fallback_reason}", file=sys.stderr, flush=True)
            self.logger.warning(self._fallback_reason)
            return

        log_file = self.log_dir / "aote.log"
        file_handler = None
        try:
            file_handler = _ResilientTimedRotatingFileHandler(
                filename=str(log_file),
                when="midnight",
                interval=1,
                backupCount=self.retention_days,
                encoding="utf-8"
            )
            # 创建后立即写入一条测试日志，验证 stream 真的可写
            # （某些 sandbox 会返回无效句柄而不抛异常）
            file_handler.emit(logging.LogRecord(
                "AOTE", logging.INFO, __file__, 0,
                "[AOTELogger] 文件日志初始化验证", None, None
            ))
        except (PermissionError, OSError) as e:
            # 主日志文件不可写：尝试候选列表中的其他目录
            project_logs = Path(__file__).resolve().parent.parent / "logs"
            for cand in [Path(os.path.expandvars(r"%LOCALAPPDATA%\ClassroomGuard\logs")), project_logs]:
                try:
                    cand.mkdir(parents=True, exist_ok=True)
                    log_file = cand / "aote.log"
                    file_handler = _ResilientTimedRotatingFileHandler(
                        filename=str(log_file),
                        when="midnight",
                        interval=1,
                        backupCount=self.retention_days,
                        encoding="utf-8"
                    )
                    file_handler.emit(logging.LogRecord(
                        "AOTE", logging.INFO, __file__, 0,
                        "[AOTELogger] 文件日志回退验证", None, None
                    ))
                    self.log_dir = cand
                    self._fallback_reason = f"主日志文件不可写({e})，回退到 {cand}"
                    break
                except (PermissionError, OSError):
                    file_handler = None
                    continue
            if file_handler is None:
                file_handler = logging.NullHandler()
                self._fallback_reason = f"所有日志路径均不可写，禁用文件日志 ({e})"
        if hasattr(file_handler, "suffix"):
            file_handler.suffix = "%Y%m%d"
        file_fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_fmt)
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        if self._fallback_reason:
            import sys
            print(f"[AOTELogger] {self._fallback_reason}", file=sys.stderr, flush=True)
            self.logger.warning(self._fallback_reason)

    def _cleanup_old_logs(self):
        """清理超过保留天数的日志文件"""
        if self.log_dir is None:
            return
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
