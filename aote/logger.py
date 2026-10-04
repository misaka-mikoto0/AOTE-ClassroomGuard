"""
AOTE 管控系统 - 日志模块

支持按日期轮转、保留期清理，记录所有关键事件。

容错设计：日志目录/文件不可写时逐级回退（配置目录 -> %LOCALAPPDATA% ->
项目 logs -> 系统临时目录 -> 纯控制台），保证日志模块永不阻断主程序启动。
"""
import os
import sys
import logging
import threading
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

# 日志输出格式（控制台与文件共用）
_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
# 轮转文件名的日期后缀（aote.log.YYYYMMDD）
_ROTATE_SUFFIX = "%Y%m%d"
_LOG_FILE_NAME = "aote.log"
_LOGGER_NAME = "AOTE"
_DEFAULT_LOG_DIR = r"C:\ProgramData\ClassroomGuard\logs"


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


def _program_base_dir() -> Path:
    """程序根目录：PyInstaller 冻结时取 exe 所在目录，否则取项目根目录"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _fallback_log_dirs() -> List[Path]:
    """主日志目录不可用时的回退候选（按优先级）"""
    return [
        Path(os.path.expandvars(r"%LOCALAPPDATA%\ClassroomGuard\logs")),
        _program_base_dir() / "logs",
    ]


def _build_formatter() -> logging.Formatter:
    return logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT)


class AOTELogger:
    """AOTE 日志门面：单例，封装标准 logging 与统一的事件日志格式"""

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

    def __init__(self, log_path: Optional[str] = None, retention_days: int = 30,
                 rotate_when: str = "midnight"):
        if self._initialized:
            return
        with self._singleton_lock:
            if self._initialized:
                return
            self._initialized = True

        # 日志写入锁：多线程 flush 避免日志交叉错乱
        self._write_lock = threading.Lock()

        if log_path is None:
            log_path = _DEFAULT_LOG_DIR

        self.retention_days = retention_days
        # 日志轮转时机从 time_settings.log_rotate_when 读取（如 "midnight"）
        self._rotate_when = rotate_when or "midnight"
        self._fallback_reason: Optional[str] = None
        self.log_dir = self._probe_writable_dir([Path(log_path)] + _fallback_log_dirs())
        self._setup_logger()
        self._cleanup_old_logs()

    # ---------- 日志目录探测 ----------
    @staticmethod
    def _probe_writable_dir(candidate_dirs: List[Path]) -> Optional[Path]:
        """按优先级返回第一个可写日志文件的目录。
        直接探测 aote.log 的可写性（不是 .write_test），避免 sandbox 拦截差异。
        注意：mkdir 必须在 try 内！否则目录存在但无访问权限（如 admin 创建的
        %LOCALAPPDATA%\\ClassroomGuard 被非 admin 进程访问）时，
        PermissionError 会逃逸导致主程序启动即崩溃。
        """
        for cand in candidate_dirs:
            try:
                cand.mkdir(parents=True, exist_ok=True)
                # 尝试以追加模式打开实际日志文件
                with open(cand / _LOG_FILE_NAME, "a", encoding="utf-8") as f:
                    f.flush()
                return cand
            except (PermissionError, OSError):
                continue
        # 终极兜底：系统临时目录（任何用户均可写），保证日志模块永不导致主程序崩溃
        try:
            import tempfile
            tmp_cand = Path(tempfile.gettempdir()) / "ClassroomGuard" / "logs"
            tmp_cand.mkdir(parents=True, exist_ok=True)
            with open(tmp_cand / _LOG_FILE_NAME, "a", encoding="utf-8") as f:
                f.flush()
            return tmp_cand
        except Exception:
            return None

    # ---------- logger 装配 ----------
    def _setup_logger(self):
        self.logger = logging.getLogger(_LOGGER_NAME)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if self.logger.handlers:
            return

        # 始终添加控制台输出（INFO 级），方便直接观察运行日志
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(_build_formatter())
        stream_handler.setLevel(logging.INFO)
        self.logger.addHandler(stream_handler)

        if self.log_dir is None:
            # 所有磁盘路径均不可用：仅控制台输出，保证日志模块绝不崩溃主程序
            stream_handler.setLevel(logging.DEBUG)
            self._fallback_reason = "所有日志路径均不可用，仅使用控制台输出"
            self._report_fallback()
            return

        file_handler = self._build_file_handler()
        if hasattr(file_handler, "suffix"):
            file_handler.suffix = _ROTATE_SUFFIX
        file_handler.setFormatter(_build_formatter())
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        if self._fallback_reason:
            self._report_fallback()

    def _build_file_handler(self) -> logging.Handler:
        """构建文件 handler：主日志不可写时回退候选目录，全部失败降级为 NullHandler"""
        try:
            handler: logging.Handler = self._new_rotating_handler(
                self.log_dir / _LOG_FILE_NAME
            )
            self._emit_probe(handler, "文件日志初始化验证")
            return handler
        except (PermissionError, OSError) as e:
            # 主日志文件不可写：尝试候选列表中的其他目录
            for cand in _fallback_log_dirs():
                try:
                    cand.mkdir(parents=True, exist_ok=True)
                    handler = self._new_rotating_handler(cand / _LOG_FILE_NAME)
                    self._emit_probe(handler, "文件日志回退验证")
                    self.log_dir = cand
                    self._fallback_reason = f"主日志文件不可写({e})，回退到 {cand}"
                    return handler
                except (PermissionError, OSError):
                    continue
            self._fallback_reason = f"所有日志路径均不可写，禁用文件日志 ({e})"
            return logging.NullHandler()

    def _new_rotating_handler(self, log_file: Path) -> TimedRotatingFileHandler:
        return _ResilientTimedRotatingFileHandler(
            filename=str(log_file),
            when=self._rotate_when,
            interval=1,
            backupCount=self.retention_days,
            encoding="utf-8"
        )

    @staticmethod
    def _emit_probe(handler: logging.Handler, message: str):
        """创建后立即写入一条测试日志，验证 stream 真的可写
        （某些 sandbox 会返回无效句柄而不抛异常）"""
        handler.emit(logging.LogRecord(
            _LOGGER_NAME, logging.INFO, __file__, 0,
            f"[AOTELogger] {message}", None, None
        ))

    def _report_fallback(self):
        """回退原因：同时写 stderr 与日志，保证连文件都不可写时仍可见"""
        print(f"[AOTELogger] {self._fallback_reason}", file=sys.stderr, flush=True)
        self.logger.warning(self._fallback_reason)

    def _cleanup_old_logs(self):
        """清理超过保留天数的日志文件"""
        if self.log_dir is None:
            return
        try:
            cutoff = datetime.now() - timedelta(days=self.retention_days)
            for log_file in self.log_dir.glob(f"{_LOG_FILE_NAME}.*"):
                try:
                    # 从文件名提取日期
                    suffix = log_file.suffix.lstrip(".")
                    file_date = datetime.strptime(suffix, _ROTATE_SUFFIX)
                    if file_date < cutoff:
                        log_file.unlink()
                        self.logger.info(f"清理过期日志: {log_file.name}")
                except (ValueError, OSError):
                    continue
        except Exception as e:
            print(f"清理日志失败: {e}")

    # ---------- 统一事件格式 ----------
    def _log_event(self, _event_type: str, _log_level: str, _message: str, **kwargs):
        """统一的事件日志格式"""
        extra_str = " | ".join(f"{k}={v}" for k, v in kwargs.items())
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

    def log_browser_intercept(self, url: str, reason: str, mode: str = ""):
        """浏览器内容拦截日志（替代原进程冻结日志）"""
        self._log_event("BROWSER_BLOCK", "INFO",
                        f"浏览器拦截: {url}",
                        url=url,
                        reason=reason,
                        mode=mode)

    def log_browser_unlock(self, url: str, seconds: int = 0):
        """浏览器解锁日志"""
        self._log_event("BROWSER_UNLOCK", "INFO",
                        f"浏览器解锁: {url}",
                        url=url,
                        seconds=seconds)

    def log_weak_network(self, action: str, host: str = "",
                         latency_ms: int = 0, download_kbps: int = 0,
                         upload_kbps: int = 0):
        """弱网切换日志：action 为 'activate'（命中黑名单切换弱网）或 'restore'（恢复网络）"""
        self._log_event("WEAK_NETWORK", "WARNING" if action == "activate" else "INFO",
                        f"弱网管控: {action} {host}".strip(),
                        action=action,
                        host=host,
                        latency_ms=latency_ms,
                        download_kbps=download_kbps,
                        upload_kbps=upload_kbps)

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
