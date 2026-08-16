"""
AOTE 管控系统 - 时间调度模块（Time Guard）
根据课程表自动判断当前是否处于上课时间，控制严格/宽松模式切换
"""
import threading
import time
from datetime import datetime, date
from typing import Callable, Optional, List

from .config import ConfigManager
from .logger import AOTELogger


class TimeGuard:
    """时间调度守护者，管理上课/下课时间判断"""

    # 系统模式常量
    MODE_STRICT = "strict"       # 严格模式：非上课时间
    MODE_RELAXED = "relaxed"     # 宽松模式：上课时间
    MODE_EMERGENCY = "emergency" # 紧急模式：扩展失效/防护触发

    def __init__(self, config: ConfigManager, logger: AOTELogger):
        self.config = config
        self.logger = logger

        self._current_mode: str = self.MODE_STRICT
        self._stop_event = threading.Event()
        self._check_thread: Optional[threading.Thread] = None

        # 模式变更回调
        self._on_mode_change: Optional[Callable[[str, str], None]] = None

        # 紧急模式标记（被Anti-Tamper触发的紧急模式不受时间调度影响）
        self._emergency_forced = False

    @property
    def current_mode(self) -> str:
        return self._current_mode

    @property
    def is_strict_mode(self) -> bool:
        return self._current_mode == self.MODE_STRICT

    @property
    def is_relaxed_mode(self) -> bool:
        return self._current_mode == self.MODE_RELAXED

    def set_on_mode_change(self, callback: Callable[[str, str], None]):
        """设置模式变更回调: callback(old_mode, new_mode)"""
        self._on_mode_change = callback

    def _set_mode(self, new_mode: str, reason: str = ""):
        """切换模式"""
        if self._current_mode == new_mode:
            return

        old_mode = self._current_mode
        self._current_mode = new_mode
        self.logger.log_mode_change(old_mode, new_mode, reason)

        if self._on_mode_change:
            try:
                self._on_mode_change(old_mode, new_mode)
            except Exception as e:
                self.logger.error(f"模式变更回调异常: {e}")

    def enter_emergency_mode(self, reason: str = ""):
        """进入紧急模式（由防绕过模块触发）"""
        self._emergency_forced = True
        self._set_mode(self.MODE_EMERGENCY, reason or "emergency_triggered")

    def exit_emergency_mode(self):
        """退出紧急模式，恢复到按时间调度的模式"""
        self._emergency_forced = False
        # 立即重新判断模式
        is_class = self._is_class_time_now()
        new_mode = self.MODE_RELAXED if is_class else self.MODE_STRICT
        self._set_mode(new_mode, "emergency_cleared")

    def _parse_time(self, time_str: str) -> tuple[int, int]:
        """解析 HH:MM 格式时间为 (hour, minute)"""
        h, m = time_str.strip().split(":")
        return int(h), int(m)

    def _is_time_in_range(self, now: datetime, start_str: str, end_str: str) -> bool:
        """判断当前时间是否在时间段内（支持跨天：如 22:00-06:00 表示晚22点到次日凌晨6点）"""
        sh, sm = self._parse_time(start_str)
        eh, em = self._parse_time(end_str)

        now_minutes = now.hour * 60 + now.minute
        start_minutes = sh * 60 + sm
        end_minutes = eh * 60 + em

        if end_minutes == start_minutes:
            # 起点=终点（配置错误）视为24小时有效
            return True

        if end_minutes > start_minutes:
            # 同一天内：[start, end)
            return start_minutes <= now_minutes < end_minutes
        else:
            # 跨天：[start, 24:00) ∪ [00:00, end)
            return now_minutes >= start_minutes or now_minutes < end_minutes

    def _is_class_time_now(self) -> bool:
        """判断当前是否为上课时间"""
        now = datetime.now()
        today_str = now.strftime("%Y-%m-%d")

        # 1. 先检查例外日配置
        exceptions = self.config.get("schedule.exceptions", {})
        if today_str in exceptions:
            status = exceptions[today_str]
            if status == "holiday":
                return False  # 全天放假
            elif status == "classday":
                return True   # 全天上课

        # 2. 按星期判断
        weekday = now.isoweekday()  # 1=周一, 7=周日
        schedule_key = f"schedule.weekday.{weekday}"
        time_ranges = self.config.get(schedule_key, [])

        for start_str, end_str in time_ranges:
            if self._is_time_in_range(now, start_str, end_str):
                return True

        return False

    def do_check(self):
        """执行一次时间检查并更新模式"""
        if self._emergency_forced:
            return  # 紧急模式下不自动切换

        is_class = self._is_class_time_now()
        new_mode = self.MODE_RELAXED if is_class else self.MODE_STRICT

        if self._current_mode != new_mode:
            reason = "class_time" if is_class else "after_school"
            self._set_mode(new_mode, reason)

    def _check_loop(self):
        """时间检查循环（每5秒）"""
        # 启动时立即执行一次检查
        self.do_check()

        while not self._stop_event.is_set():
            try:
                self.do_check()
            except Exception as e:
                self.logger.error(f"时间调度检查异常: {e}")
            self._stop_event.wait(5)

    def start(self):
        """启动时间调度守护线程"""
        if self._check_thread and self._check_thread.is_alive():
            return
        self._stop_event.clear()
        self._check_thread = threading.Thread(
            target=self._check_loop,
            daemon=True,
            name="TimeGuard"
        )
        self._check_thread.start()
        self.logger.info("[TimeGuard] 时间调度模块已启动")

    def stop(self):
        """停止时间调度"""
        self._stop_event.set()
        if self._check_thread:
            self._check_thread.join(timeout=2)
        self.logger.info("[TimeGuard] 时间调度模块已停止")
