"""
AOTE 管控系统 - 时间调度模块（Time Guard）

根据课程表自动判断当前是否处于上课时间，控制严格/宽松模式切换。

紧急模式由防绕过模块触发，期间时间调度不再自动切换模式。
"""
import threading
from datetime import datetime
from functools import lru_cache
from typing import Callable, Optional

from .config import ConfigManager
from .logger import AOTELogger

# 停止守护线程时的最大等待时间（秒）
_STOP_JOIN_TIMEOUT = 2.0


class TimeGuard:
    """时间调度守护者，管理上课/下课时间判断"""

    # 系统模式常量
    MODE_STRICT = "strict"       # 严格模式：非上课时间
    MODE_RELAXED = "relaxed"     # 宽松模式：上课时间
    MODE_EMERGENCY = "emergency" # 紧急模式：扩展失效/防护触发
    MODE_EXEMPT = "exempt"       # 豁免时间段：所有限制暂停（窗口结束自动恢复）

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

    # ---------- 状态查询 ----------
    @property
    def current_mode(self) -> str:
        return self._current_mode

    @property
    def is_strict_mode(self) -> bool:
        return self._current_mode == self.MODE_STRICT

    @property
    def is_relaxed_mode(self) -> bool:
        return self._current_mode == self.MODE_RELAXED

    @property
    def is_exempt_mode(self) -> bool:
        return self._current_mode == self.MODE_EXEMPT

    def set_on_mode_change(self, callback: Callable[[str, str], None]):
        """设置模式变更回调: callback(old_mode, new_mode)"""
        self._on_mode_change = callback

    # ---------- 模式切换 ----------
    def _set_mode(self, new_mode: str, reason: str = ""):
        """切换模式（目标与当前相同时静默返回）"""
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
        # 立即重新判断模式（豁免窗口优先于课表）
        new_mode, _ = self._scheduled_mode()
        self._set_mode(new_mode, "emergency_cleared")

    # ---------- 时间判断 ----------
    @staticmethod
    @lru_cache(maxsize=512)
    def _parse_time(time_str: str) -> tuple:
        """解析 HH:MM 格式时间为 (hour, minute)（结果缓存，避免每轮重复解析）"""
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
        # 跨天：[start, 24:00) ∪ [00:00, end)
        return now_minutes >= start_minutes or now_minutes < end_minutes

    def _is_class_time_now(self) -> bool:
        """判断当前是否为上课时间（例外日优先级高于星期课表）"""
        now = datetime.now()

        # 1. 先检查例外日配置
        exceptions = self.config.get("schedule.exceptions", {}) or {}
        today_str = now.strftime("%Y-%m-%d")
        status = exceptions.get(today_str) if isinstance(exceptions, dict) else None
        if status == "holiday":
            return False  # 全天放假
        if status == "classday":
            return True   # 全天上课

        # 2. 按星期判断
        weekday = now.isoweekday()  # 1=周一, 7=周日
        time_ranges = self.config.get(f"schedule.weekday.{weekday}", []) or []
        return any(
            self._is_time_in_range(now, start_str, end_str)
            for start_str, end_str in time_ranges
        )

    def _is_exempt_now(self) -> bool:
        """当前是否落在豁免时间段内（exempt_windows 配置驱动）。

        判定顺序（任一不满足即不豁免）：
          1. enabled 总开关
          2. exclude_dates 命中 -> 该日整体不豁免（优先级最高）
          3. dates 非空时，仅这些日期生效
          4. weekdays 非空时，仅这些星期生效（按判定时刻所在日计算）
          5. time_ranges 任一命中（跨天窗口由 _is_time_in_range 统一处理）
        窗口列表为空 = 功能未配置，视为不豁免（保持原有全部限制）。
        """
        cfg = self.config.get("exempt_windows", {}) or {}
        if not isinstance(cfg, dict) or not bool(cfg.get("enabled", True)):
            return False

        ranges = cfg.get("time_ranges") or []
        if not ranges:
            return False

        now = datetime.now()
        today = now.strftime("%Y-%m-%d")

        exclude = {str(d).strip() for d in (cfg.get("exclude_dates") or [])}
        if today in exclude:
            return False

        dates = {str(d).strip() for d in (cfg.get("dates") or [])}
        if dates and today not in dates:
            return False

        weekdays = cfg.get("weekdays")
        if isinstance(weekdays, (list, tuple)) and len(weekdays) > 0:
            try:
                allowed_days = {int(w) for w in weekdays}
            except (TypeError, ValueError):
                allowed_days = set()
            if allowed_days and now.isoweekday() not in allowed_days:
                return False

        for rng in ranges:
            try:
                start_str, end_str = str(rng[0]), str(rng[1])
            except (TypeError, IndexError, KeyError):
                continue
            try:
                if self._is_time_in_range(now, start_str, end_str):
                    return True
            except Exception as e:
                self.logger.error(f"豁免时间段解析失败 {rng}: {e}")
        return False

    def _is_class_time_exempt(self) -> bool:
        """上课时间是否按"豁免"处理（exempt_windows.class_time_exempt，默认开）。

        语义：上课时段不纳入常规限制计算，直接视为已获豁免 -> 所有限制暂停。
        与 MODE_RELAXED（宽松放行）的区别：宽松仍会执行"始终生效"的主题/游戏
        关键词/标题正则规则，而豁免会让它们一并暂停。
        """
        return bool(self.config.get("exempt_windows.class_time_exempt", True))

    def _scheduled_mode(self) -> tuple:
        """按 豁免窗口 / 课表 计算"当前应有的模式"，返回 (模式, 原因)。

        优先级：豁免时间段 > 上课时间（按 class_time_exempt 决定）> 非上课严格模式。
        返回原因是为了日志可分辨"配置的豁免窗口"与"上课时间视为豁免"两种情况。
        """
        if self._is_exempt_now():
            return self.MODE_EXEMPT, "exempt_window"
        if self._is_class_time_now():
            if self._is_class_time_exempt():
                return self.MODE_EXEMPT, "class_time_exempt"
            return self.MODE_RELAXED, "class_time"
        return self.MODE_STRICT, "after_school"

    # ---------- 调度周期 ----------
    def do_check(self):
        """执行一次时间检查并更新模式"""
        if self._emergency_forced:
            return  # 紧急模式下不自动切换（豁免窗口也不覆盖紧急模式）

        new_mode, reason = self._scheduled_mode()
        if self._current_mode != new_mode:
            self._set_mode(new_mode, reason)

    def _check_loop(self):
        """时间检查循环（间隔从 time_settings.time_check_interval 读取）"""
        interval = max(float(self.config.get("time_settings.time_check_interval", 5)), 0.5)
        while not self._stop_event.is_set():
            try:
                self.do_check()
            except Exception as e:
                self.logger.error(f"时间调度检查异常: {e}")
            self._stop_event.wait(interval)

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
            self._check_thread.join(timeout=_STOP_JOIN_TIMEOUT)
        self.logger.info("[TimeGuard] 时间调度模块已停止")
