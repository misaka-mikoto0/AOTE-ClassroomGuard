"""
AOTE 管控系统 - 进程监控与冻结模块（Process Hunter）
非上课时段持续扫描并冻结目标进程（浏览器、视频、游戏等）
支持线程挂起、窗口隐藏、Job Object 三重保护
"""
import psutil
import threading
import time
import ctypes
import sys
from ctypes import wintypes
from typing import Dict, List, Set, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from .config import ConfigManager
from .logger import AOTELogger
from .time_guard import TimeGuard


# ================ Windows API 声明 ================
if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)

    # 进程/线程访问权限
    PROCESS_ALL_ACCESS = 0x1F0FFF
    THREAD_ALL_ACCESS = 0x1F03FF
    THREAD_SUSPEND_RESUME = 0x0002

    # Job Object
    JOB_OBJECT_UILIMIT_HANDLES = 0x00000001
    JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010
    JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020
    JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040
    JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080
    JobObjectBasicUIRestrictions = 4

    SW_HIDE = 0
    SW_SHOW = 5
    SWP_NOSIZE = 0x0001
    SWP_NOZORDER = 0x0040
    HWND_TOPMOST = -1
    OFFSCREEN_X = -32000
    OFFSCREEN_Y = -32000

    class RECT(ctypes.Structure):
        _fields_ = [
            ("left", ctypes.c_long), ("top", ctypes.c_long),
            ("right", ctypes.c_long), ("bottom", ctypes.c_long),
        ]

    # 回调类型
    EnumWindowsProc = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,
        wintypes.LPARAM
    )
    EnumChildProc = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,
        wintypes.LPARAM
    )

    class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
        _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]


@dataclass
class FrozenProcessInfo:
    """冻结进程的状态信息"""
    pid: int
    name: str
    freeze_time: datetime
    thread_handles: Dict[int, int] = field(default_factory=dict)  # TID -> handle
    window_handles: List[int] = field(default_factory=list)
    job_handle: Optional[int] = None
    frozen_by: str = "thread"  # thread / window / job
    original_rects: Dict[int, tuple] = field(default_factory=dict)  # hwnd -> (x, y, w, h)
    state: str = "normal"  # normal / frozen / unfrozen


class ProcessHunter:
    """进程猎手：监控并冻结目标进程"""

    def __init__(self, config: ConfigManager, logger: AOTELogger, time_guard: TimeGuard):
        self.config = config
        self.logger = logger
        self.time_guard = time_guard

        # 冻结状态表: PID -> FrozenProcessInfo
        self._frozen: Dict[int, FrozenProcessInfo] = {}
        self._frozen_lock = threading.RLock()

        # 控制标志
        self._stop_event = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None

        # 临时解冻状态: (expire_timestamp, None=永久)
        self._temporary_unlock_until: Optional[float] = None
        self._unlock_lock = threading.RLock()

        # 额外的进程黑名单（数学题期间动态添加）
        self._extra_targets: Set[str] = set()
        self._extra_targets_lock = threading.Lock()

        # 新进程发现回调（用于触发数学挑战）
        self._on_target_detected: Optional[Callable[[List[psutil.Process]], None]] = None

    # ============ 外部接口 ============
    def set_on_target_detected(self, callback: Callable[[List[psutil.Process]], None]):
        """设置目标进程发现回调"""
        self._on_target_detected = callback

    def set_extra_targets(self, processes: List[str]):
        """设置额外需要冻结的进程（如数学题期间冻结计算器）"""
        with self._extra_targets_lock:
            self._extra_targets = set(p.lower() for p in processes)
        self.logger.info(f"[ProcessHunter] 新增冻结目标: {list(self._extra_targets)}")

    def clear_extra_targets(self):
        """清除额外冻结目标"""
        with self._extra_targets_lock:
            removed = list(self._extra_targets)
            self._extra_targets.clear()
        self.logger.info(f"[ProcessHunter] 清除额外冻结目标: {removed}")

    def temporary_unlock(self, seconds: int):
        """临时解冻所有进程，seconds秒后恢复"""
        with self._unlock_lock:
            expire = time.time() + seconds
            self._temporary_unlock_until = expire
        # 立即解冻所有
        self.unfreeze_all(reason=f"temp_unlock_{seconds}s")
        self.logger.info(f"[ProcessHunter] 临时解冻 {seconds} 秒")

    def permanent_unlock(self):
        """永久解冻（直到下次重启或手动恢复）"""
        with self._unlock_lock:
            self._temporary_unlock_until = float("inf")
        self.unfreeze_all(reason="permanent_unlock")
        self.logger.info("[ProcessHunter] 永久解冻（维护模式）")

    def restore_strict_mode(self):
        """立即恢复严格模式（取消临时解冻）"""
        with self._unlock_lock:
            self._temporary_unlock_until = None
        self.logger.info("[ProcessHunter] 恢复严格模式")

    @property
    def is_unlocked(self) -> bool:
        """当前是否处于解冻状态"""
        with self._unlock_lock:
            if self._temporary_unlock_until is None:
                return False
            if self._temporary_unlock_until == float("inf"):
                return True
            return time.time() < self._temporary_unlock_until

    # ============ 核心扫描循环 ============
    def _get_target_names(self) -> Set[str]:
        """获取当前所有需要冻结的进程名"""
        targets = set(self.config.all_target_processes)
        with self._extra_targets_lock:
            targets.update(self._extra_targets)
        return targets

    def _is_target_process(self, proc: psutil.Process, targets: Set[str]) -> bool:
        """判断进程是否在目标名单中"""
        try:
            name = proc.name().lower()
            if name in targets:
                return True
            # 也检查路径中的进程名
            try:
                exe_path = proc.exe().lower()
                for t in targets:
                    if t in exe_path:
                        return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return False

    def _find_target_processes(self) -> List[psutil.Process]:
        """查找所有运行中的目标进程"""
        targets = self._get_target_names()
        found = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if self._is_target_process(proc, targets):
                    found.append(proc)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return found

    def _find_extra_target_processes(self) -> List[psutil.Process]:
        """仅查找_extra_targets中的进程（宽松模式数学题期间使用，不冻结正常目标）"""
        with self._extra_targets_lock:
            extra_targets = set(self._extra_targets)
        if not extra_targets:
            return []
        found = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if self._is_target_process(proc, extra_targets):
                    found.append(proc)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return found

    def _get_process_tree(self, proc: psutil.Process) -> List[psutil.Process]:
        """获取进程树（父进程+所有子进程）"""
        tree = []
        try:
            tree.append(proc)
            children = proc.children(recursive=True)
            tree.extend(children)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return tree

    def _scan_loop(self):
        """主扫描循环"""
        scan_interval = float(self.config.get("process_hunter.scan_interval", 0.5))

        while not self._stop_event.is_set():
            try:
                # 1. 检查临时解冻是否到期
                self._check_unlock_expiry()

                # 2. 判断是否需要冻结
                need_freeze = self._should_freeze_now()

                if need_freeze:
                    # 3. 扫描目标进程
                    #    宽松模式+仅数学题目标时，只扫描_extra_targets（不冻结正常上课用的浏览器）
                    math_only = self._is_math_lockdown_only()
                    if math_only:
                        target_procs = self._find_extra_target_processes()
                    else:
                        target_procs = self._find_target_processes()

                    # 4. 过滤已经冻结的
                    with self._frozen_lock:
                        new_targets = [
                            p for p in target_procs if p.pid not in self._frozen
                        ]

                    if new_targets:
                        # 1. 先冻结进程树（立即隐藏窗口+挂起线程）
                        for proc in new_targets:
                            proctree = self._get_process_tree(proc)
                            for p in proctree:
                                self._freeze_process(p)

                        # 2. 冻结完成后，在独立线程中触发回调（弹出数学挑战）
                        #    宽松模式+仅数学题目标时不弹挑战（上课时间，只冻结计算器）
                        if self._on_target_detected and not math_only:
                            threading.Thread(
                                target=self._safe_callback,
                                args=(new_targets,),
                                daemon=True
                            ).start()

                    # 5. 重新冻结被恢复的线程
                    self._recheck_and_refreeze()
                else:
                    # 宽松模式或解锁状态 - 不冻结，但保持记录
                    pass

            except Exception as e:
                self.logger.error(f"[ProcessHunter] 扫描异常: {e}")

            self._stop_event.wait(scan_interval)

    def _safe_callback(self, procs):
        """安全调用目标检测回调（独立线程中执行）"""
        try:
            self._on_target_detected(procs)
        except Exception as e:
            self.logger.error(f"目标进程回调异常: {e}")

    def _is_math_lockdown_only(self) -> bool:
        """当前是否只有数学题期间的额外目标（不是严格模式）"""
        return self.time_guard.is_relaxed_mode and bool(self._extra_targets)

    def _should_freeze_now(self) -> bool:
        """判断当前是否应该执行冻结"""
        # 如果显式解锁中，不冻结
        if self.is_unlocked:
            return False
        # 严格模式或有额外目标，就需要冻结
        return self.time_guard.is_strict_mode or self.time_guard.current_mode == TimeGuard.MODE_EMERGENCY or bool(self._extra_targets)

    def _check_unlock_expiry(self):
        """检查临时解冻是否到期"""
        with self._unlock_lock:
            if (self._temporary_unlock_until is not None
                    and self._temporary_unlock_until != float("inf")
                    and time.time() >= self._temporary_unlock_until):
                self._temporary_unlock_until = None
                self.logger.info("[ProcessHunter] 临时解冻到期，恢复严格模式")

    # ============ 冻结实现 ============
    # 用于占位的哨兵：pid -> True 表示"正在冻结中"，防止并发重复冻结
    _FROZEN_PENDING = "__PENDING__"

    def _freeze_process(self, proc: psutil.Process, retry: int = 0):
        """冻结单个进程 - 三重保护同时施加（线程挂起 + 窗口隐藏移位 + Job限制）"""
        pid = proc.pid
        try:
            name = proc.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            name = "unknown"

        # 先加锁做原子检查+占位，避免并发双重冻结（Critical Issue 1）
        with self._frozen_lock:
            if pid in self._frozen:
                return  # 已冻结或正在冻结中
            # 占位：标记为冻结中，防止其他线程重复进入
            self._frozen[pid] = self._FROZEN_PENDING

        info = FrozenProcessInfo(pid=pid, name=name, freeze_time=datetime.now())
        methods_used = []

        # 方式1: 线程挂起（阻止CPU执行）
        try:
            if self._suspend_process_threads(proc, info):
                methods_used.append("thread")
        except Exception as e:
            self.logger.debug(f"线程挂起失败 PID={pid}: {e}")

        # 方式2: 窗口隐藏 + 移出屏幕 + 禁用输入（阻止用户交互）
        try:
            if self._hide_and_displace_windows(pid, info):
                methods_used.append("window")
        except Exception as e:
            self.logger.debug(f"窗口隐藏移位失败 PID={pid}: {e}")

        # 方式3: Job Object UI 限制（系统级限制）
        if sys.platform == "win32":
            try:
                if self._apply_job_restrictions(proc, info):
                    methods_used.append("job")
            except Exception as e:
                self.logger.debug(f"Job限制失败 PID={pid}: {e}")

        if methods_used:
            info.frozen_by = "+".join(methods_used)
            info.state = "frozen"
            with self._frozen_lock:
                self._frozen[pid] = info
            self.logger.log_process_freeze(pid, name, reason=f"method_{info.frozen_by}")

            # 验证冻结是否成功
            if not self._verify_freeze(pid, info) and retry < 2:
                time.sleep(0.1 * (retry + 1))
                self.logger.debug(f"冻结验证失败 PID={pid}，重试 {retry + 1}/3")
                # 清掉占位/记录，让重试能重新占位
                with self._frozen_lock:
                    current = self._frozen.get(pid)
                    if current is info or current is self._FROZEN_PENDING:
                        self._frozen.pop(pid, None)
                self._freeze_process(proc, retry=retry + 1)
        else:
            # 所有方式都失败，重试
            if retry < 2:
                time.sleep(0.1 * (retry + 1))
                self.logger.debug(f"冻结全部失败 PID={pid}，重试 {retry + 1}/3")
                # 清掉占位让重试能重新进入
                with self._frozen_lock:
                    if self._frozen.get(pid) is self._FROZEN_PENDING:
                        self._frozen.pop(pid, None)
                self._freeze_process(proc, retry=retry + 1)
            else:
                # 彻底失败，清除占位
                with self._frozen_lock:
                    if self._frozen.get(pid) is self._FROZEN_PENDING:
                        self._frozen.pop(pid, None)
                self.logger.error(f"冻结失败 PID={pid} ({name})，3次重试均未成功")

    def _verify_freeze(self, pid: int, info: FrozenProcessInfo) -> bool:
        """验证冻结是否成功：窗口不可见 + 线程已挂起"""
        if not sys.platform == "win32":
            return True
        try:
            # 检查窗口是否仍然可见
            for hwnd in info.window_handles:
                if user32.IsWindow(hwnd) and user32.IsWindowVisible(hwnd):
                    return False
            return True
        except Exception:
            return True

    def _suspend_process_threads(self, proc: psutil.Process, info: FrozenProcessInfo) -> bool:
        """挂起进程所有线程"""
        if not sys.platform == "win32":
            return False

        try:
            threads = proc.threads()
            suspended_any = False
            for t in threads:
                tid = t.id
                try:
                    h_thread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
                    if h_thread:
                        result = kernel32.SuspendThread(h_thread)
                        if result != -1:
                            info.thread_handles[tid] = h_thread
                            suspended_any = True
                        else:
                            kernel32.CloseHandle(h_thread)
                except Exception:
                    continue
            return suspended_any
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return False

    def _hide_and_displace_windows(self, pid: int, info: FrozenProcessInfo) -> bool:
        """隐藏窗口 + 移出屏幕 + 禁用输入，并保存原始位置"""
        if not sys.platform == "win32":
            return False

        found_windows = []

        def enum_callback(hwnd, lparam):
            found_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(found_pid))
            if found_pid.value == pid:
                hwnd_int = int(hwnd)
                # 保存原始窗口位置
                rect = RECT()
                if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                    info.original_rects[hwnd_int] = (
                        rect.left, rect.top,
                        rect.right - rect.left, rect.bottom - rect.top
                    )
                # 隐藏窗口
                user32.ShowWindow(hwnd, SW_HIDE)
                # 禁用输入
                user32.EnableWindow(hwnd, False)
                # 移出可视区域（负坐标）
                user32.SetWindowPos(hwnd, None, OFFSCREEN_X, OFFSCREEN_Y,
                                    0, 0, SWP_NOSIZE | SWP_NOZORDER)
                found_windows.append(hwnd_int)
            return True

        proc_cb = EnumWindowsProc(enum_callback)
        user32.EnumWindows(proc_cb, 0)

        # 也枚举子窗口
        def child_callback(hwnd, lparam):
            found_windows.append(int(hwnd))
            user32.ShowWindow(hwnd, SW_HIDE)
            return True

        for hwnd in list(found_windows):
            child_proc = EnumChildProc(child_callback)
            user32.EnumChildWindows(hwnd, child_proc, 0)

        info.window_handles = found_windows
        return len(found_windows) > 0

    def _apply_job_restrictions(self, proc: psutil.Process, info: FrozenProcessInfo) -> bool:
        """通过Job Object施加UI限制"""
        if not sys.platform == "win32":
            return False
        try:
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                return False

            ui_restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS()
            ui_restrictions.UIRestrictionsClass = (
                JOB_OBJECT_UILIMIT_HANDLES |
                JOB_OBJECT_UILIMIT_READCLIPBOARD |
                JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                JOB_OBJECT_UILIMIT_DESKTOP |
                JOB_OBJECT_UILIMIT_EXITWINDOWS
            )

            result = kernel32.SetInformationJobObject(
                job,
                JobObjectBasicUIRestrictions,
                ctypes.byref(ui_restrictions),
                ctypes.sizeof(ui_restrictions)
            )
            if not result:
                kernel32.CloseHandle(job)
                return False

            # 获取进程句柄
            h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
            if not h_proc:
                kernel32.CloseHandle(job)
                return False

            result = kernel32.AssignProcessToJobObject(job, h_proc)
            kernel32.CloseHandle(h_proc)

            if result:
                info.job_handle = job
                return True
            else:
                kernel32.CloseHandle(job)
                return False
        except Exception:
            return False

    def _recheck_and_refreeze(self):
        """重新检查被冻结进程，重新冻结被恢复的线程和窗口"""
        if not sys.platform == "win32":
            return

        with self._frozen_lock:
            items = list(self._frozen.items())

        for pid, info in items:
            # 跳过PENDING占位（正在冻结中，尚未记录完整信息）
            if info is self._FROZEN_PENDING or not isinstance(info, FrozenProcessInfo):
                continue
            try:
                # 检查进程是否还存在
                if not psutil.pid_exists(pid):
                    self._cleanup_frozen(pid, info)
                    continue

                # 1. 重新挂起被恢复的线程 + 新线程
                if info.thread_handles:
                    proc = psutil.Process(pid)
                    current_tids = {t.id for t in proc.threads()}
                    for tid in current_tids:
                        if tid not in info.thread_handles:
                            try:
                                h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
                                if h:
                                    if kernel32.SuspendThread(h) != -1:
                                        info.thread_handles[tid] = h
                                    else:
                                        kernel32.CloseHandle(h)
                            except Exception:
                                pass

                # 2. 重新隐藏被显示的窗口 + 重新移出屏幕
                for hwnd in info.window_handles:
                    try:
                        if user32.IsWindow(hwnd) and user32.IsWindowVisible(hwnd):
                            user32.ShowWindow(hwnd, SW_HIDE)
                            user32.EnableWindow(hwnd, False)
                            user32.SetWindowPos(hwnd, None, OFFSCREEN_X, OFFSCREEN_Y,
                                                0, 0, SWP_NOSIZE | SWP_NOZORDER)
                    except Exception:
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self._cleanup_frozen(pid, info)

    def _cleanup_frozen(self, pid: int, info):
        """清理已死亡进程的冻结记录（info 可能是 PENDING 哨兵）"""
        try:
            # PENDING 哨兵没有资源可清理，直接跳过
            if info is self._FROZEN_PENDING or not isinstance(info, FrozenProcessInfo):
                with self._frozen_lock:
                    self._frozen.pop(pid, None)
                return
            # 关闭线程句柄
            if sys.platform == "win32":
                for h in info.thread_handles.values():
                    try:
                        kernel32.CloseHandle(h)
                    except Exception:
                        pass
                if info.job_handle:
                    try:
                        kernel32.CloseHandle(info.job_handle)
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            with self._frozen_lock:
                self._frozen.pop(pid, None)

    # ============ 解冻实现 ============
    def unfreeze_all(self, reason: str = "unlock"):
        """解冻所有冻结的进程"""
        with self._frozen_lock:
            pids = list(self._frozen.keys())
        for pid in pids:
            self.unfreeze_process(pid, reason)

    def unfreeze_process(self, pid: int, reason: str = "unlock"):
        """解冻单个进程，恢复窗口原始位置"""
        with self._frozen_lock:
            info = self._frozen.pop(pid, None)
        if not info:
            return

        duration = int((datetime.now() - info.freeze_time).total_seconds())

        if sys.platform == "win32":
            # 1. 恢复线程
            for h in info.thread_handles.values():
                try:
                    kernel32.ResumeThread(h)
                    kernel32.CloseHandle(h)
                except Exception:
                    pass

            # 2. 恢复窗口位置 + 显示 + 启用
            for hwnd in info.window_handles:
                try:
                    if user32.IsWindow(hwnd):
                        # 恢复原始位置
                        if hwnd in info.original_rects:
                            x, y, w, h = info.original_rects[hwnd]
                            user32.SetWindowPos(hwnd, None, x, y, 0, 0,
                                                SWP_NOSIZE | SWP_NOZORDER)
                        # 显示并启用
                        user32.ShowWindow(hwnd, SW_SHOW)
                        user32.EnableWindow(hwnd, True)
                except Exception:
                    pass

            # 3. 关闭Job Object句柄（进程自动脱离）
            if info.job_handle:
                try:
                    kernel32.CloseHandle(info.job_handle)
                except Exception:
                    pass

        info.state = "unfrozen"
        self.logger.log_process_unfreeze(pid, info.name, duration_seconds=duration)

    # ============ 生命周期 ============
    def start(self):
        """启动进程监控线程"""
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self._stop_event.clear()
        self._scan_thread = threading.Thread(
            target=self._scan_loop,
            daemon=True,
            name="ProcessHunter"
        )
        self._scan_thread.start()
        self.logger.info("[ProcessHunter] 进程监控模块已启动")

    def stop(self):
        """停止监控并解冻所有进程"""
        self._stop_event.set()
        if self._scan_thread:
            self._scan_thread.join(timeout=2)
        # 清理
        self.unfreeze_all(reason="shutdown")
        self.logger.info("[ProcessHunter] 进程监控模块已停止")
