"""
AOTE 管控系统 - U盘授权解锁模块（USB Guard）
功能：
- 实时监听USB设备插入事件
- 双因素认证：硬件ID + 密钥文件SHA-256哈希
- 三种解锁模式：即拔即禁、定时解锁、永久解锁
"""
import sys
import ctypes
import time
import string
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Optional, Tuple, Callable
from pathlib import Path
from ctypes import wintypes

from .config import ConfigManager
from .logger import AOTELogger
# 复用 AntiTamper 的哈希与回文匹配算法，保证 USB 维护模式密码与紧急退出密码始终一致
from .anti_tamper import password_matches_hash, sha256_str

# 可移动磁盘类型（Windows GetDriveTypeW 返回值）
DRIVE_REMOVABLE = 2

# 模式选择窗口配色
_WINDOW_BG = "#006644"
_WINDOW_SUB_FG = "#ccffee"
_CARD_BG = "#f0fff0"
_PERM_CARD_BG = "#fff0e0"
_BTN_BLUE = "#0078d7"
_BTN_ORANGE = "#d07000"

# 窗口字体
_TITLE_FONT = ("Microsoft YaHei", 18, "bold")
_DESC_FONT = ("Microsoft YaHei", 10)
_CARD_TITLE_FONT = ("Microsoft YaHei", 12, "bold")
_CARD_DETAIL_FONT = ("Microsoft YaHei", 10)
_CARD_BTN_FONT = ("Microsoft YaHei", 11, "bold")

# 密钥文件读取缓冲区大小（字节）
_HASH_CHUNK_SIZE = 8192


def _sha256_file(filepath: str) -> str:
    """计算文件SHA-256哈希（分块读取，避免大文件占用内存）"""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


class USBGuard:
    """U盘授权守护者"""

    def __init__(self, config: ConfigManager, logger: AOTELogger):
        self.config = config
        self.logger = logger

        self._stop_event = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None

        # 当前已识别的U盘：盘符 -> (serial, 已认证)
        self._drives: Dict[str, Tuple[str, bool]] = {}

        # 解锁状态
        self._eject_mode_active = False  # 即拔即禁激活中
        self._eject_mode_drive: Optional[str] = None

        # 外部回调：当U盘认证成功时，弹出模式选择
        self._on_authorized_usb: Optional[Callable[[], Optional[str]]] = None
        # 当U盘拔出（即拔即禁模式）时的回调
        self._on_eject_mode_unplug: Optional[Callable[[], None]] = None

        # 管理员密码校验回调
        self._verify_admin_callback: Optional[Callable[[str], bool]] = None

    def _verify_admin_password(self, password: str) -> bool:
        """管理员密码校验：优先使用外部回调（AntiTamper），否则与 AntiTamper 保持同样的回文算法。
        这样 USB 维护模式密码与紧急退出密码始终一致。
        """
        if self._verify_admin_callback is not None:
            try:
                return bool(self._verify_admin_callback(password))
            except Exception as e:
                self.logger.debug(f"调用外部密码校验回调异常: {e}")
        # 降级：与 AntiTamper.verify_admin_password 完全一致的回文算法
        expected = self.config.get("emergency.admin_password_hash", "").lower()
        if not expected:
            return False
        return password_matches_hash(password, expected)

    # ============ 外部接口 ============
    def set_on_authorized_usb(self, cb: Callable[[], Optional[str]]):
        """设置U盘认证成功回调，返回选择的模式名或None"""
        self._on_authorized_usb = cb

    def set_on_eject_unplug(self, cb: Callable[[], None]):
        """设置即拔即禁模式下U盘拔出回调"""
        self._on_eject_mode_unplug = cb

    def set_admin_verifier(self, cb: Callable[[str], bool]):
        """设置管理员密码校验器"""
        self._verify_admin_callback = cb

    # ============ 盘符检测 ============
    def _get_removable_drives(self) -> List[str]:
        """获取当前所有可移动磁盘盘符"""
        drives: List[str] = []
        if sys.platform != "win32":
            return drives
        try:
            # 使用 GetLogicalDrives 位掩码枚举 A~Z
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i, letter in enumerate(string.ascii_uppercase):
                if bitmask & (1 << i):
                    drive = f"{letter}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(drive) == DRIVE_REMOVABLE:
                        drives.append(drive)
        except Exception as e:
            self.logger.debug(f"获取盘符列表失败: {e}")
        return drives

    def _get_volume_serial(self, drive_letter: str) -> str:
        """获取卷序列号（Volume Serial Number）"""
        if sys.platform != "win32":
            return ""
        try:
            serial = wintypes.DWORD(0)
            comp_len = wintypes.DWORD(0)
            flags = wintypes.DWORD(0)
            fs_name = ctypes.create_unicode_buffer(256)
            result = ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive_letter),
                None, 0,
                ctypes.byref(serial),
                ctypes.byref(comp_len),
                ctypes.byref(flags),
                fs_name, 256
            )
            if result:
                # 格式化为大写十六进制
                return format(serial.value & 0xFFFFFFFF, "08X")
        except Exception as e:
            self.logger.debug(f"获取卷序列号失败 {drive_letter}: {e}")
        return ""

    # ============ 认证逻辑 ============
    def authenticate_usb(self, drive_letter: str) -> Tuple[bool, str]:
        """
        双因素认证U盘
        :return: (是否通过认证, 硬件ID)
        """
        serial = self._get_volume_serial(drive_letter)

        # 因素1：硬件ID白名单
        whitelist = [s.upper() for s in self.config.get("usb_guard.whitelist_serials", [])]
        if whitelist and serial.upper() not in whitelist:
            self.logger.debug(f"U盘 {drive_letter} 硬件ID不在白名单: {serial}")
            # 非白名单U盘不立刻拒绝，只要密钥正确也可通过（兼容配置）
            # 如需严格双因素，取消下一行注释
            # return False, serial

        # 因素2：密钥文件
        key_filename = self.config.get("usb_guard.key_filename", ".guardian_key")
        expected_hash = self.config.get("usb_guard.key_hash_sha256", "").lower()

        key_file = Path(drive_letter) / key_filename
        if not key_file.exists():
            self.logger.debug(f"U盘 {drive_letter} 未找到密钥文件: {key_filename}")
            return False, serial

        try:
            actual_hash = _sha256_file(str(key_file)).lower()
        except Exception as e:
            self.logger.debug(f"读取密钥文件失败: {e}")
            return False, serial

        # 如果没有配置expected hash，仍然检查文件内容是否有内容
        if expected_hash and actual_hash != expected_hash:
            self.logger.debug(f"U盘 {drive_letter} 密钥哈希不匹配")
            return False, serial

        return True, serial

    # ============ 处理插入/拔出 ============
    def _handle_drive_arrival(self, drive: str):
        """处理U盘插入"""
        # 挂载稳定等待时间从 time_settings.usb_mount_delay 读取（秒）
        time.sleep(max(float(self.config.get("time_settings.usb_mount_delay", 0.5)), 0))
        # 认证结果中已包含硬件ID，无需再次查询卷序列号
        is_authorized, hw_id = self.authenticate_usb(drive)

        self.logger.log_usb_event("insert", drive, hardware_id=hw_id, is_authorized=is_authorized)

        if is_authorized:
            self._drives[drive] = (hw_id, True)
            # 弹出模式选择窗口
            mode = None
            if self._on_authorized_usb:
                mode = self._on_authorized_usb()

            if mode == "即拔即禁":
                self._eject_mode_active = True
                self._eject_mode_drive = drive
        else:
            self._drives[drive] = (hw_id, False)

    def _handle_drive_removal(self, drive: str):
        """处理U盘拔出"""
        info = self._drives.pop(drive, None)
        serial = info[0] if info else ""
        is_auth = info[1] if info else False
        self.logger.log_usb_event("remove", drive, hardware_id=serial, is_authorized=is_auth)

        # 如果处于即拔即禁模式且拔出的是对应U盘
        if self._eject_mode_active and self._eject_mode_drive == drive:
            self._eject_mode_active = False
            self._eject_mode_drive = None
            # 恢复严格模式延迟从 time_settings.usb_eject_restore_delay 读取（秒）
            delay = max(float(self.config.get("time_settings.usb_eject_restore_delay", 3.0)), 0)
            self.logger.info(f"[USBGuard] 即拔即禁U盘已拔出，{delay:.0f}秒内恢复严格模式")
            threading.Timer(delay, self._trigger_eject_unplug).start()

    def _trigger_eject_unplug(self):
        if self._on_eject_mode_unplug:
            try:
                self._on_eject_mode_unplug()
            except Exception as e:
                self.logger.error(f"即拔即禁回调异常: {e}")

    # ============ 轮询循环 ============
    def _poll_loop(self):
        """轮询检测U盘变化（间隔<=2秒）"""
        known = set(self._get_removable_drives())
        # Major 7 修复：对启动时已存在的U盘执行一次认证检查，而不是永远不识别
        # 使用后台线程避免阻塞启动初期的其他轮询
        for d in known:
            if self._stop_event.is_set():
                break
            try:
                # 用线程池异步方式认证：不阻塞也不影响其他插入事件
                threading.Thread(
                    target=self._handle_drive_arrival,
                    args=(d,),
                    daemon=True,
                    name=f"USBInitAuth-{d}"
                ).start()
            except Exception as e:
                self.logger.error(f"启动时U盘初始认证异常 {d}: {e}")

        while not self._stop_event.is_set():
            try:
                current = set(self._get_removable_drives())

                # 新增
                for d in current - known:
                    try:
                        self._handle_drive_arrival(d)
                    except Exception as e:
                        self.logger.error(f"处理U盘插入异常 {d}: {e}")

                # 移除
                for d in known - current:
                    try:
                        self._handle_drive_removal(d)
                    except Exception as e:
                        self.logger.error(f"处理U盘拔出异常 {d}: {e}")

                known = current
            except Exception as e:
                self.logger.error(f"[USBGuard] 轮询异常: {e}")

            # 轮询间隔从 time_settings.usb_poll_interval 读取（秒）
            interval = float(self.config.get("time_settings.usb_poll_interval", 1.5))
            self._stop_event.wait(max(interval, 0.1))

    # ============ 生命周期 ============
    def start(self):
        if self._poll_thread and self._poll_thread.is_alive():
            return
        self._stop_event.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name="USBGuard"
        )
        self._poll_thread.start()
        self.logger.info("[USBGuard] U盘监听模块已启动")

    def stop(self):
        self._stop_event.set()
        if self._poll_thread:
            timeout = float(self.config.get("time_settings.component_stop_timeout", 3))
            self._poll_thread.join(timeout=max(timeout, 0.1))
        self.logger.info("[USBGuard] U盘监听模块已停止")


class USBModeSelector:
    """U盘授权后弹出的模式选择GUI窗口"""

    def __init__(self, config: ConfigManager, logger: AOTELogger):
        self.config = config
        self.logger = logger
        self.selected_mode: Optional[str] = None
        self._result_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.root: Optional[tk.Tk] = None

    # ---------- 窗口构建 ----------
    def _build_window(self):
        self.root = tk.Tk()
        self.root.title("U盘授权 - 解锁模式选择")
        self.root.attributes("-topmost", True)
        # 居中显示
        w, h = 560, 460
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.resizable(False, False)
        self.root.configure(bg=_WINDOW_BG)

        tk.Label(
            self.root,
            text="✅ 授权U盘已识别\n请选择解锁模式",
            font=_TITLE_FONT,
            fg="white", bg=_WINDOW_BG,
            justify=tk.CENTER
        ).pack(pady=(25, 10))

        tk.Label(
            self.root,
            text="选择解锁模式以临时禁用系统管控",
            font=_DESC_FONT,
            fg=_WINDOW_SUB_FG, bg=_WINDOW_BG
        ).pack(pady=(0, 20))

        content = tk.Frame(self.root, bg="white", padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True, padx=15)

        self.selected_mode = None

        def _choose(mode_name):
            if mode_name == "永久解锁（维护模式）":
                # 需要二次密码验证
                self._ask_maintenance_password(mode_name)
            else:
                self.selected_mode = mode_name
                self._close()

        self._build_mode_cards(content, _choose)
        self._build_maintenance_card(content, _choose)
        self._build_cancel_button()

    def _build_mode_cards(self, content, choose: Callable[[str], None]):
        """按配置生成各解锁模式卡片"""
        for mode in self.config.get("unlock_modes", []):
            name = mode.get("name", "")
            mtype = mode.get("type", "")
            seconds = mode.get("seconds", 0)

            # 描述文字
            if mtype == "eject":
                detail = "U盘拔出前保持解锁，拔出后3秒内恢复严格模式"
            elif mtype == "timer":
                detail = f"保持解锁 {seconds // 60} 分钟，到期自动恢复严格模式"
            else:
                detail = ""

            self._add_card(
                content, icon="🔑", name=name, detail=detail,
                bg=_CARD_BG, title_fg="#003d29", detail_fg="#557",
                btn_text=f"选择「{name}」", btn_bg=_BTN_BLUE,
                # 默认参数绑定，避免闭包捕获循环变量
                command=lambda n=name: choose(n),
            )

    def _build_maintenance_card(self, content, choose: Callable[[str], None]):
        """永久解锁（维护模式）卡片：需管理员密码二次确认"""
        self._add_card(
            content, icon="🛠", name="永久解锁（维护模式）",
            detail="需输入管理员密码二次确认，解锁至下次重启或手动恢复",
            bg=_PERM_CARD_BG, title_fg="#a05000", detail_fg="#775",
            btn_text="进入维护模式", btn_bg=_BTN_ORANGE,
            command=lambda: choose("永久解锁（维护模式）"),
        )

    def _add_card(self, parent, *, icon: str, name: str, detail: str,
                  bg: str, title_fg: str, detail_fg: str,
                  btn_text: str, btn_bg: str, command):
        """在内容区添加一张模式卡片（标题 + 说明 + 选择按钮）"""
        frame = tk.Frame(parent, bg=bg, relief=tk.GROOVE, bd=1)
        frame.pack(fill=tk.X, pady=6)
        tk.Label(
            frame, text=f"{icon}  {name}",
            font=_CARD_TITLE_FONT, fg=title_fg, bg=bg, anchor="w"
        ).pack(fill=tk.X, padx=15, pady=(8, 0))
        tk.Label(
            frame, text=f"    {detail}",
            font=_CARD_DETAIL_FONT, fg=detail_fg, bg=bg, anchor="w"
        ).pack(fill=tk.X, padx=15, pady=(0, 8))
        tk.Button(
            frame, text=btn_text,
            font=_CARD_BTN_FONT, bg=btn_bg, fg="white", relief=tk.FLAT,
            padx=20, pady=6, cursor="hand2",
            command=command
        ).pack(padx=15, pady=(0, 10), anchor="e")

    def _build_cancel_button(self):
        cancel_frame = tk.Frame(self.root, bg=_WINDOW_BG)
        cancel_frame.pack(fill=tk.X, pady=12)
        tk.Button(
            cancel_frame, text="取消",
            font=_DESC_FONT,
            bg="#ccc", fg="#333", relief=tk.FLAT,
            padx=25, pady=6, cursor="hand2",
            command=self._close
        ).pack()

    # ---------- 密码验证 ----------
    def _ask_maintenance_password(self, mode_name: str):
        """维护模式二次验证密码（与 AntiTamper 密码一致）"""
        pwd = self._prompt_password()
        if pwd is None:
            return
        # 优先使用外部 verifier（由 USBGuard.set_admin_verifier 设置，与 AntiTamper 一致）
        ok = False
        verifier = getattr(self, "_verify_admin_callback", None)
        if callable(verifier):
            try:
                ok = bool(verifier(pwd))
            except Exception:
                ok = False
        else:
            # 降级：直接哈希匹配（不建议，应通过 USBGuard.set_admin_verifier 注入）
            expected = self.config.get("emergency.admin_password_hash", "").lower()
            actual = sha256_str(pwd).lower()
            ok = bool(expected and expected == actual)
        if not ok:
            messagebox.showerror("验证失败", "管理员密码错误！", parent=self.root)
            return
        self.selected_mode = mode_name
        self.logger.log_admin_action("maintenance_unlock", True)
        self._close()

    def _prompt_password(self) -> Optional[str]:
        """弹出密码输入框（返回 None 表示用户取消）"""
        dlg = tk.Toplevel(self.root)
        dlg.title("管理员密码验证")
        dlg.geometry("360x180")
        dlg.attributes("-topmost", True)
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="请输入管理员密码：", font=("Microsoft YaHei", 11)).pack(pady=(20, 5))
        entry = ttk.Entry(dlg, show="*", font=("Consolas", 14), width=24, justify=tk.CENTER)
        entry.pack(pady=5)
        entry.focus_set()

        result: Dict = {"value": None}

        def _ok():
            result["value"] = entry.get()
            dlg.destroy()

        def _cancel():
            dlg.destroy()

        btn_frame = tk.Frame(dlg)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="确认", command=_ok).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="取消", command=_cancel).pack(side=tk.LEFT, padx=8)

        entry.bind("<Return>", lambda e: _ok())
        entry.bind("<Escape>", lambda e: _cancel())

        self.root.wait_window(dlg)
        return result["value"]

    # ---------- 生命周期 ----------
    def _close(self):
        try:
            if self.root:
                self.root.destroy()
        except Exception:
            pass
        self._result_event.set()

    def show_and_wait(self) -> Optional[str]:
        """显示窗口并阻塞，返回选择的模式名或None"""
        self._result_event.clear()
        self.selected_mode = None

        def _run():
            try:
                self._build_window()
                self.root.mainloop()
            except Exception as e:
                self.logger.error(f"模式选择窗口异常: {e}")
                self._result_event.set()

        self._thread = threading.Thread(target=_run, daemon=True, name="USBModeSelector")
        self._thread.start()
        self._result_event.wait()
        return self.selected_mode
