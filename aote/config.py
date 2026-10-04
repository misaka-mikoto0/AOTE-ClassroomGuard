"""
AOTE 管控系统 - 配置模块

加载 YAML 配置文件并支持热重载：后台线程周期性比对文件 mtime，
文件变更时自动重新加载，使运行期修改配置即时生效。

ConfigManager 为进程级单例（首次构造时确定配置路径），
保证全进程共享同一份配置状态与唯一的热重载线程。
"""
import os
import sys
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def aote_base_dir() -> Path:
    """程序根目录：PyInstaller 冻结时取 exe 所在目录，否则取项目根目录"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def aote_config_path() -> Path:
    """解析 config.yaml 的路径，优先级：
    1. exe 所在目录的 config/config.yaml（用户可编辑、支持热重载）
    2. PyInstaller 内嵌的 config/config.yaml（onefile 打包，从 _MEIPASS 解压）
    3. 源码项目 config/config.yaml
    """
    if not getattr(sys, "frozen", False):
        return aote_base_dir() / "config" / "config.yaml"

    external = Path(sys.executable).resolve().parent / "config" / "config.yaml"
    if external.exists():
        return external
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        bundled = Path(meipass) / "config" / "config.yaml"
        if bundled.exists():
            return bundled
    return external


class ConfigManager:
    """YAML 配置管理器：进程级单例 + mtime 热重载 + 路径式取值"""

    _instance: Optional["ConfigManager"] = None
    _initialized = False
    _instance_lock = threading.Lock()
    _init_lock = threading.Lock()

    def __new__(cls, *args, **kwargs) -> "ConfigManager":
        # 双重检查锁定：并发首次调用也只创建一个实例
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_path: Optional[str] = None):
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            self._initialized = True

            if config_path is None:
                config_path = aote_config_path()

            self.config_path = Path(config_path)
            self._config: Dict[str, Any] = {}
            self._lock = threading.RLock()
            self._last_mtime = 0.0
            self._last_load_error: Optional[str] = None
            self._reload_thread: Optional[threading.Thread] = None
            self._stop_reload = threading.Event()

            self.load_config()
            self._start_hot_reload()

    # ---------- 加载与热重载 ----------
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件。

        解析失败时保留上一次的有效配置（若已有），仅首次加载失败才回退内置默认值，
        避免配置文件被意外写坏时丢失全部管控规则、导致管控静默失效。
        """
        with self._lock:
            try:
                if not self.config_path.exists():
                    raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

                # 先解析到局部变量：解析失败时不破坏当前已生效的配置
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}

                self._config = loaded
                self._last_mtime = os.path.getmtime(self.config_path)
                self._last_load_error = None
                return self._config
            except Exception as e:
                self._last_load_error = str(e)
                print(f"加载配置失败（保留当前配置）: {e}")
                if not self._config:
                    # 首次加载即失败：回退内置默认配置
                    self._config = self._default_config()
                return self._config

    def _check_reload(self):
        """检查配置文件是否被修改，自动重载"""
        while not self._stop_reload.is_set():
            try:
                if self.config_path.exists():
                    current_mtime = os.path.getmtime(self.config_path)
                    if current_mtime != self._last_mtime:
                        before = self._config
                        self.load_config()
                        if self._config is not before:
                            print("[Config] 配置文件已热重载")
                        elif self._last_load_error:
                            # 文件变了但解析失败：已保留原配置，提示便于排查
                            print(f"[Config] 配置变更但解析失败，已保留原配置: "
                                  f"{self._last_load_error}")
            except Exception:
                pass
            # 检查间隔从 time_settings 读取（秒），默认 5 秒
            interval = float(self.get("time_settings.config_reload_interval", 5))
            self._stop_reload.wait(max(interval, 0.5))

    def _start_hot_reload(self):
        """启动热重载线程"""
        self._reload_thread = threading.Thread(
            target=self._check_reload,
            daemon=True,
            name="ConfigHotReload"
        )
        self._reload_thread.start()

    def stop_hot_reload(self):
        """停止热重载线程"""
        self._stop_reload.set()

    # ---------- 取值 ----------
    @staticmethod
    @lru_cache(maxsize=1024)
    def _split_key_path(key_path: str) -> tuple:
        """拆分配置路径（缓存结果，避免高频取值时重复 split）"""
        return tuple(key_path.split("."))

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        按路径获取配置，如: config.get('schedule.weekday.1')

        YAML 中无引号的数字键（如 `1:`）会被解析为 int，
        而 key_path 片段是 str。这里对 dict 同时支持 str/int 键查找，
        避免 `"5" in {5: [...]}` 恒为 False 导致课表永远查不到。
        """
        with self._lock:
            value: Any = self._config
            try:
                for part in self._split_key_path(key_path):
                    if isinstance(value, dict):
                        if part in value:
                            value = value[part]
                        elif part.isdigit() and int(part) in value:
                            value = value[int(part)]
                        else:
                            return default
                    elif isinstance(value, list) and part.isdigit():
                        value = value[int(part)]
                    else:
                        return default
                return value
            except Exception:
                return default

    def _browser_rules(self) -> Dict[str, Any]:
        """读取 browser_rules 配置块（始终返回 dict）"""
        with self._lock:
            return self._config.get("browser_rules", {}) or {}

    def _domain_list(self, key: str) -> List[str]:
        """读取 browser_rules 下的域名列表，统一小写并去除首尾空白"""
        return [str(d).lower().strip() for d in (self._browser_rules().get(key) or [])]

    @property
    def browser_block_domains(self) -> List[str]:
        """获取严格模式下拦截的娱乐/游戏域名列表"""
        return self._domain_list("block_domains")

    @property
    def browser_allowed_domains(self) -> List[str]:
        """获取白名单域名列表"""
        return self._domain_list("allowed_domains")

    @property
    def weak_network(self) -> Dict[str, Any]:
        """获取弱网管控参数（命中黑名单时触发）"""
        wn = self._browser_rules().get("weak_network") or {}
        return {
            "enabled": bool(wn.get("enabled", False)),
            "delay_ms": int(wn.get("delay_ms", 3000)),
            "latency_ms": int(wn.get("latency_ms", 800)),
            "download_kbps": int(wn.get("download_kbps", 128)),
            "upload_kbps": int(wn.get("upload_kbps", 64)),
            "min_duration": float(wn.get("min_duration", 15)),
        }

    # ---------- 默认配置 ----------
    def _default_config(self) -> Dict[str, Any]:
        """默认配置（当配置文件不存在或解析失败时使用）"""
        return {
            "schedule": {
                "weekday": {
                    i: [["08:00", "12:00"], ["14:00", "17:30"]]
                    for i in range(1, 6)
                },
                "exceptions": {}
            },
            "time_settings": {
                "main_loop_interval": 1,
                "config_reload_interval": 5,
                "time_check_interval": 5,
                "tray_refresh_interval": 3,
                "http_poll_interval": 1,
                "usb_poll_interval": 1.5,
                "usb_mount_delay": 0.5,
                "usb_eject_restore_delay": 3.0,
                "sandbox_call_timeout": 30,
                "sandbox_start_timeout": 60,
                "page_load_timeout_ms": 15000,
                "password_dialog_timeout": 120,
                "component_stop_timeout": 3,
                "tasklist_timeout": 5,
                "powershell_timeout": 15,
                "taskkill_timeout": 10,
                "browser_relaunch_cooldown": 10,
                "sandbox_heartbeat_interval": 0.5,
                "cdp_retry_interval": 1,
                "browser_monitor_interval": 3,
                "cdp_retry_notify_every": 10,
                "violation_cooldown": 10,
                "log_rotate_when": "midnight",
                "tray_unlock_5min": 300,
                "tray_unlock_30min": 1800,
                "unlock_options": [300, 600, 1800, 3600],
                "max_custom_unlock_minutes": 180,
            },
            "browser_rules": {
                "block_domains": [
                    "bilibili.com", "youtube.com", "youku.com",
                    "iqiyi.com", "douyin.com", "steampowered.com",
                    "4399.com", "7k7k.com"
                ],
                "allowed_domains": [
                    "edu.cn", "gov.cn", "baidu.com", "bing.com",
                    "qq.com", "alipay.com"
                ],
                "topic_blocks": [],
                "blocked_page_html": "",
                "video_block_enabled": True,
                "weak_network": {
                    "enabled": True,
                    "delay_ms": 3000,
                    "latency_ms": 800,
                    "download_kbps": 128,
                    "upload_kbps": 64,
                    "min_duration": 15
                }
            },
            "usb_guard": {
                "whitelist_serials": [],
                "key_filename": ".guardian_key",
                "key_hash_sha256": ""
            },
            "unlock_modes": [
                {"name": "即拔即禁", "type": "eject"},
                {"name": "30分钟", "type": "timer", "seconds": 1800},
                {"name": "1小时", "type": "timer", "seconds": 3600},
            ],
            "emergency": {
                "hotkey": "ctrl+shift+alt+g",
                "admin_password_hash": ""
            },
            "logging": {
                "path": r"C:\ProgramData\ClassroomGuard\logs",
                "retention_days": 30
            },
            "http_server": {
                "host": "127.0.0.1",
                "port": 8765,
                "heartbeat_timeout": 30
            },
            "browser_sandbox": {
                "enabled": True,
                "connect_cdp_url": "http://127.0.0.1:9222",
                "monitor_browser_processes": True,
                "auto_relaunch_managed": True,
                "takeover_only_in_strict": True,
                "user_data_dir": "",
                "max_captured": 1000
            }
        }
