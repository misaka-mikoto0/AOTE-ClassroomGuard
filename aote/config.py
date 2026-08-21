"""
AOTE 管控系统 - 配置模块
加载 YAML 配置文件，支持热重载
"""
import os
import yaml
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class ConfigManager:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_path: str = None):
        if self._initialized:
            return
        self._initialized = True

        if config_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            config_path = base_dir / "config" / "config.yaml"

        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._last_mtime = 0
        self._reload_thread = None
        self._stop_reload = threading.Event()

        self.load_config()
        self._start_hot_reload()

    def load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        with self._lock:
            try:
                if not self.config_path.exists():
                    raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

                with open(self.config_path, "r", encoding="utf-8") as f:
                    self._config = yaml.safe_load(f) or {}

                self._last_mtime = os.path.getmtime(self.config_path)
                return self._config
            except Exception as e:
                print(f"加载配置失败: {e}")
                # 使用默认配置
                self._config = self._default_config()
                return self._config

    def _check_reload(self):
        """检查配置文件是否被修改，自动重载"""
        while not self._stop_reload.is_set():
            try:
                if self.config_path.exists():
                    current_mtime = os.path.getmtime(self.config_path)
                    if current_mtime != self._last_mtime:
                        self.load_config()
                        print(f"[Config] 配置文件已热重载")
            except Exception:
                pass
            self._stop_reload.wait(5)  # 每5秒检查一次

    def _start_hot_reload(self):
        """启动热重载线程"""
        self._reload_thread = threading.Thread(
            target=self._check_reload,
            daemon=True,
            name="ConfigHotReload"
        )
        self._reload_thread.start()

    def stop_hot_reload(self):
        self._stop_reload.set()

    def _default_config(self) -> Dict[str, Any]:
        """默认配置（当配置文件不存在时使用）"""
        return {
            "schedule": {
                "weekday": {
                    i: [["08:00", "12:00"], ["14:00", "17:30"]]
                    for i in range(1, 6)
                },
                "exceptions": {}
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
                "headless": False,
                "browser_channel": "auto",
                "executable_path": "",
                "connect_cdp_url": "",
                "user_data_dir": "",
                "default_url": "about:blank",
                "max_captured": 1000,
                "launch_args": []
            }
        }

    # --- 便捷获取方法 ---
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        按路径获取配置，如: config.get('schedule.weekday.1')
        """
        with self._lock:
            parts = key_path.split(".")
            value = self._config
            try:
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    elif isinstance(value, list) and part.isdigit():
                        value = value[int(part)]
                    else:
                        return default
                return value
            except Exception:
                return default

    @property
    def browser_block_domains(self) -> List[str]:
        """获取严格模式下拦截的娱乐/游戏域名列表"""
        with self._lock:
            rules = self._config.get("browser_rules", {})
            return [str(d).lower().strip() for d in rules.get("block_domains", [])]

    @property
    def browser_allowed_domains(self) -> List[str]:
        """获取白名单域名列表"""
        with self._lock:
            rules = self._config.get("browser_rules", {})
            return [str(d).lower().strip() for d in rules.get("allowed_domains", [])]

    @property
    def weak_network(self) -> Dict[str, Any]:
        """获取弱网管控参数（命中黑名单时触发）"""
        with self._lock:
            rules = self._config.get("browser_rules", {})
            wn = rules.get("weak_network", {}) or {}
            return {
                "enabled": bool(wn.get("enabled", False)),
                "delay_ms": int(wn.get("delay_ms", 3000)),
                "latency_ms": int(wn.get("latency_ms", 800)),
                "download_kbps": int(wn.get("download_kbps", 128)),
                "upload_kbps": int(wn.get("upload_kbps", 64)),
                "min_duration": float(wn.get("min_duration", 15)),
            }
