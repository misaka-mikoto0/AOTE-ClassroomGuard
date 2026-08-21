"""
AOTE 管控系统 - 浏览器控制沙盒模块（Playwright for Python）

将原「外部拦截浏览器进程」方案升级为「在独立 Chromium 实例内直接控制浏览器内容」：

- playwright.chromium.launch() 启动独立浏览器实例，默认使用 Playwright 自带 Chromium；
  也可通过配置 browser_channel/executable_path 直接复用本机已安装的浏览器
  （如 Microsoft Edge / Chrome / 其它 Chromium 内核浏览器），无需额外下载浏览器。启动参数携带：
    --disable-web-security        禁用同源策略（便于注入/伪造跨域资源）
    --proxy-server=http://127.0.0.1:8080  预留外部代理通道（本地抓包代理等）
    --remote-debugging-port=9222  开放 CDP 调试端口
    --user-data-dir=<
    独立目录>     独立用户数据，避免污染主浏览器环境
- browser.new_context() 创建隔离浏览上下文（Cookies/Storage 彼此隔离）
- page.route("**/*", handler) 在浏览器内部直接拦截 HTTPS 请求：
    should_intercept(url) 命中 -> route.fulfill(status/headers/body 完全可控)
    否则 route.continue_() 放行 —— 无需外部代理程序处理 TLS
- page.evaluate("() => {...}") 在目标页面上下文执行任意 JS（DOM/LocalStorage/Cookie）
- page.on("response", handler) 捕获所有真实/伪造的响应数据
- 底层 CDP：page.context.new_cdp_session(page) 获取 CDP Session，直接调用
    Network.getResponseBody / Runtime.evaluate 等原始 DevTools Protocol 命令
- browser.close() 统一清理进程

Python 主控程序作为 Orchestrator：启动浏览器 -> 注册路由规则 -> 执行页面脚本
-> 收集返回数据 -> 清理，实现完全隔离、网络流量可控、脚本行为可注入的浏览器沙盒。

架构说明：Playwright 的 async API 绑定在独立 asyncio 事件循环线程中运行，
所有公开方法均为线程安全的同步包装（内部 run_coroutine_threadsafe 调度），
因此主控线程/其他组件线程可随时调用。
"""
import os
import sys
import time
import json
import socket
import threading
import asyncio
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Callable, Dict, List, Optional, Union

from .config import ConfigManager
from .logger import AOTELogger


# 管控模式常量
MODE_RELAXED = "relaxed"        # 宽松：全部放行（上课/授权时段）
MODE_STRICT = "strict"          # 严格：拦截娱乐/游戏站点，访问即记违规并切换弱网
MODE_UNLOCKED = "unlocked"      # 临时/永久解锁：全部放行（密码豁免）


# ======================================================
# 工具
# ======================================================
def _compile_matcher(pattern: Union[str, Callable[[str], bool]]) -> Callable[[str], bool]:
    """将拦截规则中的 pattern 编译为 url 匹配器。
    - callable：直接作为匹配函数
    - "regex:xxx"：正则搜索匹配
    - 其他字符串：子串包含匹配
    """
    if callable(pattern):
        return pattern
    if not isinstance(pattern, str):
        raise TypeError("拦截 pattern 必须是字符串或 callable")
    if pattern.startswith("regex:"):
        import re
        rx = re.compile(pattern[len("regex:"):])
        return lambda url: bool(rx.search(url))
    return lambda url: pattern in url


class InterceptRule:
    """一条拦截规则：url 命中 -> 返回伪造响应体（status/headers/body 完全可控）"""

    __slots__ = ("rule_id", "matcher", "status", "headers", "body")

    def __init__(self, rule_id: int, matcher: Callable[[str], bool],
                 status: int = 200, headers: Optional[Dict[str, str]] = None,
                 body: Union[str, bytes] = "",
                 content_type: str = "text/html; charset=utf-8"):
        self.rule_id = rule_id
        self.matcher = matcher
        self.status = status
        headers = dict(headers or {})
        headers.setdefault("Content-Type", content_type)
        self.headers = headers
        self.body = body


class _NetworkSniffer:
    """基于 CDP Network 域的网络报文收集器：
    持续监听 requestWillBeSent 建立 requestId -> url 映射，
    从而支持 Network.getResponseBody 报文级调试。"""

    def __init__(self, cdp_session, logger: AOTELogger, max_entries: int = 1000):
        self._session = cdp_session
        self._logger = logger
        self._max = max_entries
        self._requests: Dict[str, str] = {}
        self._responses: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    async def start(self) -> None:
        try:
            self._session.on("Network.requestWillBeSent", self._on_request)
            self._session.on("Network.responseReceived", self._on_response)
            await self._session.send("Network.enable")
        except Exception as e:
            self._logger.debug(f"[Sandbox] CDP Network 域启用失败（可选功能）: {e}")

    async def stop(self) -> None:
        """清理：移除监听（Session 关闭时自动失效，此处仅为安全兜底）。"""
        try:
            self._session.remove_listener("Network.requestWillBeSent", self._on_request)
            self._session.remove_listener("Network.responseReceived", self._on_response)
        except Exception:
            pass

    # CDP 事件回调为同步函数
    def _on_request(self, payload: dict) -> None:
        try:
            rid = payload.get("requestId", "")
            url = (payload.get("request") or {}).get("url", "")
            if rid and url:
                with self._lock:
                    self._requests[rid] = url
        except Exception:
            pass

    def _on_response(self, payload: dict) -> None:
        try:
            rid = payload.get("requestId", "")
            with self._lock:
                url = self._requests.get(rid, "")
                if url:
                    self._responses.append({
                        "requestId": rid,
                        "url": url,
                        "status": (payload.get("response") or {}).get("status", 0),
                        "time": time.time(),
                    })
                    if len(self._responses) > self._max:
                        del self._responses[:-self._max]
        except Exception:
            pass

    def list_requests(self) -> List[Dict[str, str]]:
        with self._lock:
            return [{"requestId": rid, "url": url} for rid, url in self._requests.items()]

    def list_responses(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._responses)

    async def get_response_body(self, request_id: str) -> Optional[bytes]:
        """Network.getResponseBody：返回原始报文体（base64 自动解码）"""
        try:
            result = await self._session.send("Network.getResponseBody", {"requestId": request_id})
            body = result.get("body", "")
            if result.get("base64Encoded"):
                import base64
                return base64.b64decode(body)
            return body.encode("utf-8", errors="replace")
        except Exception as e:
            self._logger.debug(f"[Sandbox] getResponseBody 失败: {e}")
            return None


# ======================================================
# 默认管控拦截页（可被 config browser_rules.*_page_html 覆盖）
# ======================================================
DEFAULT_BLOCKED_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>网站已被管控</title>
<style>
 body{margin:0;font-family:"Microsoft YaHei",Arial,sans-serif;
      background:linear-gradient(135deg,#1e3c72,#2a5298);color:#fff;
      display:flex;align-items:center;justify-content:center;min-height:100vh}
 .card{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.2);
      border-radius:16px;padding:48px 56px;max-width:560px;text-align:center;
      box-shadow:0 12px 40px rgba(0,0,0,.35)}
 .icon{font-size:64px;margin-bottom:16px}
 h1{font-size:28px;margin:0 0 12px}
 p{font-size:16px;line-height:1.7;opacity:.9;margin:0}
 .tag{display:inline-block;margin-top:20px;padding:6px 18px;border-radius:999px;
      background:rgba(255,255,255,.15);font-size:13px}
</style></head><body>
<div class="card">
  <div class="icon">🚫</div>
  <h1>该网站已被管控</h1>
  <p>当前处于受管控时间，娱乐/游戏类内容已暂停访问。<br>
     请专注于学习内容。</p>
  <span class="tag">AOTE 浏览器内容管控</span>
</div>
</body></html>"""


# ======================================================
# 视频播放管控 JS（严格模式注入所有页面）
# ======================================================
# 通过全局开关 window.__AOTE_MEDIA_BLOCK.active 控制，模式切换无需刷新页面：
# - 覆盖 play/load/canPlayType：播放/加载/能力探测直接失效
# - 拦截 src setter：严格模式下赋值即丢弃，播放器拿不到视频源
# - MutationObserver 兜底：新插入的 <video>/<audio> 自动暂停并清空
# - 页面加载完成自动应用一次；提示浮层告知管控原因
MEDIA_BLOCK_BOOTSTRAP_JS = """\
() => {
  if (window.__AOTE_MEDIA_BLOCK) return;   // 已注入则跳过
  const MB = window.__AOTE_MEDIA_BLOCK = { active: false, _t: null };
  const MSG = '当前为非上课时间段，视频播放已被管控';
  function showToast() {
    try {
      let t = document.getElementById('aote-media-toast');
      if (!t) {
        t = document.createElement('div');
        t.id = 'aote-media-toast';
        t.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);' +
          'z-index:2147483647;background:rgba(20,30,60,.95);color:#fff;padding:10px 20px;' +
          'border-radius:8px;font-size:14px;font-family:"Microsoft YaHei",sans-serif;' +
          'box-shadow:0 4px 20px rgba(0,0,0,.4);pointer-events:none;white-space:nowrap';
        (document.body || document.documentElement).appendChild(t);
      }
      t.textContent = MSG;
      clearTimeout(MB._t);
      MB._t = setTimeout(() => { try { t.remove(); } catch (e) {} }, 2500);
    } catch (e) {}
  }
  function hardBlock(el) {
    if (!el) return;
    try {
      el.pause();
      el.removeAttribute('src');
      el.removeAttribute('autoplay');
      el.removeAttribute('data-src');
      el.controls = false;
      try { el.load(); } catch (e) {}
      if (el.parentNode && el.parentNode.tagName === 'SOURCE') {
        try { el.parentNode.remove(); } catch (e) {}
      }
    } catch (e) {}
  }
  // 1) 覆盖 play
  const _play = HTMLMediaElement.prototype.play;
  HTMLMediaElement.prototype.play = function () {
    if (MB.active) { hardBlock(this); showToast(); return Promise.reject(new DOMException('AOTE: video blocked', 'NotAllowedError')); }
    return _play.apply(this, arguments);
  };
  // 2) 覆盖 load
  const _load = HTMLMediaElement.prototype.load;
  HTMLMediaElement.prototype.load = function () {
    if (MB.active) { hardBlock(this); return; }
    return _load.apply(this, arguments);
  };
  // 3) 覆盖 canPlayType：宣称不支持，播放器回退/报错
  const _cpt = HTMLMediaElement.prototype.canPlayType;
  HTMLMediaElement.prototype.canPlayType = function () {
    if (MB.active) return '';
    return _cpt.apply(this, arguments);
  };
  // 4) 拦截 src setter
  try {
    const srcDesc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src');
    if (srcDesc && srcDesc.set) {
      Object.defineProperty(HTMLMediaElement.prototype, 'src', {
        get: srcDesc.get,
        set: function (v) { if (MB.active) { showToast(); return; } return srcDesc.set.call(this, v); },
        configurable: true
      });
    }
  } catch (e) {}
  // 5) MutationObserver 兜底
  try {
    new MutationObserver(function (muts) {
      if (!MB.active) return;
      for (let i = 0; i < muts.length; i++) {
        const nodes = muts[i].addedNodes;
        for (let j = 0; j < nodes.length; j++) {
          const n = nodes[j];
          if (!n || n.nodeType !== 1) continue;
          if (n.tagName === 'VIDEO' || n.tagName === 'AUDIO') { hardBlock(n); showToast(); }
          if (n.querySelectorAll) n.querySelectorAll('video,audio').forEach(hardBlock);
        }
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  } catch (e) {}
  // 6) 立即应用（供 Python 端随时调用）
  MB.apply = function () {
    if (!MB.active) return;
    try { document.querySelectorAll('video,audio').forEach(hardBlock); } catch (e) {}
    showToast();
  };
  if (document.readyState === 'complete') MB.apply();
  else window.addEventListener('load', function () { MB.apply(); }, { once: true });
}
"""

# Python 端通过 evaluate 控制开关（无需刷新页面）
MEDIA_BLOCK_APPLY_JS = """\
() => { const mb = window.__AOTE_MEDIA_BLOCK; if (mb) { mb.active = true; mb.apply(); } }
"""
MEDIA_BLOCK_DISABLE_JS = """\
() => { const mb = window.__AOTE_MEDIA_BLOCK; if (mb) { mb.active = false; } }
"""

# 视频资源 URL 判定（网络层拦截兜底）
VIDEO_EXTENSIONS = (
    ".mp4", ".m3u8", ".flv", ".webm", ".ogv", ".ogg", ".mov",
    ".mkv", ".m4v", ".ts", ".3gp", ".avi",
)
VIDEO_URL_KEYWORDS = (
    "videoplayback", "googlevideo", "bcebos.com", "video.qq.com",
    "vimeocdn", "akamaized", "gifshow", "mcdn.bilivideo",
)


# ======================================================
# 浏览器沙盒主类
# ======================================================
class BrowserSandbox:
    """Playwright 浏览器控制沙盒（Orchestrator）"""

    DEFAULT_LAUNCH_ARGS = [
        "--disable-web-security",
        "--proxy-server=http://127.0.0.1:8080",
        "--remote-debugging-port=9222",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-blink-features=AutomationControlled",
    ]

    def __init__(self, config: ConfigManager, logger: AOTELogger):
        self.config = config
        self.logger = logger

        # 运行状态
        self._loop = None                      # asyncio 事件循环（后台线程）
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._started = threading.Event()
        self._start_error: Optional[str] = None

        # Playwright 对象（仅在 loop 线程内直接使用）
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._cdp_session = None

        # 拦截规则
        self._intercept_rules: List[InterceptRule] = []
        self._rules_lock = threading.Lock()
        self._next_rule_id = 1

        # 管控模式与规则（浏览器内容管控）
        self._control_mode = MODE_RELAXED
        self._unlock_until: float = 0.0          # 临时解锁截止时间（时间戳）
        self._permanent_unlock: bool = False     # 永久解锁标志
        self._on_violation: Optional[Callable[[str, str], None]] = None
        self._last_heartbeat: float = time.time()
        self._violation_cooldown: Dict[str, float] = {}   # url->last 触发时间，去抖
        # 弱网状态（命中黑名单自动切换）
        self._weak_network_enabled: bool = False
        self._weak_network_delay_ms: int = 3000      # 命中黑名单请求附加延迟
        self._weak_network_latency_ms: int = 800     # CDP 模拟网络延迟
        self._weak_network_download_kbps: int = 128  # 下载限速 KB/s
        self._weak_network_upload_kbps: int = 64     # 上传限速 KB/s
        self._weak_network_min_duration: float = 15.0  # 弱网最短持续时间（秒），防抖动
        self._weak_network_active: bool = False      # 当前是否处于弱网
        self._weak_network_since: float = 0.0        # 弱网激活时间戳
        self._weak_network_host: str = ""            # 触发弱网的域名
        self._state_lock = threading.Lock()
        self._load_browser_rules()

        # 响应捕获（page.on("response")）
        self._captured: List[Dict[str, Any]] = []
        self._captured_lock = threading.Lock()
        self._max_captured = int(config.get("browser_sandbox.max_captured", 1000))

        # 网络嗅探器（CDP）
        self._sniffer: Optional[_NetworkSniffer] = None

        # 可用性检查：playwright 未安装时降级为不可用，不影响主程序启动
        self.available = True
        try:
            import playwright  # noqa: F401
        except Exception:
            self.available = False
            self._start_error = "playwright 未安装，浏览器沙盒不可用（pip install playwright；默认复用本机 Edge/Chrome）"

        # 独立 user-data-dir，避免污染主浏览器环境
        cfg_dir = str(config.get("browser_sandbox.user_data_dir", "")).strip()
        if cfg_dir:
            self._user_data_dir = cfg_dir
        else:
            base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local")
            self._user_data_dir = str(Path(base) / "AOTE" / "chromium_profile")

        self._headless = bool(config.get("browser_sandbox.headless", False))
        self._default_url = str(config.get("browser_sandbox.default_url", "about:blank"))

        # 本地浏览器适配：优先 executable_path，其次 browser_channel，最后自带 Chromium
        self._browser_channel = str(config.get("browser_sandbox.browser_channel", "") or "").strip()
        self._executable_path = str(config.get("browser_sandbox.executable_path", "") or "").strip()
        # CDP 连接模式：非空时不再自行启动浏览器，而是接管通过桌面快捷方式
        # 打开的外部浏览器（如 connect_over_cdp("http://127.0.0.1:9222")）
        self._connect_cdp_url = str(config.get("browser_sandbox.connect_cdp_url", "") or "").strip()
        # 全入口接管（无论用户通过何种方式打开浏览器，都纳入 CDP 管控）：
        # - monitor_browser_processes: 监控系统内浏览器进程，凡未带调试参数的一律终止接管
        # - auto_spawn_browser: CDP 连接超时后自动拉起受管浏览器（无需用户双击专用快捷方式）
        self._monitor_browser_processes = bool(config.get(
            "browser_sandbox.monitor_browser_processes", True))
        self._auto_spawn_browser = bool(config.get(
            "browser_sandbox.auto_spawn_browser", True))
        self._managed_proc = None          # 自动拉起的受管浏览器进程
        self._spawn_attempted = False      # 是否已尝试自动拉起（避免反复拉起）

    # ============ 浏览器内容管控规则 ============
    def _load_browser_rules(self) -> None:
        """从配置加载浏览器管控规则（域名黑名单/白名单/弱网参数）。"""
        rules = self.config.get("browser_rules", {}) or {}
        self._block_domains = [str(d).lower().strip() for d in rules.get("block_domains", [])]
        self._allowed_domains = [str(d).lower().strip() for d in rules.get("allowed_domains", [])]
        self._blocked_page_html = str(rules.get("blocked_page_html", "")) or DEFAULT_BLOCKED_PAGE
        self._video_block_enabled = bool(rules.get("video_block_enabled", True))
        # 弱网参数（命中黑名单时触发）
        wn = rules.get("weak_network", {}) or {}
        self._weak_network_enabled = bool(wn.get("enabled", False))
        self._weak_network_delay_ms = int(wn.get("delay_ms", 3000))
        self._weak_network_latency_ms = int(wn.get("latency_ms", 800))
        self._weak_network_download_kbps = int(wn.get("download_kbps", 128))
        self._weak_network_upload_kbps = int(wn.get("upload_kbps", 64))
        self._weak_network_min_duration = float(wn.get("min_duration", 15))

    def _domain_match(self, host: str, patterns: List[str]) -> bool:
        """域名匹配：支持 'example.com' 与 '*.example.com' 两种写法。"""
        host = (host or "").lower().strip().rstrip(".")
        if not host:
            return False
        for pat in patterns:
            pat = pat.lower().strip().lstrip("*.").strip()
            if pat and (host == pat or host.endswith("." + pat)):
                return True
        return False

    def set_on_violation(self, callback: Optional[Callable[[str, str], None]]) -> None:
        """设置违规回调：拦截到黑名单站点时调用 callback(url, reason)。
        用于通知 Orchestrator 记录违规日志（弱网由沙盒自行切换）。"""
        self._on_violation = callback

    def _notify_violation(self, url: str, reason: str) -> None:
        """违规通知（带 10s 去抖，避免同一页面重复触发）。"""
        now = time.time()
        with self._state_lock:
            last = self._violation_cooldown.get(url, 0.0)
            if now - last < 10:
                return
            self._violation_cooldown[url] = now
            cb = self._on_violation
        if cb is not None:
            try:
                cb(url, reason)
            except Exception:
                pass

    def set_control_mode(self, mode: str, unlock_seconds: float = 0) -> None:
        """切换管控模式：
        - MODE_RELAXED: 全部放行
        - MODE_STRICT: 拦截娱乐/游戏站点，访问即违规并切换弱网
        - MODE_UNLOCKED: 临时解锁（unlock_seconds>0）或永久解锁（unlock_seconds<=0，密码豁免）
        """
        with self._state_lock:
            self._control_mode = mode
            if mode == MODE_UNLOCKED:
                if unlock_seconds > 0:
                    self._unlock_until = time.time() + unlock_seconds
                    self._permanent_unlock = False
                else:
                    self._permanent_unlock = True
            else:
                self._unlock_until = 0.0
                self._permanent_unlock = False
        self.logger.info(f"[Sandbox] 管控模式 -> {mode}"
                         + (f"（{unlock_seconds:.0f}s 解锁）" if unlock_seconds > 0 else ""))
        # 严格模式：开启视频管控；宽松/解锁：关闭视频管控并恢复网络
        if mode == MODE_STRICT:
            if getattr(self, "_video_block_enabled", True):
                self._request_media_block(True)
        elif mode in (MODE_RELAXED, MODE_UNLOCKED):
            self._request_media_block(False)
            with self._state_lock:
                self._weak_network_active = False
                self._weak_network_host = ""
            self._request_weak_network(False)

    def temporary_unlock(self, seconds: float) -> None:
        """临时解锁浏览器 N 秒。"""
        self.set_control_mode(MODE_UNLOCKED, seconds)

    def permanent_unlock(self) -> None:
        """永久解锁浏览器。"""
        self.set_control_mode(MODE_UNLOCKED, 0)

    def restore_strict_mode(self) -> None:
        """恢复严格管控模式。"""
        self.set_control_mode(MODE_STRICT)

    def is_unlocked(self) -> bool:
        """是否处于（未过期的）解锁状态。"""
        with self._state_lock:
            if self._permanent_unlock:
                return True
            return self._control_mode == MODE_UNLOCKED and self._unlock_until > time.time()

    def current_mode(self) -> str:
        with self._state_lock:
            return self._control_mode

    def block_url_now(self, url: str) -> None:
        """即时将指定 URL 加入临时黑名单（HTTP 上报违禁内容时调用）。
        该 URL 在严格模式下也会被拦截，直到调用 unblock_url() 或切换模式。"""
        from urllib.parse import urlparse
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if not host:
            return
        with self._state_lock:
            self._block_domains.append(host)
            # 避免无限膨胀
            self._block_domains = self._block_domains[-500:]
        self.logger.info(f"[Sandbox] 即时拦截域名: {host}")

    def unblock_url(self, url: str) -> None:
        """从临时黑名单移除指定 URL（不触碰配置中的永久名单）。"""
        from urllib.parse import urlparse
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if not host:
            return
        cfg_domains = [d.lower().strip()
                       for d in (self.config.get("browser_rules.block_domains", []) or [])]
        with self._state_lock:
            remaining = []
            for d in self._block_domains:
                if d == host and d not in cfg_domains:
                    continue  # 仅移除动态加入的
                remaining.append(d)
            self._block_domains = remaining
        self.logger.info(f"[Sandbox] 解除即时拦截域名: {host}")

    def heartbeat(self) -> float:
        """心跳：返回自上次浏览器活动以来的秒数。供 AntiTamper 检测沙盒存活。"""
        now = time.time()
        with self._state_lock:
            if self._last_heartbeat == 0:
                return float("inf")
            age = now - self._last_heartbeat
            self._last_heartbeat = now
            return age

    # ============ 状态 ============
    @property
    def is_running(self) -> bool:
        # 线程存活即视为运行中：自主启动模式下 browser 存在；
        # CDP 连接模式下浏览器可能尚未打开（等待连接阶段），线程存活即可
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_error(self) -> Optional[str]:
        return self._start_error

    def intercept_count(self) -> int:
        with self._rules_lock:
            return len(self._intercept_rules)

    # ============ 线程安全调用器 ============
    def _call(self, coro, timeout: float = 30.0):
        """将协程调度到浏览器事件循环线程并等待结果（线程安全）。"""
        if self._loop is None or self._thread is None or not self._thread.is_alive():
            raise RuntimeError(f"BrowserSandbox 未启动或已停止: {self._start_error or 'thread dead'}")
        future = asyncio_run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except Exception as e:
            if isinstance(e, RuntimeError) and "asyncio.run()" in str(e):
                raise RuntimeError("BrowserSandbox 事件循环已关闭") from e
            raise

    # ============ 生命周期 ============
    def start(self, wait_timeout: float = 60.0) -> bool:
        """启动沙盒（后台线程运行浏览器），等待初始化完成。"""
        if not self.available:
            self.logger.warning(f"[Sandbox] 不可用：{self._start_error}")
            return False
        if self.is_running:
            return True
        if self._thread is not None and self._thread.is_alive():
            self.logger.debug("[Sandbox] 启动中...")
            return self._started.wait(timeout=wait_timeout) and self._start_error is None

        import asyncio
        self._stop.clear()
        self._started.clear()
        self._start_error = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, args=(self._loop,),
            daemon=True, name="BrowserSandbox"
        )
        self._thread.start()
        ok = self._started.wait(timeout=wait_timeout)
        if ok and self._start_error is None:
            if self._connect_cdp_url:
                self.logger.info("[Sandbox] 浏览器沙盒已就绪（CDP 连接模式，等待外部浏览器）")
            else:
                self.logger.info("[Sandbox] 浏览器沙盒已启动（独立浏览器模式）")
            return True
        self.logger.error(f"[Sandbox] 启动失败: {self._start_error}")
        return False

    def _run_loop(self, loop) -> None:
        import asyncio
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run())
        except Exception as e:
            self._start_error = f"{type(e).__name__}: {e}"
            self.logger.error(f"[Sandbox] 浏览器运行循环异常: {self._start_error}")
            try:
                loop.run_until_complete(self._cleanup())
            except Exception:
                pass
        finally:
            self._started.set()
            try:
                loop.close()
            except Exception:
                pass

    async def _run(self) -> None:
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()

        # 全入口接管：监控系统内浏览器进程，未受管的浏览器一律终止接管
        if self._monitor_browser_processes:
            asyncio.create_task(self._watchdog_browser_processes())

        if self._connect_cdp_url:
            # ========== CDP 连接模式：接管外部浏览器 ==========
            await self._run_connect_mode()
        else:
            # ========== 自主启动模式 ==========
            await self._run_launch_mode()

    async def _run_launch_mode(self) -> None:
        """自主启动独立浏览器并挂接路由/响应捕获。"""
        # 独立浏览器实例：携带 --disable-web-security / --proxy-server /
        # --remote-debugging-port，并使用独立 --user-data-dir
        launch_args = list(self.DEFAULT_LAUNCH_ARGS)
        custom = self.config.get("browser_sandbox.launch_args", None)
        if isinstance(custom, list):
            launch_args = [str(a) for a in custom]
        # 显式追加独立 user-data-dir（不污染主浏览器环境）
        launch_args.append(f"--user-data-dir={self._user_data_dir}")
        try:
            Path(self._user_data_dir).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

        self._browser = await self._launch_browser(launch_args)
        # 创建隔离浏览上下文
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=None,
        )
        # 统一挂接路由拦截 + 响应捕获（context 级，覆盖所有页面含新开页面）
        await self._attach_context(self._context)
        # 打开默认页面
        self._page = await self._context.new_page()

        # 建立 CDP Session，启用 Network 域（Network.getResponseBody 支持）
        try:
            self._cdp_session = await self._context.new_cdp_session(self._page)
            self._sniffer = _NetworkSniffer(self._cdp_session, self.logger, self._max_captured)
            await self._sniffer.start()
        except Exception as e:
            self.logger.debug(f"[Sandbox] CDP 初始化失败（可选功能）: {e}")

        if self._default_url and self._default_url != "about:blank":
            try:
                await self._page.goto(self._default_url, timeout=15000)
            except Exception as e:
                self.logger.debug(f"[Sandbox] 默认页加载失败: {e}")

        self._start_error = None
        with self._state_lock:
            self._last_heartbeat = time.time()
        self._started.set()

        # 保持浏览器存活，直到 stop() 被调用；期间持续刷新心跳
        while not self._stop.is_set():
            with self._state_lock:
                self._last_heartbeat = time.time()
            await asyncio.sleep(0.5)
        await self._cleanup()

    async def _run_connect_mode(self) -> None:
        """CDP 连接模式：接管外部浏览器（桌面快捷方式打开的那个实例）。
        - 浏览器未打开时自动重试等待（不阻塞主程序启动）；
        - 断线后自动重连（用户关掉浏览器再重新打开也能继续接管）；
        - 关闭沙盒时不关闭用户浏览器。
        """
        self._start_error = None
        with self._state_lock:
            self._last_heartbeat = time.time()
        self._started.set()  # 立即就绪：主程序无需等待浏览器
        self.logger.info(
            f"[Sandbox] CDP 连接模式已启动：等待外部浏览器就绪（{self._connect_cdp_url}）。"
            "请双击桌面『AOTE CDP Debug Browser』打开调试浏览器。"
        )

        retry_count = 0
        while not self._stop.is_set():
            with self._state_lock:
                self._last_heartbeat = time.time()
            if self._browser is None:
                # 首次连接：外部浏览器可能尚未打开，自动重试等待
                try:
                    self._browser = await self._playwright.chromium.connect_over_cdp(
                        self._connect_cdp_url
                    )
                    self.logger.info("[Sandbox] 已连接外部浏览器（CDP），正在接管页面...")
                    await self._attach_cdp_contexts()
                    retry_count = 0
                except Exception as e:
                    # 每 10 秒提示一次，避免静默无输出
                    retry_count += 1
                    if retry_count % 10 == 1:
                        self.logger.warning(
                            f"[Sandbox] 正在等待调试浏览器连接（{self._connect_cdp_url}）..."
                        )
                        self.logger.warning(
                            "[Sandbox] 若一直连不上，请检查："
                            "1) 是否已通过『AOTE CDP Debug Browser』或本系统自动拉起受管浏览器；"
                            "2) 是否已有普通浏览器在运行（本系统会自动接管并重启）。"
                        )
                    # 自动拉起受管浏览器（无需用户手动双击专用快捷方式）
                    if (self._auto_spawn_browser
                            and retry_count >= 5
                            and not self._spawn_attempted):
                        await self._ensure_managed_browser_spawned()
                    self.logger.debug(f"[Sandbox] 等待外部浏览器连接: {e}")
            else:
                # 已连接：检测断线并自动重连
                try:
                    if not self._browser.is_connected():
                        self.logger.warning("[Sandbox] 外部浏览器连接断开，尝试重连...")
                        await self._try_reconnect_cdp()
                except Exception:
                    await self._try_reconnect_cdp()
            await asyncio.sleep(1)
        await self._cleanup()

    # ============ 全入口接管：浏览器进程监控 + 自动拉起 ============
    # 目标：无论用户通过任务栏/开始菜单/搜索/链接/双击文件等何种方式打开浏览器，
    # 只要不是 AOTE 受管实例（无 CDP 调试参数），一律终止并由 AOTE 接管，
    # 从而保证所有浏览请求都经过路由拦截（弱网/黑名单/视频管控）。
    _BROWSER_PROCESS_NAMES = ("msedge.exe", "chrome.exe", "chromium.exe")

    async def _watchdog_browser_processes(self) -> None:
        """浏览器进程监控循环：周期扫描系统内浏览器进程，未受管的一律终止。"""
        self.logger.info(
            "[Sandbox] 浏览器进程监控已启动：任何未受管浏览器将被自动接管"
        )
        while not self._stop.is_set():
            try:
                # 同步扫描放入线程池执行，避免阻塞事件循环
                await asyncio.to_thread(self._scan_and_kill_unmanaged_browsers)
            except Exception as e:
                self.logger.debug(f"[Sandbox] 浏览器进程监控异常: {e}")
            await asyncio.sleep(3)

    def _scan_and_kill_unmanaged_browsers(self) -> None:
        """扫描并终止未受管浏览器进程（在后台线程中运行）。
        判定"受管"：命令行包含 --remote-debugging-port / --remote-debugging-pipe，
        或使用了 AOTE 的独立 user-data-dir（即由本沙盒启动的实例）。"""
        import subprocess
        # 1) 快速检测是否存在浏览器进程（无则直接返回，避免频繁调用 PowerShell）
        try:
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return
        text = (r.stdout or "").lower()
        if not any(name in text for name in self._BROWSER_PROCESS_NAMES):
            return
        # 2) 通过 PowerShell 获取各浏览器进程的命令行，判定是否受管
        names = self._BROWSER_PROCESS_NAMES
        filter_expr = " -or ".join(f"Name = '{n}'" for n in names)
        ps_cmd = (
            "Get-CimInstance Win32_Process -Filter \"" + filter_expr + "\""
            " | ForEach-Object { '{0};{1}' -f $_.ProcessId, $_.CommandLine }"
        )
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as e:
            self.logger.debug(f"[Sandbox] 查询浏览器进程命令行失败: {e}")
            return
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                pid, cmdline = line.split(";", 1)
            except ValueError:
                continue
            pid, cmdline = pid.strip(), (cmdline or "").strip()
            if not pid.isdigit():
                continue
            if self._is_managed_browser_cmdline(cmdline):
                continue
            self.logger.warning(
                f"[Sandbox] 检测到未受管浏览器进程 PID={pid}（无 CDP 调试端口），"
                "立即终止并交由 AOTE 接管"
            )
            try:
                subprocess.run(
                    ["taskkill", "/PID", pid, "/F"],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                pass

    def _is_managed_browser_cmdline(self, cmdline: str) -> bool:
        """判断浏览器命令行是否属于 AOTE 受管实例。"""
        low = cmdline.lower()
        if "--remote-debugging-port" in low or "--remote-debugging-pipe" in low:
            return True
        # 使用 AOTE 独立 profile 启动的实例（playwright launch / 自动拉起）
        try:
            udd = str(self._user_data_dir).lower().replace("/", "\\")
            return bool(udd) and udd in low
        except Exception:
            return False

    async def _ensure_managed_browser_spawned(self) -> None:
        """CDP 连接超时后，自动拉起一个带调试端口的受管浏览器，供 connect_over_cdp 接管。
        这样用户无需手动双击专用快捷方式，浏览器也会自动就位。"""
        if self._spawn_attempted or self._managed_proc is not None or self._browser is not None:
            return
        self._spawn_attempted = True
        exe = self._executable_path or self._probe_installed_browser()
        if not exe or not os.path.exists(exe):
            self.logger.warning("[Sandbox] 未找到本机浏览器，无法自动拉起受管浏览器")
            return
        try:
            Path(self._user_data_dir).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        import subprocess
        launch_args = [
            "--remote-debugging-port=9222",
            f"--user-data-dir={self._user_data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-blink-features=AutomationControlled",
        ]
        self.logger.info(
            f"[Sandbox] 自动拉起受管浏览器: {exe}（调试端口 9222，profile: {self._user_data_dir}）"
        )
        try:
            self._managed_proc = subprocess.Popen(
                [exe, *launch_args, self._default_url],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as e:
            self.logger.warning(f"[Sandbox] 自动拉起受管浏览器失败: {e}")

    async def _attach_context(self, ctx) -> None:
        """对单个 BrowserContext 统一挂接：路由拦截 + 响应捕获 + 新页面监听。"""
        try:
            await ctx.route("**/*", self._route_handler)
        except Exception as e:
            self.logger.debug(f"[Sandbox] context.route 挂接失败: {e}")
        # 视频管控脚本：新页面自动注入（context 级 init script）
        try:
            await ctx.add_init_script(MEDIA_BLOCK_BOOTSTRAP_JS)
        except Exception as e:
            self.logger.debug(f"[Sandbox] add_init_script 失败: {e}")
        ctx.on("page", self._on_new_page)
        for page in list(ctx.pages):
            self._attach_page_listeners(page)
            await self._inject_media_block(page)  # 已有页面手动注入一次

    async def _attach_cdp_contexts(self) -> None:
        """接管 CDP 浏览器中已有的全部上下文与页面，并建立 CDP Session。"""
        self._context = None
        self._page = None
        self._cdp_session = None
        self._sniffer = None
        try:
            contexts = self._browser.contexts
        except Exception as e:
            self.logger.debug(f"[Sandbox] 获取浏览器上下文失败: {e}")
            return
        if contexts:
            self._context = contexts[0]
            for ctx in contexts:
                await self._attach_context(ctx)
            # 取第一个页面作为主控页面（用于 CDP 报文捕获）
            for ctx in contexts:
                if ctx.pages:
                    self._page = ctx.pages[0]
                    break
            self.logger.info(f"[Sandbox] 已接管 {len(contexts)} 个浏览器上下文")
        else:
            self.logger.info("[Sandbox] 外部浏览器暂无页面，等待用户打开新页面...")
        if self._page is not None:
            try:
                self._cdp_session = await self._context.new_cdp_session(self._page)
                self._sniffer = _NetworkSniffer(self._cdp_session, self.logger, self._max_captured)
                await self._sniffer.start()
            except Exception as e:
                self.logger.debug(f"[Sandbox] CDP 初始化失败（可选功能）: {e}")

    def _on_new_page(self, page) -> None:
        """外部浏览器新开页面时：挂接响应捕获并记录访问日志。"""
        self._attach_page_listeners(page)
        # 新页面注入视频管控脚本（后台执行，不阻塞事件回调）
        loop = self._loop
        if loop is not None and loop.is_running():
            try:
                asyncio_run_coroutine_threadsafe(self._inject_media_block(page), loop)
            except Exception:
                pass
        try:
            self.logger.info(f"[Sandbox] 检测到新页面: {page.url or '(空白页)'}")
        except Exception:
            pass

    def _attach_page_listeners(self, page) -> None:
        try:
            page.on("response", self._response_handler)
        except Exception:
            pass

    async def _try_reconnect_cdp(self) -> None:
        """断线后重连外部浏览器，并重新接管页面。"""
        try:
            self._browser = await self._playwright.chromium.connect_over_cdp(
                self._connect_cdp_url
            )
            self.logger.info("[Sandbox] 外部浏览器重连成功（CDP）")
            await self._attach_cdp_contexts()
        except Exception as e:
            self.logger.debug(f"[Sandbox] 重连失败，稍后重试: {e}")

    # ============ 本地浏览器适配 ============
    @staticmethod
    def _probe_installed_browser() -> Optional[str]:
        """探测本机已安装的 Chromium 内核浏览器可执行文件（Edge/Chrome）。"""
        candidates = [
            # Microsoft Edge
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            # Google Chrome
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            # 用户目录下的 Edge（便携/按用户安装）
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        ]
        for p in candidates:
            if os.path.exists(p):
                return p
        return None

    async def _launch_browser(self, launch_args: List[str]):
        """启动浏览器，适配本机已安装浏览器，避免强制下载 Chromium。
        回退链：executable_path -> browser_channel -> 自动探测本机 Edge/Chrome -> 自带 Chromium
        """
        # 1) 显式指定可执行文件路径（优先级最高，兼容任意 Chromium 内核浏览器）
        if self._executable_path:
            if os.path.exists(self._executable_path):
                self.logger.info(
                    f"[Sandbox] 使用本地浏览器（executable_path）: {self._executable_path}"
                )
                return await self._playwright.chromium.launch(
                    headless=self._headless,
                    args=launch_args,
                    executable_path=self._executable_path,
                )
            self.logger.warning(f"[Sandbox] executable_path 不存在，跳过: {self._executable_path}")

        # 2) 指定 Playwright 浏览器通道（msedge / chrome 等，使用系统已安装浏览器）
        if self._browser_channel:
            try:
                self.logger.info(f"[Sandbox] 使用系统浏览器通道: {self._browser_channel}")
                return await self._playwright.chromium.launch(
                    headless=self._headless,
                    args=launch_args,
                    channel=self._browser_channel,
                )
            except Exception as e:
                self.logger.warning(
                    f"[Sandbox] 通道 '{self._browser_channel}' 启动失败: {e}，尝试自动探测"
                )

        # 3) 自动探测本机 Edge/Chrome（browser_channel 为空/auto 时也会走到这里）
        if not self._browser_channel or self._browser_channel == "auto":
            exe = self._probe_installed_browser()
            if exe:
                self.logger.info(f"[Sandbox] 自动探测到本机浏览器，直接复用: {exe}")
                return await self._playwright.chromium.launch(
                    headless=self._headless,
                    args=launch_args,
                    executable_path=exe,
                )

        # 4) 最后兜底：Playwright 自带 Chromium（需 python -m playwright install chromium）
        self.logger.info(
            f"[Sandbox] 使用 Playwright 自带 Chromium: headless={self._headless}"
        )
        return await self._playwright.chromium.launch(
            headless=self._headless,
            args=launch_args,
        )

    async def _cleanup(self) -> None:
        """浏览器统一清理。CDP 连接模式下仅断开连接，不关闭用户浏览器；
        但自动拉起的受管浏览器（本系统启动）会被一并关闭。"""
        if self._sniffer is not None:
            try:
                await self._sniffer.stop()
            except Exception:
                pass
        # 关闭本系统自动拉起的受管浏览器进程（外部用户手动打开的浏览器不在此列）
        if self._managed_proc is not None:
            try:
                self._managed_proc.terminate()
                self.logger.info("[Sandbox] 已关闭自动拉起的受管浏览器")
            except Exception:
                pass
            self._managed_proc = None
        try:
            if self._browser is not None:
                if self._connect_cdp_url:
                    # 外部浏览器由用户管理，只断开 CDP 连接（不 browser.close()）
                    self.logger.info("[Sandbox] 外部浏览器由用户管理，仅断开 CDP 连接（未关闭浏览器）")
                else:
                    await self._browser.close()
        except Exception as e:
            self.logger.debug(f"[Sandbox] 关闭浏览器异常: {e}")
        self._browser = None
        self._context = None
        self._page = None
        self._cdp_session = None
        self._sniffer = None

    def stop(self, timeout: float = 30.0) -> None:
        """请求关闭沙盒并等待浏览器清理完成（CDP 模式不关闭外部浏览器）。"""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._thread:
            if self._connect_cdp_url:
                self.logger.info("[Sandbox] 浏览器沙盒已停止（CDP 连接已断开，外部浏览器保持运行）")
            else:
                self.logger.info("[Sandbox] 浏览器沙盒已关闭（browser.close()）")

    def close(self) -> None:
        """别名：与 stop 相同语义，便于 Orchestrator 统一清理。"""
        self.stop()

    # ============ 路由拦截（route.fulfill / route.continue_） ============
    async def _route_handler(self, route) -> None:
        url = route.request.url
        rule = self._match_rule(url)
        try:
            if rule is not None:
                body = rule.body
                if isinstance(body, str):
                    body = body.encode("utf-8")
                self.logger.debug(f"[Sandbox] 拦截 {url} -> status={rule.status}")
                await route.fulfill(
                    status=rule.status,
                    headers=rule.headers,
                    body=body,
                )
                return
            # 浏览器内容管控决策（无用户显式规则时）
            decision = self._content_decision(url)
            # 弱网管控：持续监控每个访问请求，命中黑名单即时切换弱网
            page = None
            try:
                page = route.request.frame.page
            except Exception:
                pass
            weak_hit = await self._handle_weak_network(url, page)
            if decision["action"] == "block":
                body = decision["page"].encode("utf-8")
                self.logger.info(f"[Sandbox] 内容管控拦截 {url} -> {decision['reason']}")
                self._notify_violation(url, decision["reason"])
                await route.fulfill(
                    status=403,
                    headers={"Content-Type": "text/html; charset=utf-8",
                             "X-AOTE-Blocked": decision["reason"]},
                    body=body,
                )
                return
            # 严格模式：网络层拦截视频资源，杜绝漏网
            if self._media_block_enabled():
                rtype = ""
                try:
                    rtype = route.request.resource_type or ""
                except Exception:
                    pass
                if rtype == "media" or self._is_video_url(url):
                    self.logger.info(f"[Sandbox] 视频资源拦截 {url}")
                    await route.fulfill(
                        status=403,
                        headers={"Content-Type": "text/plain; charset=utf-8",
                                 "X-AOTE-Blocked": "video"},
                        body=b"",
                    )
                    return
            # 命中黑名单的请求：附加请求级延迟（仅影响该请求，不影响其他站点）
            if weak_hit and self._weak_network_delay_ms > 0:
                await asyncio.sleep(self._weak_network_delay_ms / 1000.0)
            await route.continue_()
        except Exception as e:
            self.logger.debug(f"[Sandbox] 路由处理异常 {url}: {e}")
            try:
                await route.continue_()
            except Exception:
                pass

    def _content_decision(self, url: str) -> Dict[str, str]:
        """浏览器内容管控决策：根据当前模式 + 域名规则决定 放行/拦截。
        返回 {'action': 'allow'|'block', 'reason': str, 'page': html}"""
        # 本地/管理页面一律放行
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            scheme = (parsed.scheme or "").lower()
        except Exception:
            host, scheme = "", ""
        if scheme in ("data", "about", "javascript", "chrome") or host in (
                "127.0.0.1", "localhost", "::1"):
            return {"action": "allow", "reason": "", "page": ""}

        with self._state_lock:
            mode = self._control_mode
            unlocked = (self._permanent_unlock
                        or (mode == MODE_UNLOCKED and self._unlock_until > time.time()))

        if unlocked:
            return {"action": "allow", "reason": "", "page": ""}

        if mode == MODE_STRICT:
            if self._domain_match(host, self._block_domains):
                return {"action": "block", "reason": "blocked_domain",
                        "page": self._blocked_page_html}
            return {"action": "allow", "reason": "", "page": ""}

        # MODE_RELAXED 与其它：放行
        return {"action": "allow", "reason": "", "page": ""}

    # ============ 弱网管控（命中黑名单即时切换，不影响其他站点） ============
    async def _handle_weak_network(self, url: str, page=None) -> bool:
        """弱网检测：持续监控每个访问请求。
        - 命中黑名单 -> 立即切换弱网（CDP 限速当前页面 + 返回 True 触发请求级延迟）
        - 非黑名单且弱网已超最短时长 -> 恢复网络
        返回 True 表示该请求命中黑名单，需要附加请求级延迟。"""
        if not getattr(self, "_weak_network_enabled", False):
            return False
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if not host:
            return False
        with self._state_lock:
            unlocked = (self._permanent_unlock
                        or (self._control_mode == MODE_UNLOCKED
                            and self._unlock_until > time.time()))
        if unlocked:
            return False
        hit = self._domain_match(host, self._block_domains)
        now = time.time()
        with self._state_lock:
            active = self._weak_network_active
            since = self._weak_network_since
        if hit:
            if not active:
                with self._state_lock:
                    self._weak_network_active = True
                    self._weak_network_since = now
                    self._weak_network_host = host
                self.logger.warning(f"[Sandbox] 命中黑名单 -> 切换弱网: {host}")
                self.logger.log_weak_network(
                    "activate", host,
                    self._weak_network_latency_ms,
                    self._weak_network_download_kbps,
                    self._weak_network_upload_kbps)
                await self._apply_weak_network_cdp(True, page)
            return True
        # 未命中黑名单：弱网已超过最短持续时间则恢复（避免频繁抖动）
        if active and (now - since) >= getattr(self, "_weak_network_min_duration", 15.0):
            with self._state_lock:
                self._weak_network_active = False
                self._weak_network_host = ""
            self.logger.info("[Sandbox] 已离开黑名单站点 -> 恢复网络")
            self.logger.log_weak_network("restore")
            await self._apply_weak_network_cdp(False, page)
        return False

    async def _apply_weak_network_cdp(self, active: bool, page=None) -> None:
        """通过 CDP Network.emulateNetworkConditions 对指定页面应用/恢复弱网。
        弱网为 per-page 生效：只限速命中黑名单的页面，不影响其他页面。"""
        if page is None or self._context is None:
            return
        if active:
            params = {
                "offline": False,
                "latency": getattr(self, "_weak_network_latency_ms", 800),
                "downloadThroughput": max(0, int(getattr(self, "_weak_network_download_kbps", 128)
                                                  * 1024 / 8)),
                "uploadThroughput": max(0, int(getattr(self, "_weak_network_upload_kbps", 64)
                                                * 1024 / 8)),
                "connectionType": "cellular3g",
            }
        else:
            params = {"offline": False, "latency": 0,
                      "downloadThroughput": -1, "uploadThroughput": -1}
        try:
            session = await self._context.new_cdp_session(page)
            await session.send("Network.emulateNetworkConditions", params)
        except Exception as e:
            self.logger.debug(f"[Sandbox] CDP 弱网设置失败: {e}")
            return
        if active:
            self.logger.info(f"[Sandbox] 弱网已生效（延迟 {self._weak_network_latency_ms}ms / "
                             f"下载 {self._weak_network_download_kbps}KB/s / "
                             f"上传 {self._weak_network_upload_kbps}KB/s）")

    def _request_weak_network(self, active: bool, page=None) -> None:
        """线程安全地请求对页面应用/恢复弱网（非阻塞）。"""
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            asyncio_run_coroutine_threadsafe(
                self._apply_weak_network_cdp(active, page), loop
            )
        except Exception:
            pass

    def weak_network_status(self) -> Dict[str, Any]:
        """当前弱网状态（供 HTTP /status 与托盘展示）。"""
        with self._state_lock:
            return {
                "enabled": self._weak_network_enabled,
                "active": self._weak_network_active,
                "since": self._weak_network_since,
                "host": self._weak_network_host,
                "delay_ms": self._weak_network_delay_ms,
                "latency_ms": self._weak_network_latency_ms,
                "download_kbps": self._weak_network_download_kbps,
                "upload_kbps": self._weak_network_upload_kbps,
            }

    def set_weak_network_params(self, enabled=None, delay_ms=None, latency_ms=None,
                                download_kbps=None, upload_kbps=None) -> None:
        """动态调整弱网参数（供配置热重载 / HTTP 接口调用）。"""
        with self._state_lock:
            if enabled is not None:
                self._weak_network_enabled = bool(enabled)
            if delay_ms is not None:
                self._weak_network_delay_ms = max(0, int(delay_ms))
            if latency_ms is not None:
                self._weak_network_latency_ms = max(0, int(latency_ms))
            if download_kbps is not None:
                self._weak_network_download_kbps = max(0, int(download_kbps))
            if upload_kbps is not None:
                self._weak_network_upload_kbps = max(0, int(upload_kbps))
        self.logger.info(f"[Sandbox] 弱网参数更新: enabled={self._weak_network_enabled} "
                         f"delay={self._weak_network_delay_ms}ms "
                         f"latency={self._weak_network_latency_ms}ms "
                         f"dl={self._weak_network_download_kbps}KB/s "
                         f"ul={self._weak_network_upload_kbps}KB/s")

    # ============ 视频播放管控（非上课时间全面禁视频） ============
    def _media_block_enabled(self) -> bool:
        """严格模式下、且未解锁时启用视频管控（受配置开关控制）。"""
        if not getattr(self, "_video_block_enabled", True):
            return False
        with self._state_lock:
            if self._permanent_unlock:
                return False
            if self._control_mode == MODE_UNLOCKED and self._unlock_until > time.time():
                return False
            return self._control_mode == MODE_STRICT

    @staticmethod
    def _is_video_url(url: str) -> bool:
        """粗略判断 URL 是否为视频资源（扩展名 + 常见视频流关键字）。"""
        try:
            path = url.split("?", 1)[0].lower()
            if path.endswith(VIDEO_EXTENSIONS):
                return True
            low = url.lower()
            return any(k in low for k in VIDEO_URL_KEYWORDS)
        except Exception:
            return False

    def _request_media_block(self, enable: bool) -> None:
        """线程安全地请求对所有已接管页面执行视频管控开关（非阻塞）。"""
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            asyncio_run_coroutine_threadsafe(
                self._apply_media_block_pages(enable), loop
            )
        except Exception:
            pass

    async def _apply_media_block_pages(self, enable: bool) -> None:
        """对所有已接管页面执行 JS：开启/关闭视频管控。"""
        pages = []
        try:
            if self._context is not None:
                pages = list(self._context.pages)
        except Exception:
            pass
        js = MEDIA_BLOCK_APPLY_JS if enable else MEDIA_BLOCK_DISABLE_JS
        for p in pages:
            try:
                await p.evaluate(js)
            except Exception:
                pass
        self.logger.info(
            f"[Sandbox] 视频播放管控 -> {'开启' if enable else '关闭'}"
            f"（已处理 {len(pages)} 个页面）"
        )

    async def _inject_media_block(self, page) -> None:
        """向单个页面注入视频管控脚本（页面已加载时手动注入一次）。"""
        try:
            await page.evaluate(MEDIA_BLOCK_BOOTSTRAP_JS)
            if self._media_block_enabled():
                await page.evaluate(MEDIA_BLOCK_APPLY_JS)
        except Exception:
            pass

    def _match_rule(self, url: str) -> Optional[InterceptRule]:
        with self._rules_lock:
            for rule in self._intercept_rules:
                try:
                    if rule.matcher(url):
                        return rule
                except Exception:
                    continue
        return None

    def register_intercept(self, pattern: Union[str, Callable[[str], bool]],
                           status: int = 200,
                           headers: Optional[Dict[str, str]] = None,
                           body: Union[str, bytes] = "",
                           content_type: str = "text/html; charset=utf-8") -> int:
        """注册拦截规则：匹配到的 URL 将返回伪造响应体（status/headers/body 完全可控）。
        pattern 支持：子串 / "regex:xxx" / callable(url)->bool。
        返回 rule_id，可用于 unregister_intercept。"""
        matcher = _compile_matcher(pattern)
        with self._rules_lock:
            rule_id = self._next_rule_id
            self._next_rule_id += 1
            self._intercept_rules.append(
                InterceptRule(rule_id, matcher, status, headers, body, content_type)
            )
        self.logger.info(f"[Sandbox] 已注册拦截规则 #{rule_id}: {pattern} -> {status}")
        return rule_id

    def unregister_intercept(self, rule_id: int) -> bool:
        with self._rules_lock:
            for i, r in enumerate(self._intercept_rules):
                if r.rule_id == rule_id:
                    del self._intercept_rules[i]
                    self.logger.info(f"[Sandbox] 已移除拦截规则 #{rule_id}")
                    return True
        return False

    def clear_intercepts(self) -> None:
        with self._rules_lock:
            self._intercept_rules.clear()
        self.logger.info("[Sandbox] 已清空全部拦截规则")

    # ============ 响应捕获（page.on("response")） ============
    async def _response_handler(self, response) -> None:
        entry = {
            "url": response.url,
            "status": response.status,
            "headers": dict(response.headers),
            "time": time.time(),
        }
        with self._captured_lock:
            self._captured.append(entry)
            if len(self._captured) > self._max_captured:
                del self._captured[:-self._max_captured]

        # 访问日志：主文档（页面导航）记 INFO，子资源记 DEBUG，便于调试
        try:
            resource_type = response.request.resource_type if response.request else ""
        except Exception:
            resource_type = ""
        if resource_type == "document":
            self.logger.info(
                f"[Sandbox] 访问页面 [{response.status}] {response.url}"
            )
        else:
            self.logger.debug(
                f"[Sandbox] 资源 [{response.status}] {resource_type} {response.url}"
            )

    def captured_responses(self, limit: int = 50, url_filter: str = "") -> List[Dict[str, Any]]:
        """返回捕获的响应列表（真实/伪造均有）。"""
        with self._captured_lock:
            items = list(self._captured)
        if url_filter:
            items = [i for i in items if url_filter in i.get("url", "")]
        return items[-limit:] if limit else items

    def clear_captured(self) -> None:
        with self._captured_lock:
            self._captured.clear()

    # ============ 页面控制 ============
    def navigate(self, url: str, timeout: float = 30000) -> None:
        """当前主页面导航到指定 URL（等待加载完成）。"""
        self._call(self._navigate(url, timeout))

    async def _navigate(self, url: str, timeout: float) -> None:
        await self._page.goto(url, timeout=timeout, wait_until="load")

    def new_page(self) -> int:
        """打开新标签页，返回页索引。"""
        async def _do():
            await self._context.new_page()
            page = self._context.pages[-1]
            await page.route("**/*", self._route_handler)
            page.on("response", self._response_handler)
            return len(self._context.pages) - 1
        return self._call(_do())

    def page_count(self) -> int:
        if self._context is None:
            return 0
        return self._call(self._count_pages())

    async def _count_pages(self) -> int:
        return len(self._context.pages)

    def _page_at(self, index: int):
        pages = self._context.pages
        if not pages:
            return self._page
        return pages[min(index, len(pages) - 1)]

    # ============ JS 注入（page.evaluate） ============
    def evaluate(self, expression: str, arg: Any = None, page_index: int = 0) -> Any:
        """在目标页面上下文执行任意 JavaScript，返回执行结果。
        可读取/修改 DOM、LocalStorage、Cookie 等。"""
        return self._call(self._evaluate(expression, arg, page_index))

    async def _evaluate(self, expression: str, arg: Any, page_index: int) -> Any:
        page = self._page_at(page_index)
        if arg is None:
            return await page.evaluate(expression)
        return await page.evaluate(expression, arg)

    def evaluate_all_pages(self, expression: str, arg: Any = None) -> List[Any]:
        """在所有标签页中执行同一段 JS，返回结果列表。"""
        return self._call(self._evaluate_all(expression, arg))

    async def _evaluate_all(self, expression: str, arg: Any) -> List[Any]:
        results = []
        for page in self._context.pages:
            if arg is None:
                results.append(await page.evaluate(expression))
            else:
                results.append(await page.evaluate(expression, arg))
        return results

    # --- LocalStorage / Cookie 便捷操作 ---
    def set_local_storage(self, key: str, value: Any, page_index: int = 0) -> None:
        payload = json.dumps(value, ensure_ascii=False)
        self.evaluate(
            f"(k, v) => {{ localStorage.setItem(k, v); return localStorage.getItem(k); }}",
            arg={"k": key, "v": payload},
            page_index=page_index,
        )

    def get_local_storage(self, key: str, page_index: int = 0) -> Any:
        raw = self.evaluate(
            "k => localStorage.getItem(k)",
            arg=key,
            page_index=page_index,
        )
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return raw

    def set_cookie(self, name: str, value: str, url: str = None) -> None:
        """通过 context.add_cookies 设置 Cookie（跨页面生效，需提供 url 或后续注入）。"""
        cookie = {"name": name, "value": value, "path": "/"}
        if url:
            cookie["url"] = url
        else:
            cookie["domain"] = ".example.com"
        self._call(self._set_cookie(cookie))

    async def _set_cookie(self, cookie: dict) -> None:
        await self._context.add_cookies([cookie])

    def get_cookies(self) -> List[Dict[str, Any]]:
        return self._call(self._get_cookies())

    async def _get_cookies(self) -> List[Dict[str, Any]]:
        return await self._context.cookies()

    # ============ CDP 底层操作 ============
    def cdp(self, method: str, params: Optional[dict] = None, page_index: int = 0) -> Any:
        """直接调用原始 DevTools Protocol 命令，如：
        cdp("Network.getResponseBody", {"requestId": rid})
        cdp("Runtime.evaluate", {"expression": "document.title"})
        返回 CDP 返回的原始 JSON 结构。"""
        return self._call(self._cdp(method, params, page_index))

    async def _cdp(self, method: str, params: Optional[dict], page_index: int) -> Any:
        page = self._page_at(page_index)
        session = await self._context.new_cdp_session(page)
        return await session.send(method, params or {})

    def network_requests(self) -> List[Dict[str, str]]:
        """列出 CDP Network 域收集到的 requestId -> url 映射（网络报文级调试入口）。"""
        if self._sniffer is None:
            return []
        return self._sniffer.list_requests()

    def network_responses(self) -> List[Dict[str, Any]]:
        if self._sniffer is None:
            return []
        return self._sniffer.list_responses()

    def get_response_body_by_url(self, url_substring: str) -> Optional[bytes]:
        """按 URL 匹配，通过 CDP Network.getResponseBody 获取原始报文体。"""
        if self._sniffer is None:
            return None
        for req in reversed(self._sniffer.list_responses()):
            if url_substring in req.get("url", ""):
                body = self._call(self._sniffer.get_response_body(req["requestId"]))
                return body
        return None

    def runtime_evaluate(self, expression: str, return_by_value: bool = True) -> Any:
        """Runtime.evaluate：与 page.evaluate 等价的 CDP 原始命令，返回完整 CDP 结构。"""
        return self.cdp("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": return_by_value,
        })


# 模块级辅助：避免顶层 import asyncio 影响启动速度
def asyncio_run_coroutine_threadsafe(coro, loop):
    import asyncio
    return asyncio.run_coroutine_threadsafe(coro, loop)
