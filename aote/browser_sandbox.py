"""
AOTE 管控系统 - 浏览器控制沙盒模块（Playwright for Python）

将原「外部拦截浏览器进程」方案升级为「在独立 Chromium 实例内直接控制浏览器内容」：

- playwright.chromium.launch() 启动独立 Chromium，启动参数携带：
    --disable-web-security        禁用同源策略（便于注入/伪造跨域资源）
    --proxy-server=http://127.0.0.1:8080  预留外部代理通道（本地抓包代理等）
    --remote-debugging-port=9222  开放 CDP 调试端口
    --user-data-dir=<独立目录>     独立用户数据，避免污染主浏览器环境
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
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Callable, Dict, List, Optional, Union

from .config import ConfigManager
from .logger import AOTELogger


# 管控模式常量
MODE_RELAXED = "relaxed"        # 宽松：全部放行（上课/授权时段）
MODE_STRICT = "strict"          # 严格：拦截娱乐/游戏站点，访问即触发数学挑战
MODE_MATH_LOCKDOWN = "math"     # 数学挑战：拦截数学工具站点 + 娱乐站点
MODE_UNLOCKED = "unlocked"      # 临时/永久解锁：全部放行


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

DEFAULT_MATH_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>数学挑战进行中</title>
<style>
 body{margin:0;font-family:"Microsoft YaHei",Arial,sans-serif;
      background:linear-gradient(135deg,#41295a,#2F0743);color:#fff;
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
  <div class="icon">🧮</div>
  <h1>请先完成数学挑战</h1>
  <p>检测到需要专注的操作，请先完成弹出的数学挑战。<br>
     挑战通过后，学习工具将恢复正常使用。</p>
  <span class="tag">AOTE 数学挑战</span>
</div>
</body></html>"""


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
            self._start_error = "playwright 未安装，浏览器沙盒不可用（pip install playwright && playwright install chromium）"

        # 独立 user-data-dir，避免污染主浏览器环境
        cfg_dir = str(config.get("browser_sandbox.user_data_dir", "")).strip()
        if cfg_dir:
            self._user_data_dir = cfg_dir
        else:
            base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local")
            self._user_data_dir = str(Path(base) / "AOTE" / "chromium_profile")

        self._headless = bool(config.get("browser_sandbox.headless", False))
        self._default_url = str(config.get("browser_sandbox.default_url", "about:blank"))

    # ============ 浏览器内容管控规则 ============
    def _load_browser_rules(self) -> None:
        """从配置加载浏览器管控规则（域名黑名单/白名单/数学工具名单）。"""
        rules = self.config.get("browser_rules", {}) or {}
        self._block_domains = [str(d).lower().strip() for d in rules.get("block_domains", [])]
        self._allowed_domains = [str(d).lower().strip() for d in rules.get("allowed_domains", [])]
        self._math_lockdown_domains = [str(d).lower().strip() for d in rules.get("math_lockdown_domains", [])]
        self._blocked_page_html = str(rules.get("blocked_page_html", "")) or DEFAULT_BLOCKED_PAGE
        self._math_lockdown_page_html = str(rules.get("math_lockdown_page_html", "")) or DEFAULT_MATH_PAGE

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
        用于通知 Orchestrator 触发数学挑战等。"""
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
        - MODE_STRICT: 拦截娱乐/游戏站点，访问即违规
        - MODE_MATH_LOCKDOWN: 拦截数学工具 + 娱乐站点（数学挑战期间）
        - MODE_UNLOCKED: 临时解锁（unlock_seconds>0）或永久解锁（unlock_seconds<=0）
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
        return self._browser is not None and self._thread is not None and self._thread.is_alive()

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
            self.logger.info("[Sandbox] 浏览器沙盒已启动（独立 Chromium）")
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
        # 独立 Chromium 实例：携带 --disable-web-security / --proxy-server /
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

        self.logger.info(
            f"[Sandbox] 启动独立 Chromium: headless={self._headless} args={launch_args}"
        )
        self._browser = await self._playwright.chromium.launch(
            headless=self._headless,
            args=launch_args,
        )
        # 创建隔离浏览上下文
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=None,
        )
        # 打开默认页面并注册路由拦截 + 响应捕获
        self._page = await self._context.new_page()
        await self._page.route("**/*", self._route_handler)
        self._page.on("response", self._response_handler)

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

    async def _cleanup(self) -> None:
        """浏览器统一清理（browser.close()）"""
        try:
            if self._browser is not None:
                await self._browser.close()
        except Exception as e:
            self.logger.debug(f"[Sandbox] 关闭浏览器异常: {e}")
        self._browser = None
        self._context = None
        self._page = None
        self._cdp_session = None
        self._sniffer = None

    def stop(self, timeout: float = 30.0) -> None:
        """请求关闭沙盒并等待浏览器进程清理完成。"""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._thread:
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

        if mode == MODE_MATH_LOCKDOWN:
            # 数学挑战期间：拦截数学工具 + 娱乐/游戏站点，其余放行
            if self._domain_match(host, self._math_lockdown_domains):
                return {"action": "block", "reason": "math_lockdown",
                        "page": self._math_lockdown_page_html}
            if self._domain_match(host, self._block_domains):
                return {"action": "block", "reason": "blocked_domain",
                        "page": self._blocked_page_html}
            return {"action": "allow", "reason": "", "page": ""}

        if mode == MODE_STRICT:
            if self._domain_match(host, self._block_domains):
                return {"action": "block", "reason": "blocked_domain",
                        "page": self._blocked_page_html}
            return {"action": "allow", "reason": "", "page": ""}

        # MODE_RELAXED 与其它：放行
        return {"action": "allow", "reason": "", "page": ""}

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
