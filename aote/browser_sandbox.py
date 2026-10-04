"""
AOTE 管控系统 - 浏览器控制沙盒模块（Playwright for Python）

本系统不再主动抢占用户的正常浏览会话，而是通过 CDP 接管外部浏览器
（配合 scripts/hijack_browser_entries.ps1 将各入口统一改为带调试端口启动）。

接管不依赖"独立文件目录参数"（--user-data-dir）：只要浏览器带任意远程调试开关
（--remote-debugging-port[=任意值] / --remote-debugging-pipe），即判定为受管实例；
若浏览器完全不带调试参数（含快捷方式被误删参数、或调试参数被已有实例吞掉导致
端口未开启的情况），进程监控会终止该实例并自动以受管参数（调试端口 + 独立
profile）重新拉起，从而保证任何入口打开的浏览器最终都能被 AOTE 接管。
该兜底行为由 browser_sandbox.auto_relaunch_managed 控制（默认开启）。

接管后的管控手段：
- ctx.route("**/*", handler) 在浏览器内部直接拦截 HTTPS 请求：
  should_intercept(url) 命中 -> route.fulfill(status/headers/body 完全可控)
  否则 route.continue_() 放行 —— 无需外部代理程序处理 TLS
- page.evaluate("() => {...}") 在目标页面上下文执行任意 JS（DOM/LocalStorage/Cookie）
- page.on("response", handler) 捕获所有真实/伪造的响应数据
- 底层 CDP：page.context.new_cdp_session(page) 获取 CDP Session，直接调用
  Network.getResponseBody / Network.emulateNetworkConditions 等原始协议命令
- 关闭时仅断开 CDP 连接，不关闭用户浏览器

架构说明：Playwright 的 async API 绑定在独立 asyncio 事件循环线程中运行，
所有公开方法均为线程安全的同步包装（内部 run_coroutine_threadsafe 调度），
因此主控线程/其他组件线程可随时调用。
"""
import os
import re
import time
import json
import socket
import subprocess
import threading
import asyncio
from asyncio import run_coroutine_threadsafe as asyncio_run_coroutine_threadsafe
from collections import deque
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse, unquote
from html import unescape as html_unescape
from typing import Any, Callable, Dict, List, Optional, Union

from .block_page import DEFAULT_BLOCKED_PAGE, BLOCK_PAGE_FRAGMENT


# 管控模式常量
MODE_RELAXED = "relaxed"        # 宽松：全部放行（上课/授权时段）
MODE_STRICT = "strict"          # 严格：拦截娱乐/游戏站点，访问即记违规并切换弱网
MODE_UNLOCKED = "unlocked"      # 临时/永久解锁：全部放行（密码豁免）

# 默认调试端口（connect_cdp_url 未配置端口时使用）
DEFAULT_CDP_PORT = 9222

# 一律放行的协议与本机地址（管控不介入浏览器自身与本地服务）
PASSTHROUGH_SCHEMES = ("data", "about", "javascript", "chrome")
PASSTHROUGH_HOSTS = ("127.0.0.1", "localhost", "::1")

# 动态黑名单（block_url_now）最大条目数，避免无限膨胀
MAX_DYNAMIC_BLOCK_DOMAINS = 500

# 探测浏览器调试端口是否可连接的超时（秒）。
# 用于识别"命令行有调试参数、但端口实际没监听"的假受管实例。
DEBUG_PORT_PROBE_TIMEOUT = 0.5

# 主题检测时扫描响应体的最大字符数。覆盖 title / meta / 首屏正文已足够，
# 避免超大页面（如长词条）产生无谓的字符串拷贝与匹配开销。
MAX_TOPIC_SCAN_CHARS = 50000

# 游戏关键词规则在日志/违规记录里使用的规则名
GAME_KEYWORD_RULE_NAME = "游戏关键词"

# 短拉丁关键词（<= 该长度且纯 ASCII）采用词边界匹配：
# 避免 "dnf" 命中随机串、"cf" 命中 "config"、"lol" 命中英文语气词这类误伤。
GAME_SHORT_LATIN_MAXLEN = 5

# 标题正则规则在日志/违规记录里使用的规则名前缀
TITLE_REGEX_RULE_PREFIX = "title_regex"

# 从响应体里提取 <title> 的正则（DOTALL：标题可能跨行或很长）
TITLE_TAG_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# 浏览器启动宽限期（秒）：刚拉起的进程需要数百毫秒到数秒才会真正监听调试端口。
# 在此期间若按"端口未监听"判为假受管并终止，会导致用户点链接后浏览器反复闪退重启。
STARTUP_PORT_GRACE_SEC = 15.0


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

    def __init__(self, cdp_session, logger, max_entries: int = 1000):
        self._session = cdp_session
        self._logger = logger
        self._max = max_entries
        self._requests: Dict[str, str] = {}
        # 定长队列：超上限自动丢弃最旧的记录，无需手动裁剪
        self._responses: deque = deque(maxlen=max_entries)
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
            result = await self._session.send(
                "Network.getResponseBody", {"requestId": request_id}
            )
            body = result.get("body", "")
            if result.get("base64Encoded"):
                import base64
                return base64.b64decode(body)
            return body.encode("utf-8", errors="replace")
        except Exception as e:
            self._logger.debug(f"[Sandbox] getResponseBody 失败: {e}")
            return None


# ======================================================
# 默认管控拦截页
# ======================================================
# 页面样式与结构统一维护在 aote/block_page.py（表现层独立，便于单独调样式）：
#   DEFAULT_BLOCKED_PAGE —— 路由层 403 响应使用的完整文档
#   BLOCK_PAGE_FRAGMENT  —— 页面内 JS 注入使用的 head+body 片段
# 两者共用同一套 CSS，避免"路由页 / JS 注入页"样式各自漂移。
# 可被 config browser_rules.blocked_page_html 整体覆盖（自定义页面原样返回）。


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

# 主题限制的前端检测脚本模板。
# __TOPIC_BLOCKS__ / __REPORT_URL__ 由 _topic_block_script() 用配置填充。
#
# 路由层只能看到 URL，看不到页面标题、<meta> 元数据与正文主题，因此这里在页面内
# 做补充检测，并覆盖站内搜索、推荐跳转、SPA 路由切换等不产生新文档请求的入口：
#   - DOMContentLoaded 尽早扫描 + MutationObserver 持续扫描（异步渲染的内容）
#   - popstate / hashchange 重新扫描（单页应用站内跳转）
# 命中即 window.stop() 阻止继续加载、替换为统一受限提示，并向本地服务上报以便审计。
TOPIC_BLOCK_JS = """\
() => {
  const BLOCKS = __TOPIC_BLOCKS__;
  const REPORT = "__REPORT_URL__";
  const ALLOWED = __ALWAYS_ALLOWED__;
  const TREGEX = __TITLE_REGEX__;
  // 标题正则预编译：扫描会被 MutationObserver 反复触发，不能每次重建 RegExp
  const TREGEX_C = [];
  if (TREGEX && TREGEX.length) {
    for (var ti = 0; ti < TREGEX.length; ti++) {
      try { TREGEX_C.push({ name: TREGEX[ti].name, re: new RegExp(TREGEX[ti].pattern, 'i') }); }
      catch (e) {}
    }
  }
  // 豁免时间段标志：主程序在豁免窗口开关时通过 evaluate 写入当前页面；
  // 同时每次切换都会重新注册一份本脚本，使后续新文档也能拿到最新值。
  window.__AOTE_EXEMPT = __EXEMPT__;
  // 幂等保护：因豁免切换会重复注册本脚本，只让首份安装监听器，
  // 后续副本仅用于刷新上面的豁免标志（避免重复监听与重复上报）。
  var __g = window.__AOTE_TOPIC_GUARD || {};
  if (__g.installed) return;
  __g.installed = true;
  __g.blocks = (BLOCKS || []).length;
  __g.titleRegex = TREGEX_C.length;
  // 全局标记：便于从页面侧确认检测脚本已注入（排障用）
  window.__AOTE_TOPIC_GUARD = __g;
  // 全局白名单豁免：页面级 JS 检测对豁免域名完全不生效，
  // 否则路由层放行了、页面 JS 仍会把页面替换成拦截页（两层必须一致）。
  if (ALLOWED && ALLOWED.length) {
    var h = (location.hostname || '').toLowerCase();
    for (var ai = 0; ai < ALLOWED.length; ai++) {
      var d = String(ALLOWED[ai]).toLowerCase();
      if (h === d || h.indexOf('.' + d) === h.length - d.length - 1) {
        window.__AOTE_TOPIC_GUARD = { blocks: (BLOCKS || []).length, exempt: true };
        return;
      }
    }
  }
  if ((!BLOCKS || !BLOCKS.length) && !TREGEX_C.length) return;
  let done = false;

  function blocked(name, kw) {
    done = true;
    try { window.stop(); } catch (e) {}
    // 拦截页 HTML 由主程序注入（与路由层 403 页共用 aote/block_page.py 的同一套模板，
    // 保证两处观感一致）。内联 onclick 依赖 document 内联脚本执行，天然可用。
    var html = __BLOCK_HTML__;
    try { document.documentElement.innerHTML = html; } catch (e) {}
    // 移动端适配：原站可能没写 viewport，或写死了窄于设备的宽度，
    // 这里强制按设备宽度渲染，否则手机上拦截页会整体缩放走样。
    try {
      var vp = document.querySelector('meta[name="viewport"]');
      if (!vp) {
        vp = document.createElement('meta');
        vp.setAttribute('name', 'viewport');
        (document.head || document.documentElement).appendChild(vp);
      }
      vp.setAttribute('content', 'width=device-width,initial-scale=1,viewport-fit=cover');
    } catch (e) {}
    // 上报审计：本地服务会把该 URL 记入违规日志并加入即时拦截清单
    try {
      fetch(REPORT, { method: 'POST', mode: 'no-cors',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ url: location.href, reason: name + ':' + kw }) });
    } catch (e) {}
  }

  function scan() {
    if (done) return;
    // 豁免时间段：所有限制暂停（含检测与拦截）；窗口结束后由主程序
    // 重新置位并调用 __AOTE_RESCAN 立即恢复生效。
    if (window.__AOTE_EXEMPT) return;
    // 标题正则优先：游戏标题（扫雷/2048/俄罗斯方块…）往往关键词表覆盖不到
    if (TREGEX_C.length) {
      var rawTitle = document.title || '';
      for (var tr = 0; tr < TREGEX_C.length; tr++) {
        var tm = TREGEX_C[tr].re.exec(rawTitle);
        if (tm) { blocked(TREGEX_C[tr].name, tm[0]); return; }
      }
    }
    var title = (document.title || '').toLowerCase();
    var meta = '';
    try {
      var ms = document.querySelectorAll('meta');
      for (var i = 0; i < ms.length; i++) {
        meta += ' ' + ((ms[i].getAttribute('content') || '') + ' ' +
                       (ms[i].getAttribute('name') || '') + ' ' +
                       (ms[i].getAttribute('property') || '')).toLowerCase();
      }
    } catch (e) {}
    var body = '';
    try {
      body = document.body ? (document.body.innerText || '') : '';
      body = body.slice(0, 4000).toLowerCase();
    } catch (e) {}
    for (var b = 0; b < BLOCKS.length; b++) {
      var blk = BLOCKS[b];
      for (var j = 0; j < blk.keywords.length; j++) {
        var k = blk.keywords[j];
        if (blk.title && title.indexOf(k) >= 0) { blocked(blk.name, k); return; }
        if (blk.meta && meta.indexOf(k) >= 0) { blocked(blk.name, k); return; }
        if (blk.content && body.indexOf(k) >= 0) { blocked(blk.name, k); return; }
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scan, { once: true });
  } else { scan(); }
  window.addEventListener('load', scan, { once: true });
  try {
    new MutationObserver(scan).observe(document.documentElement,
      { childList: true, subtree: true });
  } catch (e) {}
  function rescan() { done = false; scan(); }
  // 供主程序在豁免结束时主动触发一次重新检测
  window.__AOTE_RESCAN = rescan;
  window.addEventListener('popstate', rescan);
  window.addEventListener('hashchange', rescan);
}
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

    def __init__(self, config, logger):
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
        self._exempt_active: bool = False        # 豁免时间段标志（由 TimeGuard 驱动）
        self._on_violation: Optional[Callable[[str, str], None]] = None
        self._last_heartbeat: float = time.time()
        self._violation_cooldown: Dict[str, float] = {}   # url->last 触发时间，去抖
        self._state_lock = threading.Lock()
        self._load_browser_rules()
        # 弱网状态（命中黑名单自动切换）
        self._weak_network_active = False      # 当前是否处于弱网
        self._weak_network_since = 0.0         # 弱网激活时间戳
        self._weak_network_host = ""           # 触发弱网的域名

        # 响应捕获（page.on("response")）：定长队列自动丢弃最旧记录
        self._max_captured = int(config.get("browser_sandbox.max_captured", 1000))
        self._captured: deque = deque(maxlen=self._max_captured)
        self._captured_lock = threading.Lock()

        # 网络嗅探器（CDP）
        self._sniffer: Optional[_NetworkSniffer] = None

        # 可用性检查：playwright 未安装时降级为不可用，不影响主程序启动
        self.available = True
        try:
            import playwright  # noqa: F401
        except Exception:
            self.available = False
            self._start_error = ("playwright 未安装，浏览器沙盒不可用"
                                 "（pip install playwright；默认复用本机 Edge/Chrome）")

        # 独立 user-data-dir，避免污染主浏览器环境
        #（默认与 scripts/hijack_browser_entries.ps1 的 cdp_debug_profile 保持一致，
        #  便于进程监控据此识别受管实例）
        cfg_dir = str(config.get("browser_sandbox.user_data_dir", "")).strip()
        if cfg_dir:
            self._user_data_dir = cfg_dir
        else:
            base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local")
            self._user_data_dir = str(Path(base) / "AOTE" / "cdp_debug_profile")

        # CDP 连接模式：仅接管用户通过快捷方式/手动打开的外部浏览器
        #（如 connect_over_cdp("http://127.0.0.1:9222")），系统不再自动打开浏览器
        self._connect_cdp_url = str(
            config.get("browser_sandbox.connect_cdp_url", "") or ""
        ).strip()
        # 调试端口（从 connect_cdp_url 解析，用于自动拉起受管浏览器）
        self._cdp_port = self._parse_cdp_port(self._connect_cdp_url)
        # 全入口接管（无论用户通过何种方式打开浏览器，都纳入 CDP 管控）：
        # 监控系统内浏览器进程，凡未带调试参数的一律终止接管
        self._monitor_browser_processes = bool(config.get(
            "browser_sandbox.monitor_browser_processes", True))
        # 兜底接管：快捷方式缺少独立 profile（--user-data-dir）等参数时，
        # 终止未受管实例后自动以受管参数重新拉起浏览器，确保能被 CDP 接管
        self._auto_relaunch_managed = bool(config.get(
            "browser_sandbox.auto_relaunch_managed", True))
        # 仅在非上课时段（严格模式）接管未受管浏览器：上课时段本就不拦截任何内容，
        # 终止浏览器只会打断正常教学对浏览器的使用，没有任何管控收益
        self._takeover_only_in_strict = bool(config.get(
            "browser_sandbox.takeover_only_in_strict", True))
        # 接管开关的上次取值（仅在状态翻转时记日志，避免每轮刷屏）
        self._takeover_state_last: Optional[bool] = None
        # 自动拉起节流（避免失败时高频重试）：上次拉起时间戳与连续失败次数
        self._last_relaunch_at: float = 0.0
        self._relaunch_failures = 0
        # 浏览器进程查询连续失败次数（用于暴露 watchdog 静默失效）
        self._query_failures = 0

    # ============ 浏览器内容管控规则 ============
    def _load_browser_rules(self) -> None:
        """从配置加载浏览器管控规则（域名黑名单/白名单/弱网参数）。"""
        rules = self.config.get("browser_rules", {}) or {}
        self._block_domains = [str(d).lower().strip()
                               for d in (rules.get("block_domains") or [])]
        self._allowed_domains = [str(d).lower().strip()
                                 for d in (rules.get("allowed_domains") or [])]
        # 全局豁免白名单：绕过全部应用层管控（主题/游戏关键词/视频/弱网/重定向）。
        # 与 allowed_domains 的区别：allowed_domains 仅在严格模式下优先于黑名单放行，
        # 拦不住主题与关键词；这里列出的域名是"任何策略都不拦"。
        self._always_allowed_domains = [
            str(d).lower().strip().lstrip("*.")
            for d in (rules.get("always_allowed_domains") or []) if str(d).strip()
        ]
        gk = rules.get("game_keywords") or {}
        self._game_keywords_enabled = bool(gk.get("enabled", True))
        self._game_keywords = [str(k).strip().lower()
                               for k in (gk.get("keywords") or []) if str(k).strip()]
        self._game_check_url = bool(gk.get("check_url", True))
        self._game_check_content = bool(gk.get("check_content", True))
        self._game_matchers = self._build_game_matchers(self._game_keywords)
        # 页面标题正则拦截：[(规则名, 原始正则串, 编译后的正则)]
        # 关键词表是"子串包含"，表达不了"扫雷|21点|8-ball"这类候选集合，
        # 这里补一条正则通道，统一用 IGNORECASE（标题大小写不可控）。
        self._title_regex_rules: List[tuple] = []
        for trb in (rules.get("title_regex_blocks") or []):
            if not isinstance(trb, dict):
                continue
            name = str(trb.get("name", "") or "").strip()
            pattern = str(trb.get("pattern", "") or "").strip()
            if not name or not pattern or not bool(trb.get("enabled", True)):
                continue
            try:
                self._title_regex_rules.append((name, pattern, re.compile(pattern, re.IGNORECASE)))
            except re.error as e:
                self.logger.warning(f"[Sandbox] 标题正则编译失败（已跳过）{name}: {e}")
        self._blocked_page_html = str(rules.get("blocked_page_html", "") or DEFAULT_BLOCKED_PAGE)
        self._video_block_enabled = bool(rules.get("video_block_enabled", True))
        # 弱网参数（命中黑名单时触发）
        wn = rules.get("weak_network") or {}
        self._weak_network_enabled = bool(wn.get("enabled", False))
        self._weak_network_delay_ms = int(wn.get("delay_ms", 3000))
        self._weak_network_latency_ms = int(wn.get("latency_ms", 800))
        self._weak_network_download_kbps = int(wn.get("download_kbps", 128))
        self._weak_network_upload_kbps = int(wn.get("upload_kbps", 64))
        self._weak_network_min_duration = float(wn.get("min_duration", 15))
        # 主题限制规则（URL / 标题 / 元数据 / 正文 多维度）
        self._topic_blocks: List[Dict[str, Any]] = []
        for tb in (rules.get("topic_blocks") or []):
            if not isinstance(tb, dict):
                continue
            name = str(tb.get("name", "") or "").strip()
            keywords = [str(k).strip().lower()
                        for k in (tb.get("keywords") or []) if str(k).strip()]
            # 关闭的、或没有有效关键词的规则直接忽略（避免空规则拖慢每个请求）
            if not name or not keywords or not bool(tb.get("enabled", True)):
                continue
            self._topic_blocks.append({
                "name": name,
                "keywords": keywords,
                "check_url": bool(tb.get("check_url", True)),
                "check_title": bool(tb.get("check_title", True)),
                "check_meta": bool(tb.get("check_meta", True)),
                "check_content": bool(tb.get("check_content", True)),
                # false=始终生效（默认）；true=仅在非上课时段生效
                "strict_mode_only": bool(tb.get("strict_mode_only", False)),
            })
        # 可观测性：规则是否真的被加载，是排查"配了却拦不住"的第一手依据
        if self._topic_blocks:
            self.logger.info(
                f"[Sandbox] 主题限制规则已加载 {len(self._topic_blocks)} 条: "
                + ", ".join(b["name"] for b in self._topic_blocks)
            )
        if self._always_allowed_domains:
            self.logger.info(
                "[Sandbox] 全局豁免白名单已加载 "
                f"{len(self._always_allowed_domains)} 个域名: "
                + ", ".join(self._always_allowed_domains)
            )
        if self._game_keywords_enabled and self._game_keywords:
            self.logger.info(
                f"[Sandbox] 游戏关键词已加载 {len(self._game_keywords)} 个"
                f"（url={self._game_check_url}, content={self._game_check_content}）"
            )
        if self._title_regex_rules:
            self.logger.info(
                f"[Sandbox] 标题正则规则已加载 {len(self._title_regex_rules)} 条: "
                + ", ".join(n for n, _, _ in self._title_regex_rules)
            )
        # 域名重定向规则：命中域名（裸域 + 全部子域、任意路径）-> 302 跳转目标站。
        # 在请求阶段直接 fulfill 302，浏览器不会向原站发起任何网络请求、也不会
        # 渲染原站内容，即"页面加载前触发跳转"。
        for rd in (rules.get("redirect_rules") or []):
            if not isinstance(rd, dict):
                continue
            target = str(rd.get("target", "") or "").strip()
            domains = [str(d).strip() for d in (rd.get("domains") or []) if str(d).strip()]
            if not target or not domains or not bool(rd.get("enabled", True)):
                continue

            def _redirect_matcher(url: str, d=domains) -> bool:
                return self._domain_match(self._host_of(url), d)

            with self._rules_lock:
                rule_id = self._next_rule_id
                self._next_rule_id += 1
                self._intercept_rules.append(
                    InterceptRule(rule_id, _redirect_matcher, 302,
                                  {"Location": target}, b"")
                )
            self.logger.info(
                f"[Sandbox] 重定向规则已加载 #{rule_id}: "
                + ", ".join(domains) + f" -> {target}"
            )

    @staticmethod
    @lru_cache(maxsize=1024)
    def _normalize_domain_pattern(pattern: str) -> str:
        """归一化域名规则：'*.Example.com' -> 'example.com'（结果缓存，供热路径复用）"""
        return pattern.lower().strip().lstrip("*.").strip()

    def _domain_match(self, host: str, patterns: List[str]) -> bool:
        """域名匹配：支持 'example.com' 与 '*.example.com' 两种写法。
        语义：二者均覆盖裸域 + 所有子域（宽松匹配，对拦截更安全）。"""
        host = (host or "").lower().strip().rstrip(".")
        if not host:
            return False
        for pat in patterns:
            norm = self._normalize_domain_pattern(pat)
            if norm and (host == norm or host.endswith("." + norm)):
                return True
        return False

    @staticmethod
    def _host_of(url: str) -> str:
        """从 URL 提取小写主机名（解析失败返回空串）"""
        try:
            return (urlparse(url).hostname or "").lower()
        except Exception:
            return ""

    @staticmethod
    def _build_game_matchers(keywords: List[str]):
        """为游戏关键词预编译匹配器，返回 [(关键词, 正则或 None)]。

        None 表示按子串匹配；非 None 表示需按词边界匹配（短拉丁词专用）。
        预编译的目的是让每个请求的热路径只做 search，不重复编译正则。
        """
        matchers = []
        for kw in keywords:
            if not kw:
                continue
            if kw.isascii() and len(kw) <= GAME_SHORT_LATIN_MAXLEN:
                rx = re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])")
                matchers.append((kw, rx))
            else:
                matchers.append((kw, None))
        return matchers

    def _match_game_keyword(self, text: str) -> Optional[str]:
        """按游戏关键词表匹配文本，返回命中的关键词；未命中返回 None。"""
        if not text or not self._game_matchers:
            return None
        low = text.lower()
        for kw, rx in self._game_matchers:
            if rx is not None:
                if rx.search(low):
                    return kw
            elif kw in low:
                return kw
        return None

    def _match_game_in_url(self, url: str) -> Optional[tuple]:
        """URL 维度的游戏关键词检测，返回 (规则名, 命中关键词)。

        同时匹配原始 URL 与解码后 URL：查询串里的中文会被 percent-encode
        （如 ?q=%E7%8E%8B%E8%80%85%E8%8D%A3%E8%80%80），不解码则永远命中不了。
        """
        if not (self._game_keywords_enabled and self._game_check_url) or not url:
            return None
        try:
            decoded = unquote(url)
        except Exception:
            decoded = url
        kw = self._match_game_keyword(url) or self._match_game_keyword(decoded)
        return (GAME_KEYWORD_RULE_NAME, kw) if kw else None

    def _match_game_in_text(self, text: str) -> Optional[tuple]:
        """正文/响应体维度的游戏关键词检测，返回 (规则名, 命中关键词)。"""
        if not (self._game_keywords_enabled and self._game_check_content) or not text:
            return None
        kw = self._match_game_keyword(text[:MAX_TOPIC_SCAN_CHARS])
        return (GAME_KEYWORD_RULE_NAME, kw) if kw else None

    def _match_title_regex(self, html_text: str) -> Optional[tuple]:
        """从 HTML 中取出 <title> 并做正则匹配，返回 (规则名, 命中片段)。

        用正则而非关键词：像"扫雷|21点|8-ball"这类候选集合、以及
        `Lights\\s*Off`、`8\\s*[-\\s]?ball` 这类带容错的写法，子串匹配表达不了。
        """
        if not self._title_regex_rules or not html_text:
            return None
        m = TITLE_TAG_RE.search(html_text[:MAX_TOPIC_SCAN_CHARS])
        if not m:
            return None
        title = html_unescape(m.group(1)).strip()
        if not title:
            return None
        for name, _, rx in self._title_regex_rules:
            hit = rx.search(title)
            if hit:
                return (name, hit.group(0))
        return None

    def _is_always_allowed(self, url: str) -> bool:
        """是否属于全局豁免白名单域名（裸域 + 全部子域、任意路径全放行）。"""
        if not self._always_allowed_domains:
            return False
        return self._domain_match(self._host_of(url), self._always_allowed_domains)

    def _should_check_response_body(self, route) -> bool:
        """是否需对响应体做主题检测：仅主文档，且存在开启 content 维度的规则。"""
        if not any(b["check_content"] for b in self._topic_blocks):
            if not (self._game_keywords_enabled and self._game_check_content
                    and self._game_keywords):
                if not self._title_regex_rules:
                    return False
        try:
            return route.request.resource_type == "document"
        except Exception:
            return False
        try:
            return route.request.resource_type == "document"
        except Exception:
            return False

    def _match_topic_content(self, text: str) -> Optional[tuple]:
        """在页面文本（响应体）中检测主题关键词，返回 (规则名, 命中关键词)。

        只检查前 MAX_TOPIC_SCAN_CHARS 个字符：既覆盖标题/元数据与首屏正文，
        又避免超大页面带来的无谓开销。
        """
        if not text:
            return None
        sample = text[:MAX_TOPIC_SCAN_CHARS]
        for block in self._topic_blocks:
            if not block["check_content"]:
                continue
            kw = self._match_topic_keyword(sample, block["keywords"])
            if kw:
                return (block["name"], kw)
        return None

    @staticmethod
    def _match_topic_keyword(text: str, keywords: List[str]) -> Optional[str]:
        """在文本中查找命中的主题关键词；返回命中的关键词，未命中返回 None。"""
        low = (text or "").lower()
        if not low:
            return None
        for kw in keywords:
            if kw and kw in low:
                return kw
        return None

    def _match_topic_in_url(self, url: str) -> Optional[tuple]:
        """URL / 路径 / 查询串维度的主题检测，返回 (规则名, 命中关键词)。

        覆盖直接链接、站内搜索（?q=...）、推荐跳转与外部引荐（?ref=...）等入口——
        这些入口最终都体现在请求 URL 上，路由层即可拦截，无需等页面渲染。

        关键：浏览器会把查询串中的中文等非 ASCII 字符编码成 %XX（percent-encoding），
        例如搜索"火影忍者"实际请求为 ?q=%E7%81%AB%E5%BD%B1%E5%BF%8D%E8%80%85。
        因此必须同时匹配原始 URL 与解码后的 URL，否则中文关键词将永远无法命中。
        """
        if not url:
            return None
        try:
            decoded = unquote(url)
        except Exception:
            decoded = url
        for block in self._topic_blocks:
            if not block["check_url"]:
                continue
            kw = (self._match_topic_keyword(url, block["keywords"])
                  or self._match_topic_keyword(decoded, block["keywords"]))
            if kw:
                return (block["name"], kw)
        return None

    def _topic_block_script(self) -> str:
        """用当前配置生成主题检测脚本（关键词与上报地址注入 JS 模板）。

        未配置任何有效规则时返回空串，调用方跳过注入，避免无谓的页面开销。
        """
        blocks = [
            {
                "name": b["name"],
                "keywords": b["keywords"],
                "title": b["check_title"],
                "meta": b["check_meta"],
                "content": b["check_content"],
            }
            for b in self._topic_blocks
            if b["check_title"] or b["check_meta"] or b["check_content"]
        ]
        # 游戏关键词：页面维度（标题/元数据/正文）与主题限制共用同一套 JS 扫描，
        # 这样"异步渲染的内容"和"接管前已打开的旧标签页"也能覆盖到。
        if self._game_keywords_enabled and self._game_check_content and self._game_keywords:
            blocks.append({
                "name": GAME_KEYWORD_RULE_NAME,
                "keywords": self._game_keywords,
                "title": True, "meta": True, "content": True,
            })
        if not blocks and not self._title_regex_rules:
            return ""
        port = int(self.config.get("http_server.port", 8765))
        return (TOPIC_BLOCK_JS
                .replace("__TOPIC_BLOCKS__", json.dumps(blocks, ensure_ascii=False))
                .replace("__ALWAYS_ALLOWED__",
                         json.dumps(self._always_allowed_domains, ensure_ascii=False))
                .replace("__TITLE_REGEX__",
                         json.dumps([{"name": n, "pattern": p}
                                     for n, p, _ in self._title_regex_rules],
                                    ensure_ascii=False))
                .replace("__EXEMPT__", "true" if self.is_exempt() else "false")
                .replace("__BLOCK_HTML__",
                         json.dumps(BLOCK_PAGE_FRAGMENT, ensure_ascii=False))
                .replace("__REPORT_URL__", f"http://127.0.0.1:{port}/kill"))

    # ============ 违规回调 ============
    def set_on_violation(self, callback: Optional[Callable[[str, str], None]]) -> None:
        """设置违规回调：拦截到黑名单站点时调用 callback(url, reason)。
        用于通知 Orchestrator 记录违规日志（弱网由沙盒自行切换）。"""
        self._on_violation = callback

    def _notify_violation(self, url: str, reason: str) -> None:
        """违规通知（去抖时间从 time_settings.violation_cooldown 读取，默认 10s）。"""
        cooldown = float(self.config.get("time_settings.violation_cooldown", 10))
        now = time.time()
        with self._state_lock:
            if now - self._violation_cooldown.get(url, 0.0) < cooldown:
                return
            self._violation_cooldown[url] = now
            cb = self._on_violation
        if cb is not None:
            try:
                cb(url, reason)
            except Exception:
                pass

    # ============ 管控模式 ============
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
        self._apply_mode_side_effects(mode)

    def _apply_mode_side_effects(self, mode: str) -> None:
        """模式切换的副作用：严格模式开启视频管控；宽松/解锁/豁免关闭视频管控并恢复网络。"""
        with self._state_lock:
            exempt = self._exempt_active
        if mode == MODE_STRICT and not exempt:
            if self._video_block_enabled:
                self._request_media_block(True)
        elif mode in (MODE_RELAXED, MODE_UNLOCKED) or exempt:
            self._request_media_block(False)
            with self._state_lock:
                self._weak_network_active = False
                self._weak_network_host = ""
            self._request_weak_network(False)

    def set_exempt(self, active: bool) -> None:
        """进入/退出豁免时间段（由 TimeGuard 按 exempt_windows 驱动）。

        豁免期间等同"临时解锁"：所有限制（主题/游戏关键词/标题正则/黑名单/
        视频管控/弱网限速/域名重定向/未受管浏览器接管）全部暂停；
        窗口结束由 TimeGuard 再次调用本方法（active=False）自动恢复，
        恢复后的强度仍由当前管控模式（严格/宽松）决定。
        """
        active = bool(active)
        with self._state_lock:
            if self._exempt_active == active:
                return
            self._exempt_active = active
            mode = self._control_mode
        if active:
            self.logger.info(
                "[Sandbox] 进入豁免时间段：所有限制已暂停（窗口结束自动恢复）"
            )
        else:
            self.logger.info(
                f"[Sandbox] 豁免时间段结束：恢复管控（当前模式 {mode}）"
            )
        self._apply_mode_side_effects(mode)
        # 已打开页面与后续新文档都要同步豁免标志，否则页面内 JS 仍会拦截
        self._request_exempt_flag(active)

    def is_exempt(self) -> bool:
        """当前是否处于豁免时间段。"""
        with self._state_lock:
            return self._exempt_active

    def temporary_unlock(self, seconds: float) -> None:
        """临时解锁浏览器 N 秒。"""
        self.set_control_mode(MODE_UNLOCKED, seconds)

    def permanent_unlock(self) -> None:
        """永久解锁浏览器。"""
        self.set_control_mode(MODE_UNLOCKED, 0)

    def restore_strict_mode(self) -> None:
        """恢复严格管控模式。"""
        self.set_control_mode(MODE_STRICT)

    def _is_unlocked_locked(self) -> bool:
        """在已持有 _state_lock 的前提下判断是否处于"不受限制"状态。

        包含三种来源：永久解锁、未过期的临时解锁、时间段豁免。
        三者都表示"所有限制暂停"，因此复用同一判定入口，
        内容管控 / 视频管控 / 弱网限速 / 域名重定向等消费者无需各自感知豁免。
        """
        if self._permanent_unlock or self._exempt_active:
            return True
        return (self._control_mode == MODE_UNLOCKED
                and self._unlock_until > time.time())

    def is_unlocked(self) -> bool:
        """是否处于（未过期的）解锁状态。"""
        with self._state_lock:
            return self._is_unlocked_locked()

    def current_mode(self) -> str:
        with self._state_lock:
            return self._control_mode

    # ============ 域名黑名单增删 ============
    def block_url_now(self, url: str) -> None:
        """即时将指定 URL 加入临时黑名单（HTTP 上报违禁内容时调用）。
        该 URL 在严格模式下也会被拦截，直到调用 unblock_url() 或切换模式。"""
        host = self._host_of(url)
        if not host:
            return
        with self._state_lock:
            self._block_domains.append(host)
            # 避免无限膨胀
            if len(self._block_domains) > MAX_DYNAMIC_BLOCK_DOMAINS:
                del self._block_domains[:-MAX_DYNAMIC_BLOCK_DOMAINS]
        self.logger.info(f"[Sandbox] 即时拦截域名: {host}")

    def unblock_url(self, url: str) -> None:
        """从临时黑名单移除指定 URL（不触碰配置中的永久名单）。"""
        host = self._host_of(url)
        if not host:
            return
        cfg_domains = [d.lower().strip()
                       for d in (self.config.get("browser_rules.block_domains") or [])]
        with self._state_lock:
            self._block_domains = [
                d for d in self._block_domains
                if not (d == host and d not in cfg_domains)  # 仅移除动态加入的
            ]
        self.logger.info(f"[Sandbox] 解除即时拦截域名: {host}")

    # ============ 心跳与状态 ============
    def heartbeat(self) -> float:
        """心跳：返回自上次浏览器活动以来的秒数。供 AntiTamper 检测沙盒存活。"""
        now = time.time()
        with self._state_lock:
            if self._last_heartbeat == 0:
                return float("inf")
            age = now - self._last_heartbeat
            self._last_heartbeat = now
            return age

    @property
    def is_running(self) -> bool:
        # 线程存活即视为运行中：CDP 连接模式下浏览器可能尚未打开（等待连接阶段），
        # 线程存活即可
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_error(self) -> Optional[str]:
        return self._start_error

    def intercept_count(self) -> int:
        with self._rules_lock:
            return len(self._intercept_rules)

    # ============ 线程安全调用器 ============
    def _call(self, coro, timeout: float = None):
        """在沙盒事件循环线程中执行协程并同步等待结果（线程安全）。
        超时从 time_settings.sandbox_call_timeout 读取（默认 30 秒）。"""
        if timeout is None:
            timeout = float(self.config.get("time_settings.sandbox_call_timeout", 30))
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
    def start(self, wait_timeout: float = None) -> bool:
        """启动沙盒（后台线程运行浏览器），等待初始化完成。
        等待超时从 time_settings.sandbox_start_timeout 读取（默认 60 秒）。"""
        if wait_timeout is None:
            wait_timeout = float(self.config.get("time_settings.sandbox_start_timeout", 60))
        if not self.available:
            self.logger.warning(f"[Sandbox] 不可用：{self._start_error}")
            return False
        if self.is_running:
            return True
        if self._thread is not None and self._thread.is_alive():
            self.logger.debug("[Sandbox] 启动中...")
            return self._started.wait(timeout=wait_timeout) and self._start_error is None

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
            # ========== CDP 连接模式：接管外部浏览器（系统不自动打开浏览器）==========
            await self._run_connect_mode()
        else:
            # 未配置 CDP 连接地址：不自动打开浏览器，仅记录错误等待配置修复
            self._start_error = "未配置 browser_sandbox.connect_cdp_url，浏览器沙盒未接管任何浏览器"
            self.logger.error(f"[Sandbox] {self._start_error}")
            self._started.set()
            while not self._stop.is_set():
                await asyncio.sleep(1)

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
        # 提示频率从 time_settings 读取
        notify_every = int(self.config.get("time_settings.cdp_retry_notify_every", 10))
        retry_interval = float(self.config.get("time_settings.cdp_retry_interval", 1))
        while not self._stop.is_set():
            with self._state_lock:
                self._last_heartbeat = time.time()
            if self._browser is None:
                # 首次连接：外部浏览器可能尚未打开，自动重试等待（系统不自动打开浏览器）
                try:
                    self._browser = await self._playwright.chromium.connect_over_cdp(
                        self._connect_cdp_url
                    )
                    self.logger.info("[Sandbox] 已连接外部浏览器（CDP），正在接管页面...")
                    await self._attach_cdp_contexts()
                    retry_count = 0
                except Exception as e:
                    # 每 notify_every 次提示一次，避免静默无输出
                    retry_count += 1
                    if retry_count % max(notify_every, 1) == 1:
                        self.logger.warning(
                            f"[Sandbox] 正在等待调试浏览器连接（{self._connect_cdp_url}）..."
                        )
                        self.logger.warning(
                            "[Sandbox] 若一直连不上，请通过『AOTE CDP Debug Browser』"
                            "快捷方式手动打开浏览器。"
                        )
                    self.logger.debug(f"[Sandbox] 等待外部浏览器连接: {e}")
            else:
                # 已连接：检测断线并自动重连
                try:
                    if not self._browser.is_connected():
                        self.logger.warning("[Sandbox] 外部浏览器连接断开，尝试重连...")
                        await self._try_reconnect_cdp()
                except Exception:
                    await self._try_reconnect_cdp()
            await asyncio.sleep(max(retry_interval, 0.1))
        await self._cleanup()

    # ============ 全入口接管：浏览器进程监控 ============
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
            # 扫描间隔从 time_settings.browser_monitor_interval 读取（秒）
            scan_interval = float(self.config.get("time_settings.browser_monitor_interval", 3))
            await asyncio.sleep(max(scan_interval, 0.5))

    def _has_always_on_topic_rule(self) -> bool:
        """是否存在"始终生效"（不局限于非上课时段）的主题限制规则。"""
        return any(not b.get("strict_mode_only", False) for b in self._topic_blocks)

    def _takeover_allowed_now(self) -> bool:
        """当前是否允许对未受管浏览器执行接管（终止 + 以受管参数重启）。

        默认仅在非上课时段（严格模式）接管，避免打断正常教学；但当配置了
        "始终生效"的主题限制规则（strict_mode_only=false）时必须保持接管——
        否则这类规则在上课时段会完全失效：既没有路由拦截，也没有检测脚本注入，
        形成"规则配了却拦截不了"的假象。
        """
        if not self._takeover_only_in_strict:
            return True
        # 豁免时间段：连"终止未受管浏览器"这类约束也一并暂停，
        # 否则会出现"规则都停了、浏览器却还在被强制接管"的矛盾现象。
        if self.is_exempt():
            if self._takeover_state_last:
                self._takeover_state_last = False
                self.logger.info("[Sandbox] 浏览器进程接管: 暂停（豁免时间段）")
            return False
        if self._has_always_on_topic_rule():
            # 主题限制要求始终生效 -> 任何时段都保持接管
            allowed = True
        else:
            with self._state_lock:
                if self._is_unlocked_locked():
                    allowed = False
                else:
                    allowed = self._control_mode == MODE_STRICT
        # 仅在状态翻转时记一条日志：既便于诊断，又避免每轮扫描刷屏
        if allowed != self._takeover_state_last:
            self._takeover_state_last = allowed
            self.logger.info(
                f"[Sandbox] 浏览器进程接管: "
                f"{'启用（非上课时段）' if allowed else '暂停（上课/解锁时段，不终止浏览器）'}"
            )
        return allowed

    def _scan_and_kill_unmanaged_browsers(self) -> None:
        """扫描并终止未接管浏览器进程（在后台线程中运行）。

        受管判定不能只看命令行参数：快捷方式若缺少 --user-data-dir，带调试参数的
        启动会被已运行的默认 profile 实例吞掉（进程转发后退出），表现为"命令行有
        --remote-debugging-port，但端口其实没监听"。仅凭参数判定会把这类实例当成
        受管放过去，导致 CDP 永远连不上、管控静默失效。

        因此这里对主进程额外做一次端口连通性探测，把上述情况识别为"假受管"，
        与完全不带调试参数的"未受管"一并终止，再由兜底逻辑以完整受管参数重启。

        上课时段（宽松模式）/解锁状态下整体跳过：此时不拦截任何内容，终止浏览器
        只会打断正常教学使用（判定见 _takeover_allowed_now）。
        """
        # 0) 上课/解锁时段不接管：连进程扫描一并跳过，省去无谓的进程查询开销
        if not self._takeover_allowed_now():
            return
        # 1) 快速检测是否存在浏览器进程（无则直接返回，避免频繁调用 PowerShell）
        tasklist_timeout = float(self.config.get("time_settings.tasklist_timeout", 5))
        try:
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=tasklist_timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return
        text = (r.stdout or "").lower()
        if not any(name in text for name in self._BROWSER_PROCESS_NAMES):
            return
        # 2) 通过 PowerShell 获取各浏览器进程的命令行与可执行文件路径
        #    （用制表符分隔，避免命令行中的分号造成解析歧义）
        #    WQL 使用 SQL 风格的 OR（不是 PowerShell 的 -or），否则 Get-CimInstance
        #    报"无效查询"导致 watchdog 静默失效、管控从未真正接管浏览器。
        #    同时强制 UTF-8 输出，避免命令行含非 ASCII 字符时解码损坏。
        filter_expr = " OR ".join(f"Name = '{n}'" for n in self._BROWSER_PROCESS_NAMES)
        ps_cmd = (
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            "Get-CimInstance Win32_Process -Filter \"" + filter_expr + "\""
            " | ForEach-Object { $p = Get-Process -Id $_.ProcessId "
            "-ErrorAction SilentlyContinue; $age = if ($p) { [int]((Get-Date) "
            "- $p.StartTime).TotalSeconds } else { -1 };"
            " \"{0}`t{1}`t{2}`t{3}`t{4}\" -f $_.ProcessId,"
            " $_.CommandLine, $_.ExecutablePath, $_.ParentProcessId, $age }"
        )
        try:
            ps_timeout = float(self.config.get("time_settings.powershell_timeout", 15))
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=ps_timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as e:
            self.logger.warning(f"[Sandbox] 查询浏览器进程命令行失败: {e}")
            return
        if r.returncode != 0:
            # 查询本身出错（WQL 语句无效、权限不足等）必须与"查不到进程"严格区分：
            # 若混为一谈，watchdog 会静默失效、管控长期不生效且日志无任何线索。
            self._query_failures += 1
            self.logger.warning(
                f"[Sandbox] 浏览器进程查询失败 rc={r.returncode}"
                f"（连续 {self._query_failures} 次）: "
                f"{(r.stderr or '').strip()[:200]}"
            )
            return
        self._query_failures = 0
        # 3) 分类：真受管保留，未受管与"假受管"进入待终止列表
        # 附带 cmdline 与 parent_pid：仅凭 PID 无法判断链接是从任务栏、
        # App Paths 还是某个客户端拉起的，排查漏劫持入口必须看这两项
        pending_kill: List[tuple] = []   # [(pid, exe_path, reason, cmdline, parent_pid)]
        managed_exists = False
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            pid = parts[0].strip()
            cmdline = (parts[1] or "").strip()
            exe_path = (parts[2] or "").strip() if len(parts) > 2 else ""
            parent_pid = (parts[3] or "").strip() if len(parts) > 3 else ""
            age_sec = -1.0
            if len(parts) > 4:
                try:
                    age_sec = float(parts[4])
                except Exception:
                    age_sec = -1.0
            if not pid.isdigit():
                continue
            kind, reason = self._classify_browser_process(cmdline, age_sec)
            if kind == "managed":
                managed_exists = True
            else:
                pending_kill.append((pid, exe_path, reason, cmdline, parent_pid))

        # 4) 终止待接管进程（假受管的调试端口实际不可用，必须重启才能接管）
        killed: List[tuple] = []         # [(pid, exe_path)]
        taskkill_timeout = float(self.config.get("time_settings.taskkill_timeout", 10))
        for pid, exe_path, reason, cmdline, parent_pid in pending_kill:
            self.logger.warning(
                f"[Sandbox] 检测到未接管浏览器进程 PID={pid}（{reason}），"
                "立即终止并交由 AOTE 接管"
            )
            self.logger.info(
                f"[Sandbox]   未受管进程详情 PID={pid} 父进程={parent_pid or '未知'}"
                f"\n    命令行: {(cmdline or '')[:600]}"
                f"\n    可执行: {exe_path}"
            )
            try:
                subprocess.run(
                    ["taskkill", "/PID", pid, "/F"],
                    capture_output=True, timeout=taskkill_timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                killed.append((pid, exe_path))
            except Exception:
                pass
        # 5) 兜底接管：已无受管实例时，自动以受管参数重新拉起浏览器。
        #    带上被终止进程原本要打开的 URL：否则用户点的新闻/链接会随实例一起
        #    消失，重启后只剩一个空白页，表现为"点了链接什么都没打开"。
        start_url = ""
        for _pid, _exe, _reason, cmdline, _ppid in pending_kill:
            start_url = self._extract_start_url(cmdline)
            if start_url:
                break
        self._relaunch_managed_if_needed(killed, managed_exists, start_url)

    @staticmethod
    def _extract_start_url(cmdline: str) -> str:
        """从浏览器命令行提取用户要打开的 URL。

        需支持两种形态：
        - 直接的 http(s) 地址；
        - Edge 协议包裹：microsoft-edge:?url=<百分号编码>（Windows 搜索框、
          小组件/资讯等系统入口常用），必须先解码才能拿到真实链接。

        用于兜底重启时还原用户原本点击的链接；取不到时返回空串（打开默认页）。
        """
        if not cmdline:
            return ""
        m = re.search(r'microsoft-edge:\?url=([^\s"\']+)', cmdline)
        if m:
            try:
                return unquote(m.group(1))
            except Exception:
                return ""
        m = re.search(r'https?://[^\s"\']+', cmdline)
        return m.group(0) if m else ""

    def _relaunch_managed_if_needed(self, killed: List[tuple], managed_exists: bool,
                                    start_url: str = "") -> None:
        """终止未接管实例后，若系统内已无受管浏览器，则以受管参数重新拉起。

        killed 可包含两类来源：完全不带调试参数的"未受管"，以及带参数但端口未开
        的"假受管"。二者终止后若无任何真受管实例存活，统一以完整受管参数
        （调试端口 + 独立 profile）重启浏览器，确保端口真正监听、CDP 可连。
        """
        if not (self._auto_relaunch_managed and killed and not managed_exists):
            return
        if self._is_cdp_connected():
            self._relaunch_failures = 0
            return
        exe_path = next((p for _, p in killed if p), "")
        if not exe_path:
            self.logger.debug("[Sandbox] 未能获取被终止浏览器的路径，跳过自动接管重启")
            return
        cooldown = float(self.config.get("time_settings.browser_relaunch_cooldown", 10))
        # 连续失败时指数退避：浏览器拉不起来时避免高频重启刷屏并持续占用资源
        if self._relaunch_failures:
            cooldown = min(cooldown * (2 ** min(self._relaunch_failures, 4)), 300.0)
        if time.time() - self._last_relaunch_at < max(cooldown, 0.0):
            return
        self._last_relaunch_at = time.time()
        self.logger.info(
            "[Sandbox] 自动接管重启浏览器"
            + (f"，还原链接: {start_url}" if start_url else "（原进程无 URL）")
        )
        if self._launch_managed_browser(exe_path, start_url):
            self._relaunch_failures = 0
        else:
            self._relaunch_failures += 1
            self.logger.error(
                f"[Sandbox] 自动接管重启失败（连续 {self._relaunch_failures} 次），"
                f"将在 {cooldown:.0f}s 后重试"
            )

    # ============ 受管判定 / 兜底接管辅助 ============
    @staticmethod
    def _extract_debug_port(cmdline: str) -> Optional[int]:
        """从命令行提取 --remote-debugging-port 的端口号（不存在返回 None）。"""
        m = re.search(r"--remote-debugging-port[= ]+(\d+)", str(cmdline or ""), re.I)
        if not m:
            return None
        try:
            return int(m.group(1))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_port_listening(port: int, host: str = "127.0.0.1",
                           timeout: float = DEBUG_PORT_PROBE_TIMEOUT) -> bool:
        """探测调试端口是否真的在监听——CDP 可用性的最终判据。

        仅凭命令行参数判定会漏掉"参数在但端口没开"的情况（实例合并导致），
        因此这里实际建立一次 TCP 连接来确认。
        """
        if not port or port <= 0:
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False
        except Exception:
            return False

    @staticmethod
    def _is_browser_main_process(cmdline: str) -> bool:
        """判断是否为浏览器主进程：子进程（renderer/gpu/utility...）均带 --type=。"""
        return "--type=" not in str(cmdline or "").lower()

    def _classify_browser_process(self, cmdline: str, age_sec: float = -1.0) -> tuple:
        """判定单个浏览器进程的受管状态，返回 (kind, reason)。

        age_sec 为进程已存活秒数（<0 表示未知）：刚拉起的浏览器需要一段时间才会
        真正监听调试端口，在 STARTUP_PORT_GRACE_SEC 宽限期内不判为 fake，否则会把
        正常启动的实例杀掉，表现为"一点链接浏览器就闪退然后重启"。

        kind 取值：
          - "managed"  ：调试端口真实可用，或采用 --remote-debugging-pipe /
                         AOTE 独立 profile 等无法用端口探测的模式
          - "fake"     ：命令行带 --remote-debugging-port，但该端口并未监听
                         （典型场景：快捷方式缺 --user-data-dir，启动参数被已运行的
                         默认 profile 实例吞掉，进程转发后退出，端口从未开启）
          - "unmanaged"：完全不带调试参数

        端口探测仅对主进程执行：子进程会继承调试参数，但端口由主进程监听，
        逐个探测既无意义又增加开销。
        """
        port = self._extract_debug_port(cmdline)
        if port is not None:
            if self._is_browser_main_process(cmdline) and not self._is_port_listening(port):
                if 0 <= age_sec < STARTUP_PORT_GRACE_SEC:
                    return ("managed", "")
                return ("fake", f"带调试参数但端口 {port} 未监听")
            return ("managed", "")
        if self._is_managed_browser_cmdline(cmdline):
            return ("managed", "")
        return ("unmanaged", "无 CDP 调试参数")

    @staticmethod
    def _parse_cdp_port(connect_url: str, default: int = DEFAULT_CDP_PORT) -> int:
        """从 CDP 连接地址解析调试端口（http://127.0.0.1:9222 -> 9222）。"""
        try:
            parsed = urlparse(str(connect_url or ""))
            if parsed.port:
                return int(parsed.port)
            tail = (parsed.netloc or "").rsplit(":", 1)[-1]
            return int(tail) if str(tail).isdigit() else default
        except Exception:
            return default

    @staticmethod
    def _normalize_dir_path(p: str) -> str:
        """规范化目录路径用于比对：去引号、统一反斜杠、去尾部斜杠、转小写。"""
        s = str(p or "").strip()
        for _ in range(2):
            if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
                s = s[1:-1].strip()
        return s.replace("/", "\\").rstrip("\\").lower()

    def _is_managed_browser_cmdline(self, cmdline: str) -> bool:
        """判断浏览器命令行是否属于 AOTE 受管实例。

        不强制要求携带独立文件目录参数（--user-data-dir）：
        - 只要带任意远程调试开关（--remote-debugging-port[=任意值] /
          --remote-debugging-pipe），即视为受管；
        - 或使用了 AOTE 的独立 profile（与 user-data-dir 值规范化比对，
          兼容引号 / 正反斜杠 / 大小写 / 结尾斜杠差异）。
        """
        low = str(cmdline or "").lower()
        if "--remote-debugging-port" in low or "--remote-debugging-pipe" in low:
            return True
        # 使用 AOTE 独立 profile 启动的实例
        try:
            udd = self._normalize_dir_path(self._user_data_dir)
            if not udd:
                return False
            m = re.search(r'--user-data-dir[= ]+("[^"]*"|\'[^\']*\'|\S+)', low)
            if m:
                return self._normalize_dir_path(m.group(1)) == udd
        except Exception:
            pass
        return False

    def _is_cdp_connected(self) -> bool:
        """当前是否已通过 CDP 连接并接管浏览器。"""
        try:
            return bool(self._browser is not None and self._browser.is_connected())
        except Exception:
            return False

    def _launch_managed_browser(self, exe_path: str, url: str = "") -> bool:
        """以"受管方式"启动浏览器：调试端口 + 独立 profile。

        用于快捷方式缺少 --user-data-dir 等参数时的兜底接管。带上独立 profile
        可确保浏览器一定以新实例启动并真正监听调试端口（否则调试参数可能被
        已运行的默认 profile 实例吞掉，导致 CDP 永远连不上）。
        """
        if not exe_path or not os.path.isfile(exe_path):
            self.logger.warning(f"[Sandbox] 自动接管跳过：浏览器路径无效 {exe_path!r}")
            return False
        udd = str(self._user_data_dir)
        try:
            Path(udd).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.debug(f"[Sandbox] 创建独立 profile 目录失败: {e}")
        args = [
            exe_path,
            f"--remote-debugging-port={self._cdp_port}",
            f"--user-data-dir={udd}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-blink-features=AutomationControlled",
        ]
        if url:
            args.append(url)
        try:
            creationflags = 0
            creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
            creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creationflags,
            )
        except Exception as e:
            self.logger.error(f"[Sandbox] 自动拉起受管浏览器失败: {e}")
            return False
        self.logger.info(
            f"[Sandbox] 检测到未受管浏览器，已自动接管重启："
            f"端口 {self._cdp_port}，独立 profile {udd}"
        )
        return True

    # ============ 页面挂接 ============
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
        # 主题限制脚本：补充检测标题 / 元数据 / 正文（路由层看不到的维度）
        topic_script = self._topic_block_script()
        if topic_script:
            try:
                await ctx.add_init_script(topic_script)
            except Exception as e:
                self.logger.debug(f"[Sandbox] 主题限制脚本注入失败: {e}")
        ctx.on("page", self._on_new_page)
        for page in list(ctx.pages):
            self._attach_page_listeners(page)
            await self._inject_media_block(page)  # 已有页面手动注入一次
            # add_init_script 只对后续新建的页面生效；接管时已存在的页面
            # （例如用户早先打开的搜索结果页）必须手动注入一次，否则内容维度不设防
            if topic_script:
                try:
                    await page.evaluate(topic_script)
                except Exception as e:
                    self.logger.debug(f"[Sandbox] 主题限制脚本注入已有页面失败: {e}")
            # 兜底：接管时页面可能已停在应重定向的站点上
            await self._enforce_redirect_on_attach(page)

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
                self._sniffer = _NetworkSniffer(
                    self._cdp_session, self.logger, self._max_captured
                )
                await self._sniffer.start()
            except Exception as e:
                self.logger.debug(f"[Sandbox] CDP 初始化失败（可选功能）: {e}")

    def _on_new_page(self, page) -> None:
        """外部浏览器新开页面时：挂接响应捕获并记录访问日志。"""
        self._attach_page_listeners(page)
        # 新页面注入视频管控脚本（后台执行，不阻塞事件回调）
        self._submit(lambda: self._inject_media_block(page))
        # 兜底：页面创建时若已带 URL（外部程序拉起等），首个导航可能早于路由绑定
        self._submit(lambda: self._enforce_redirect_on_attach(page))
        try:
            self.logger.info(f"[Sandbox] 检测到新页面: {page.url or '(空白页)'}")
        except Exception:
            pass

    async def _enforce_redirect_on_attach(self, page) -> None:
        """页面接管兜底：补查当前 URL 是否命中重定向规则。

        少数入口（如外部程序一次性"创建页面并立即导航"）的首个请求可能早于
        路由绑定而绕过拦截，这里在 attach 时补一次，命中则立即跳转目标站。
        """
        try:
            url = page.url or ""
        except Exception:
            return
        if not url or url.startswith(("edge://", "chrome://", "about:", "devtools://", "data:")):
            return
        rule = self._match_rule(url)
        if rule is None or rule.status != 302:
            return
        target = (rule.headers or {}).get("Location")
        if not target or target == url:
            return
        try:
            await page.goto(target, timeout=8000)
            self.logger.info(f"[Sandbox] 页面接管兜底重定向: {url} -> {target}")
        except Exception as e:
            self.logger.debug(f"[Sandbox] 兜底重定向失败 {url}: {e}")

    def _attach_page_listeners(self, page) -> None:
        try:
            page.on("response", self._response_handler)
        except Exception:
            pass

    def _submit(self, coro_factory: Callable) -> None:
        """把协程投递到沙盒事件循环线程执行（不等待结果，失败静默）。

        传入协程工厂（callable）而非协程对象：事件循环不可用时不会创建协程，
        从而避免 "coroutine was never awaited" 警告。
        """
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            asyncio_run_coroutine_threadsafe(coro_factory(), loop)
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

    async def _cleanup(self) -> None:
        """浏览器统一清理。CDP 连接模式下仅断开连接，不关闭用户浏览器。"""
        if self._sniffer is not None:
            try:
                await self._sniffer.stop()
            except Exception:
                pass
        try:
            if self._browser is not None:
                # 外部浏览器由用户管理，只断开 CDP 连接（不 browser.close()）
                self.logger.info(
                    "[Sandbox] 外部浏览器由用户管理，仅断开 CDP 连接（未关闭浏览器）"
                )
        except Exception as e:
            self.logger.debug(f"[Sandbox] 关闭浏览器异常: {e}")
        self._browser = None
        self._context = None
        self._page = None
        self._cdp_session = None
        self._sniffer = None

    def stop(self, timeout: float = None) -> None:
        """请求关闭沙盒并等待浏览器清理完成（CDP 模式不关闭外部浏览器）。
        超时从 time_settings.sandbox_call_timeout 读取（默认 30 秒）。"""
        if timeout is None:
            timeout = float(self.config.get("time_settings.sandbox_call_timeout", 30))
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._thread:
            self.logger.info(
                "[Sandbox] 浏览器沙盒已停止（CDP 连接已断开，外部浏览器保持运行）"
            )

    def close(self) -> None:
        """别名：与 stop 相同语义，便于 Orchestrator 统一清理。"""
        self.stop()

    # ============ 路由拦截（route.fulfill / route.continue_） ============
    async def _route_handler(self, route) -> None:
        """每个请求的处理入口：伪造规则 -> 内容管控 -> 视频拦截 -> 弱网延迟 -> 放行。"""
        url = route.request.url
        # 0) 放行优先级最高：全局豁免白名单 / 豁免时间段，直接 continue。
        #    必须放在所有策略之前，才能同时绕开重定向规则、主题/游戏关键词、
        #    内容管控、视频拦截与弱网限速——否则任一层都会把请求拦下。
        #    （重定向规则在第 1 步就走 fulfill，不在这里拦就会漏。）
        if self._is_always_allowed(url) or self.is_exempt():
            await route.continue_()
            return
        rule = self._match_rule(url)
        try:
            # 1) 用户显式注册的伪造响应规则优先级最高
            if rule is not None:
                await self._fulfill_rule(route, url, rule)
                return
            # 2) 内容管控决策 + 弱网监控（每个请求都跑，命中黑名单即时切换弱网）
            decision = self._content_decision(url)
            weak_hit = await self._handle_weak_network(url, self._request_page(route))
            if decision["action"] == "block":
                await self._fulfill_blocked(route, url, decision["reason"], decision["page"])
                return
            # 3) 严格模式：网络层拦截视频资源，杜绝漏网
            if self._media_block_enabled() and self._is_media_request(route, url):
                await self._fulfill_video_blocked(route, url)
                return
            # 4) 主题限制 - 主文档响应体检测：
            #    URL 层拦不住"URL 干净但内容违规"的页面（如百科词条、站内文章），
            #    这里在页面渲染前拉取响应体检查，命中即阻断，比页面内 JS 更早也更可靠。
            if self._should_check_response_body(route):
                try:
                    resp = await route.fetch()
                    body = await resp.text()
                    # 顺序：标题正则 -> 主题 -> 游戏关键词。
                    # 标题是"页面自称是什么"，比正文关键字更精确且更便宜，
                    # 命中时优先采用，日志 reason 才能指向真正的判定依据。
                    hit = (self._match_title_regex(body)
                           or self._match_topic_content(body)
                           or self._match_game_in_text(body))
                    if hit:
                        if hit[0] == GAME_KEYWORD_RULE_NAME:
                            prefix = "game_keyword"
                        elif any(hit[0] == n for n, _, _ in self._title_regex_rules):
                            prefix = TITLE_REGEX_RULE_PREFIX
                        else:
                            prefix = "topic_block"
                        await self._fulfill_blocked(
                            route, url, f"{prefix}:{hit[0]}:{hit[1]}",
                            self._blocked_page_html)
                        return
                    await route.fulfill(response=resp)
                    return
                except Exception as e:
                    self.logger.debug(f"[Sandbox] 响应体主题检测失败 {url}: {e}")
            # 5) 命中黑名单的请求附加请求级延迟（仅影响该请求，不影响其他站点）
            if weak_hit and self._weak_network_delay_ms > 0:
                await asyncio.sleep(self._weak_network_delay_ms / 1000.0)
            await route.continue_()
        except Exception as e:
            self.logger.debug(f"[Sandbox] 路由处理异常 {url}: {e}")
            try:
                await route.continue_()
            except Exception:
                pass

    @staticmethod
    def _request_page(route):
        """取请求所属页面（用于 per-page 弱网限速），失败返回 None。"""
        try:
            return route.request.frame.page
        except Exception:
            return None

    async def _fulfill_rule(self, route, url: str, rule: InterceptRule) -> None:
        body = rule.body
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.logger.debug(f"[Sandbox] 拦截 {url} -> status={rule.status}")
        await route.fulfill(status=rule.status, headers=rule.headers, body=body)

    async def _fulfill_blocked(self, route, url: str, reason: str, html: str) -> None:
        """用管控拦截页响应（403），并通知违规回调。"""
        self.logger.info(f"[Sandbox] 内容管控拦截 {url} -> {reason}")
        self._notify_violation(url, reason)
        await route.fulfill(
            status=403,
            headers={"Content-Type": "text/html; charset=utf-8",
                     "X-AOTE-Blocked": reason},
            body=html.encode("utf-8"),
        )

    async def _fulfill_video_blocked(self, route, url: str) -> None:
        """空响应拦截视频资源（403）。"""
        self.logger.info(f"[Sandbox] 视频资源拦截 {url}")
        await route.fulfill(
            status=403,
            headers={"Content-Type": "text/plain; charset=utf-8",
                     "X-AOTE-Blocked": "video"},
            body=b"",
        )

    def _is_media_request(self, route, url: str) -> bool:
        """判断请求是否为视频资源（按资源类型或 URL 特征）。"""
        try:
            rtype = route.request.resource_type or ""
        except Exception:
            rtype = ""
        return rtype == "media" or self._is_video_url(url)

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
        if scheme in PASSTHROUGH_SCHEMES or host in PASSTHROUGH_HOSTS:
            return {"action": "allow", "reason": "", "page": ""}
        # 全局豁免白名单：早于时段/解锁/主题/黑白名单判断，任何策略都不拦截
        if self._is_always_allowed(url):
            return {"action": "allow", "reason": "", "page": ""}

        with self._state_lock:
            mode = self._control_mode
            unlocked = self._is_unlocked_locked()

        if unlocked:
            return {"action": "allow", "reason": "", "page": ""}

        # ① 主题限制：命中最优先拦截，不受时段与白名单豁免，确保禁令不被绕过。
        #    URL 维度覆盖直接链接、站内搜索、推荐跳转与外部引荐等入口。
        hit = self._match_topic_in_url(url) or self._match_game_in_url(url)
        if hit:
            return {"action": "block",
                    "reason": f"{'game_keyword' if hit[0] == GAME_KEYWORD_RULE_NAME else 'topic_block'}:{hit[0]}:{hit[1]}",
                    "page": self._blocked_page_html}

        if mode == MODE_STRICT:
            # ② 白名单域名优先于黑名单放行（学习/政务站点等）
            if self._domain_match(host, self._allowed_domains):
                return {"action": "allow", "reason": "", "page": ""}
            # ③ 域名黑名单拦截
            if self._domain_match(host, self._block_domains):
                return {"action": "block", "reason": "blocked_domain",
                        "page": self._blocked_page_html}

        # MODE_RELAXED 与其它：放行
        return {"action": "allow", "reason": "", "page": ""}

    # ============ 弱网管控（命中黑名单即时切换，不影响其他站点） ============
    async def _handle_weak_network(self, url: str, page=None) -> bool:
        """弱网检测：仅非上课时段（严格模式）生效。
        - 命中黑名单 -> 立即切换弱网（CDP 限速当前页面 + 返回 True 触发请求级延迟）
        - 非黑名单且弱网已超最短时长 -> 恢复网络
        返回 True 表示该请求命中黑名单，需要附加请求级延迟。
        上课时段（宽松模式）与解锁状态：弱网一律不生效。"""
        if not self._weak_network_enabled:
            return False
        host = self._host_of(url)
        if not host:
            return False
        with self._state_lock:
            mode = self._control_mode
            unlocked = self._is_unlocked_locked()
        # 上课时段（宽松模式）或解锁状态：不进行任何弱网限制
        if unlocked or mode != MODE_STRICT:
            return False

        if self._domain_match(host, self._block_domains):
            now = time.time()
            with self._state_lock:
                if not self._weak_network_active:
                    self._weak_network_active = True
                    self._weak_network_since = now
                    self._weak_network_host = host
                    should_apply = True
                else:
                    should_apply = False
            if should_apply:
                self.logger.warning(f"[Sandbox] 命中黑名单 -> 切换弱网: {host}")
                self.logger.log_weak_network(
                    "activate", host,
                    self._weak_network_latency_ms,
                    self._weak_network_download_kbps,
                    self._weak_network_upload_kbps)
                await self._apply_weak_network_cdp(True, page)
            return True

        # 未命中黑名单：弱网已超过最短持续时间则恢复（避免频繁抖动）
        now = time.time()
        with self._state_lock:
            active = self._weak_network_active
            expired = active and (now - self._weak_network_since) >= self._weak_network_min_duration
            if expired:
                self._weak_network_active = False
                self._weak_network_host = ""
        if expired:
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
                "latency": self._weak_network_latency_ms,
                "downloadThroughput": max(0, int(self._weak_network_download_kbps * 1024 / 8)),
                "uploadThroughput": max(0, int(self._weak_network_upload_kbps * 1024 / 8)),
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
        self._submit(lambda: self._apply_weak_network_cdp(active, page))

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
        if not self._video_block_enabled:
            return False
        with self._state_lock:
            if self._is_unlocked_locked():
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
        self._submit(lambda: self._apply_media_block_pages(enable))

    def _request_exempt_flag(self, active: bool) -> None:
        """线程安全地同步豁免标志（已打开页面 + 后续新文档），非阻塞。"""
        self._submit(lambda: self._apply_exempt_flag_pages(active))

    async def _apply_exempt_flag_pages(self, active: bool) -> None:
        """把豁免标志写入已接管页面，并重新注册 init script 供后续新文档使用。

        init script 会随每次豁免切换累积注册，因此脚本内做了幂等保护
        （只有首份安装监听器，后续副本只刷新 window.__AOTE_EXEMPT）。
        """
        js = ("(v) => { window.__AOTE_EXEMPT = v;"
              " if (window.__AOTE_RESCAN) window.__AOTE_RESCAN(); }")
        pages = []
        try:
            if self._context is not None:
                pages = list(self._context.pages)
        except Exception:
            pass
        for page in pages:
            try:
                await page.evaluate(js, active)
            except Exception:
                pass
        try:
            if self._context is not None:
                script = self._topic_block_script()
                if script:
                    await self._context.add_init_script(script)
        except Exception as e:
            self.logger.debug(f"[Sandbox] 豁免标志 init script 注册失败: {e}")

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

    # ============ 拦截规则管理 ============
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
        # 定长队列：超上限自动丢弃最旧记录
        with self._captured_lock:
            self._captured.append(entry)

        # 访问日志：主文档（页面导航）记 INFO，子资源记 DEBUG，便于调试
        try:
            resource_type = response.request.resource_type if response.request else ""
        except Exception:
            resource_type = ""
        if resource_type == "document":
            self.logger.info(f"[Sandbox] 访问页面 [{response.status}] {response.url}")
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
            "(k, v) => { localStorage.setItem(k, v); return localStorage.getItem(k); }",
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
