"""
AOTE 管控系统 - 本地HTTP服务（浏览器内容管控上报）
端点：
  GET  /ping    存活检查
  GET  /status  查询当前管控状态
  POST /kill    上报浏览器内违禁内容（触发数学挑战 / 记录拦截）
监听 127.0.0.1:8765，仅接受本地连接
"""
import threading
import time
import json
from typing import Optional, Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import ConfigManager
from .logger import AOTELogger
from .browser_sandbox import BrowserSandbox


class AOTEHTTPHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器"""
    server_config: Optional[ConfigManager] = None
    server_logger: Optional[AOTELogger] = None
    server_browser_sandbox: Optional[BrowserSandbox] = None
    # 违禁内容上报回调 on_violation(url, reason, level)
    server_on_violation: Optional[Callable[[str, str, int], None]] = None

    def log_message(self, format, *args):
        """屏蔽默认的stderr日志，改用我们的"""
        if self.server_logger:
            self.server_logger.debug(f"[HTTP] {format % args}")

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_local_only(self) -> bool:
        """确保只接受本地连接"""
        try:
            client_ip = self.client_address[0]
            if client_ip not in ("127.0.0.1", "::1"):
                self._send_json(403, {"error": "local_only"})
                return False
        except Exception:
            try:
                self._send_json(403, {"error": "local_only"})
            except Exception:
                pass
            return False
        return True

    def do_GET(self):
        if not self._check_local_only():
            return
        if self.path.startswith("/ping"):
            self._send_json(200, {"alive": True, "timestamp": int(time.time())})
        elif self.path.startswith("/status"):
            # 调试：查询当前状态
            mode = "unknown"
            unlocked = False
            sandbox_running = False
            try:
                sb = self.server_browser_sandbox
                if sb is not None:
                    sandbox_running = sb.is_running
                    if sandbox_running:
                        mode = sb.current_mode()
                        unlocked = sb.is_unlocked()
            except Exception:
                pass
            self._send_json(200, {
                "mode": mode,
                "unlocked": unlocked,
                "sandbox_running": sandbox_running,
            })
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if not self._check_local_only():
            return

        if self.path.startswith("/kill"):
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length > 0 else b"{}"
                payload = json.loads(raw.decode("utf-8"))

                url = payload.get("url", "")
                reason = payload.get("reason", "")
                level = payload.get("level", 1)

                if self.server_logger:
                    self.server_logger.log_browser_intercept(url, reason, "report")

                # 浏览器内容管控：交由 Orchestrator 处理（触发数学挑战等）
                if self.server_on_violation:
                    try:
                        self.server_on_violation(url, reason, level)
                    except Exception as e:
                        if self.server_logger:
                            self.server_logger.error(f"[HTTP] 违规回调异常: {e}")

                # 附加：若沙盒运行中，直接阻止该域名（添加到实时拦截清单）
                blocked_now = False
                if self.server_browser_sandbox is not None:
                    try:
                        self.server_browser_sandbox.block_url_now(url)
                        blocked_now = True
                    except Exception as e:
                        if self.server_logger:
                            self.server_logger.debug(f"[HTTP] 沙盒即时拦截失败: {e}")

                self._send_json(200, {"status": "ok", "blocked_now": blocked_now})
            except Exception as e:
                if self.server_logger:
                    self.server_logger.error(f"[HTTP] /kill 异常: {e}")
                self._send_json(500, {"status": "error", "message": str(e)})
        else:
            self._send_json(404, {"error": "not_found"})


class AOTEHTTPServer:
    """封装的HTTP服务"""

    def __init__(self, config: ConfigManager, logger: AOTELogger,
                 browser_sandbox: BrowserSandbox):
        self.config = config
        self.logger = logger
        self.browser_sandbox = browser_sandbox

        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        # 违规上报回调（由主程序注入：触发数学挑战等）
        self._on_violation: Optional[Callable[[str, str, int], None]] = None

    def set_on_violation(self, cb: Callable[[str, str, int], None]):
        self._on_violation = cb

    def start(self):
        host = self.config.get("http_server.host", "127.0.0.1")
        port = int(self.config.get("http_server.port", 8765))

        # 注入类属性
        AOTEHTTPHandler.server_config = self.config
        AOTEHTTPHandler.server_logger = self.logger
        AOTEHTTPHandler.server_browser_sandbox = self.browser_sandbox
        AOTEHTTPHandler.server_on_violation = self._on_violation

        try:
            self._server = ThreadingHTTPServer((host, port), AOTEHTTPHandler)
            self._server.daemon_threads = True
        except Exception as e:
            self.logger.error(f"[HTTP] 启动失败: {e}")
            return

        def _run():
            self.logger.info(f"[HTTP] 本地服务已启动: http://{host}:{port}")
            try:
                self._server.serve_forever(poll_interval=1)
            except Exception as e:
                if not self._stop.is_set():
                    self.logger.error(f"[HTTP] 服务异常: {e}")

        self._thread = threading.Thread(target=_run, daemon=True, name="AOTEHttpServer")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass
            try:
                self._server.server_close()
            except Exception:
                pass
        self.logger.info("[HTTP] 本地服务已停止")
