"""
AOTE 管控系统 - 本地HTTP服务（浏览器扩展通信）
端点：
  GET  /ping   扩展心跳
  POST /kill   上报违禁内容（触发冻结）
监听 127.0.0.1:8765，仅接受本地连接
"""
import threading
import time
import json
from typing import Optional
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import ConfigManager
from .logger import AOTELogger
from .anti_tamper import AntiTamper
from .process_hunter import ProcessHunter


class AOTEHTTPHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器"""
    server_config: Optional[ConfigManager] = None
    server_logger: Optional[AOTELogger] = None
    server_anti_tamper: Optional[AntiTamper] = None
    server_process_hunter: Optional[ProcessHunter] = None

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
            # 注意：TCP socket 的 client_address[0] 一定是 IP 字符串，永远不会是 "localhost"（DNS层概念），
            # 所以只检查 127.0.0.1 / ::1 即可。
            if client_ip not in ("127.0.0.1", "::1"):
                self._send_json(403, {"error": "local_only"})
                return False
        except Exception:
            # 拿不到客户端地址时保守起见：拒绝
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
            # 心跳
            if self.server_anti_tamper:
                self.server_anti_tamper.report_extension_heartbeat()
            self._send_json(200, {"alive": True, "timestamp": int(time.time())})
        elif self.path.startswith("/status"):
            # 调试：查询当前状态
            mode = "unknown"
            unlocked = False
            try:
                from .time_guard import TimeGuard
                tg = self.server_process_hunter.time_guard if self.server_process_hunter else None
                if tg:
                    mode = tg.current_mode
                if self.server_process_hunter:
                    unlocked = self.server_process_hunter.is_unlocked
            except Exception:
                pass
            self._send_json(200, {"mode": mode, "unlocked": unlocked})
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
                    self.server_logger.warning(
                        f"[扩展拦截] 违禁内容: {url} 原因: {reason} (level={level})"
                    )

                frozen_pids = []
                if self.server_process_hunter:
                    # 检查是否允许冻结（解锁时不冻结）
                    if not self.server_process_hunter.is_unlocked:
                        # 只冻结浏览器（遵循正常冻结流程：进程树遍历+已冻结检查）
                        import psutil
                        browsers = self.server_config.get("target_processes.browsers", [])
                        browsers_set = {b.lower() for b in browsers}
                        for p in psutil.process_iter(["pid", "name"]):
                            try:
                                if p.name().lower() in browsers_set:
                                    # 使用公有冻结流程：进程树展开
                                    proctree = self.server_process_hunter._get_process_tree(p)
                                    for tp in proctree:
                                        # _freeze_process 内部有已冻结检查，可安全调用
                                        self.server_process_hunter._freeze_process(tp)
                                        frozen_pids.append(tp.pid)
                            except Exception:
                                pass

                self._send_json(200, {"status": "ok", "frozen": frozen_pids})
            except Exception as e:
                if self.server_logger:
                    self.server_logger.error(f"[HTTP] /kill 异常: {e}")
                self._send_json(500, {"status": "error", "message": str(e)})
        else:
            self._send_json(404, {"error": "not_found"})


class AOTEHTTPServer:
    """封装的HTTP服务"""

    def __init__(self, config: ConfigManager, logger: AOTELogger,
                 anti_tamper: AntiTamper, process_hunter: ProcessHunter):
        self.config = config
        self.logger = logger
        self.anti_tamper = anti_tamper
        self.process_hunter = process_hunter

        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self):
        host = self.config.get("http_server.host", "127.0.0.1")
        port = int(self.config.get("http_server.port", 8765))

        # 注入类属性
        AOTEHTTPHandler.server_config = self.config
        AOTEHTTPHandler.server_logger = self.logger
        AOTEHTTPHandler.server_anti_tamper = self.anti_tamper
        AOTEHTTPHandler.server_process_hunter = self.process_hunter

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
