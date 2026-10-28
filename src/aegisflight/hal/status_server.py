"""Read-only, loopback-only HTTP status endpoint for the inline IPS bridge (``aegis ips-bridge --status-port``).

``GET /status`` returns ``InlineIpsBridge.status()`` plus ``{"crossend": {"sent": n}}``. GET only; no write endpoints.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ALLOWED_ORIGINS = frozenset({
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:8000", "http://127.0.0.1:8000",
    "http://localhost:8008", "http://127.0.0.1:8008",
    "tauri://localhost", "http://tauri.localhost", "https://tauri.localhost",
})


class BridgeStatusServer:
    def __init__(self, bridge: Any, port: int = 0) -> None:
        self.bridge = bridge
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a: Any) -> None:  # silent
                pass

            def _cors(self) -> None:
                origin = self.headers.get("Origin")
                if origin in ALLOWED_ORIGINS:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")

            def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
                self.send_response(code)
                self._cors()
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/status":
                    self._send(404, b'{"error":"not found"}')
                    return
                try:
                    st = dict(outer.bridge.status())
                    st["crossend"] = {"sent": int(getattr(outer.bridge, "crossend_sent", 0))}
                    self._send(200, json.dumps(st).encode())
                except Exception:  # noqa: BLE001
                    self._send(500, b'{"error":"status unavailable"}')

            def _refuse(self) -> None:
                self.send_response(405)
                self.send_header("Allow", "GET")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse  # noqa: N815

        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="bridge-status", daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> BridgeStatusServer:
        self._thread.start()
        return self

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
