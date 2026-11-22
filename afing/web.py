"""Web dashboard + JSON API (chỉ dùng thư viện chuẩn)."""

import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import alias
from .db import Database
from .monitor import Monitor

INDEX_PATH = os.path.join(os.path.dirname(__file__), "static", "index.html")
MAC_PATH = re.compile(r"^/api/devices/((?:[0-9a-f]{2}:){5}[0-9a-f]{2})/name$")


def make_server(host: str, port: int, db: Database, monitor: Monitor) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "afing"

        def log_message(self, *args):  # không in log từng request
            pass

        def _send(self, code, body: bytes, ctype="application/json; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode())

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                with open(INDEX_PATH, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif path == "/api/state":
                self._json({
                    "now": int(time.time()),
                    "status": monitor.status,
                    "devices": [dict(d, alias_icon=alias.icon(d["alias"])) for d in db.devices()],
                    "events": [dict(e, alias_icon=alias.icon(e["alias"])) for e in db.events(50)],
                })
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            m = MAC_PATH.match(self.path)
            if not m:
                return self._json({"error": "not found"}, 404)
            # Bắt buộc JSON để trang web khác không thể gửi form ngầm tới dashboard (CSRF).
            if "application/json" not in self.headers.get("Content-Type", ""):
                return self._json({"error": "Content-Type phải là application/json"}, 415)
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length > 4096:
                    raise ValueError
                name = json.loads(self.rfile.read(length)).get("name") or ""
                if not isinstance(name, str):
                    raise ValueError
            except (ValueError, AttributeError):
                return self._json({"error": "dữ liệu không hợp lệ"}, 400)
            name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()[:80]
            if db.set_custom_name(m.group(1), name):
                self._json({"ok": True, "name": name})
            else:
                self._json({"error": "không tìm thấy thiết bị"}, 404)

    return ThreadingHTTPServer((host, port), Handler)
