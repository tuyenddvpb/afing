"""Web dashboard + JSON API (chỉ dùng thư viện chuẩn)."""

import base64
import csv
import hmac
import io
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from . import alias, config, notify
from .classify import TYPES
from .db import Database
from .monitor import Monitor

INDEX_PATH = os.path.join(os.path.dirname(__file__), "static", "index.html")
MAC = r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2})"
DEVICE_PATH = re.compile(rf"^/api/devices/{MAC}(?:/(name|delete|merge))?$")
SECRET_KEYS = {("notify", "telegram_token"), ("web", "password")}
MASK = "•"
HISTORY_DAYS = 14


def clean(text, limit: int = 80) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "", str(text or "")).strip()[:limit]


def mask(section: str, key: str, value) -> str:
    """Không gửi token/mật khẩu ra trình duyệt: chỉ cho biết đã đặt và 4 ký tự cuối của token."""
    value = str(value or "")
    if (section, key) not in SECRET_KEYS or not value:
        return value
    return MASK * 6 + (value[-4:] if key == "telegram_token" and len(value) > 8 else "")


def make_server(host: str, port: int, db: Database, monitor: Monitor,
                config_path: Optional[str] = None,
                log_path: Optional[str] = None) -> ThreadingHTTPServer:
    def settings():
        return config.load(config_path) if config_path else None

    class Handler(BaseHTTPRequestHandler):
        server_version = "afing"

        def log_message(self, *args):  # không in log từng request
            pass

        # ---------- trả lời ----------

        def _send(self, code, body: bytes, ctype="application/json; charset=utf-8", extra=()):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode())

        def _csv(self, filename: str, header, rows):
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(header)
            writer.writerows(rows)
            # BOM để Excel mở đúng tiếng Việt
            self._send(200, out.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                       [("Content-Disposition", f'attachment; filename="{filename}"')])

        # ---------- quyền ----------

        def _password(self) -> str:
            try:
                cfg = settings()
            except config.ConfigError:
                return ""
            return cfg[("web", "password")] if cfg else ""

        def _authorized(self) -> bool:
            """Đã đặt mật khẩu thì mọi request phải kèm HTTP Basic đúng mật khẩu (tên gì cũng được)."""
            password = self._password()
            if not password:
                return True
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic "):
                try:
                    given = base64.b64decode(header[6:]).decode("utf-8", "replace").partition(":")[2]
                except ValueError:
                    given = ""
                if hmac.compare_digest(given.encode(), password.encode()):
                    return True
            self._send(401, b'{"error": "password required"}',
                       extra=[("WWW-Authenticate", 'Basic realm="afing", charset="UTF-8"')])
            return False

        def _can_admin(self) -> bool:
            """Xem/sửa cấu hình (có token) chỉ cho máy đang chạy afing, hoặc khi đã đặt mật khẩu."""
            local = self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
            return bool(config_path) and (local or bool(self._password()))

        # ---------- GET ----------

        def do_GET(self):
            if not self._authorized():
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                with open(INDEX_PATH, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/api/state":
                try:
                    cfg = settings()
                    language = cfg[("web", "language")] if cfg else "en"
                except config.ConfigError:
                    language = "en"
                return self._json({
                    "now": int(time.time()),
                    "status": monitor.status,
                    "language": language,
                    "muted_until": int(float(db.get_state("mute_until", "0") or 0)),
                    "can_admin": self._can_admin(),
                    "devices": [dict(d, alias_icon=alias.icon(d["alias"])) for d in db.devices()],
                    "events": [dict(e, alias_icon=alias.icon(e["alias"])) for e in db.events(50)],
                })
            m = DEVICE_PATH.match(path)
            if m and not m.group(2):
                dev = db.device(m.group(1))
                if not dev:
                    return self._json({"error": "not found"}, 404)
                now = int(time.time())
                since = now - HISTORY_DAYS * 86400
                return self._json({
                    "now": now,
                    "device": dict(dev, alias_icon=alias.icon(dev["alias"])),
                    "events": db.device_events(dev["mac"], 100),
                    "sessions": db.sessions(dev["mac"], since, now),
                    "history_since": since,
                    "dhcp": db.dhcp_clients().get(dev["mac"]),
                })
            if path == "/api/export/devices.csv":
                cols = ["alias", "custom_name", "hostname", "device_type", "custom_type", "os", "ip",
                        "mac", "vendor", "model", "person", "known", "is_online", "first_seen",
                        "last_seen", "notes"]
                stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
                rows = [[stamp(d[c]) if c in ("first_seen", "last_seen") else
                         ("" if d[c] is None else d[c]) for c in cols] for d in db.devices()]
                return self._csv("afing-devices.csv", cols, rows)
            if path == "/api/export/events.csv":
                rows = [[time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])), e["type"],
                         e["alias"] or "", e["name"] or "", e["mac"], e["ip"] or "", e["detail"] or ""]
                        for e in db.all_events()]
                return self._csv("afing-events.csv",
                                 ["time", "event", "alias", "name", "mac", "ip", "detail"], rows)
            if path == "/api/config":
                if not self._can_admin():
                    return self._json({"error": "forbidden"}, 403)
                try:
                    cfg = settings()
                except config.ConfigError as e:
                    return self._json({"error": str(e), "path": config_path}, 200)
                values = {}
                for (section, key), value in cfg.values.items():
                    if isinstance(value, bool):
                        value = "yes" if value else "no"
                    elif key == "times":
                        value = ", ".join(f"{h:02d}:{m:02d}" for h, m in value)
                    elif key == "quiet_hours":
                        value = "" if not value else "{:02d}:{:02d}-{:02d}:{:02d}".format(
                            value[0] // 60, value[0] % 60, value[1] // 60, value[1] % 60)
                    elif isinstance(value, float):
                        value = f"{value:g}"
                    values.setdefault(section, {})[key] = mask(section, key, value)
                return self._json({"path": config_path, "values": values,
                                   "kinds": {f"{s}.{k}": v for (s, k), v in config.KINDS.items()}})
            if path == "/api/log":
                if not self._can_admin():
                    return self._json({"error": "forbidden"}, 403)
                lines = []
                if log_path and os.path.exists(log_path):
                    with open(log_path, encoding="utf-8", errors="replace") as f:
                        lines = f.read().splitlines()[-200:]
                return self._json({"path": log_path, "lines": lines})
            self._json({"error": "not found"}, 404)

        # ---------- POST ----------

        def _body(self) -> Optional[dict]:
            # Bắt buộc JSON để trang web khác không thể gửi form ngầm tới dashboard (CSRF).
            if "application/json" not in self.headers.get("Content-Type", ""):
                self._json({"error": "Content-Type phải là application/json"}, 415)
                return None
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length > 16384:
                    raise ValueError
                data = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(data, dict):
                    raise ValueError
                return data
            except ValueError:
                self._json({"error": "dữ liệu không hợp lệ"}, 400)
                return None

        def do_POST(self):
            if not self._authorized():
                return
            path = self.path.split("?")[0]
            data = self._body()
            if data is None:
                return
            m = DEVICE_PATH.match(path)
            if m:
                return self._device_action(m.group(1), m.group(2), data)
            if path == "/api/devices/known-all":
                return self._json({"ok": True, "count": db.mark_all_known()})
            if path == "/api/mute":
                try:
                    minutes = float(data.get("minutes", 0))
                except (TypeError, ValueError):
                    return self._json({"error": "minutes phải là số"}, 400)
                until = int(time.time() + minutes * 60) if minutes > 0 else 0
                db.set_state("mute_until", str(until))
                return self._json({"ok": True, "muted_until": until})
            if path in ("/api/config", "/api/notify-test"):
                if not self._can_admin():
                    return self._json({"error": "forbidden"}, 403)
                if path == "/api/notify-test":
                    cfg = notify.load_config(config_path)
                    if not notify.channels(cfg):
                        return self._json({"ok": False, "error": "no channel configured"})
                    lang = notify.rules(config_path)["language"]
                    results = notify.send(cfg, notify.i18n.t(lang, "test"))
                    return self._json({"ok": all(not e for _, e in results),
                                       "results": [{"channel": c, "error": e} for c, e in results]})
                return self._set_config(data)
            self._json({"error": "not found"}, 404)

        def _device_action(self, mac: str, action: Optional[str], data: dict):
            if action == "delete":
                ok = db.delete_device(mac)
            elif action == "merge":
                into = str(data.get("into", "")).lower()
                if not re.fullmatch(MAC, into):
                    return self._json({"error": "thiếu thiết bị đích"}, 400)
                ok = db.merge_devices(mac, into)
            else:
                if action == "name":  # đường dẫn cũ: {"name": ...}
                    data = {"custom_name": data.get("name")}
                fields = {}
                for key, limit in (("custom_name", 80), ("person", 40), ("notes", 500)):
                    if key in data:
                        if data[key] is not None and not isinstance(data[key], str):
                            return self._json({"error": f"{key} phải là chuỗi"}, 400)
                        fields[key] = clean(data[key], limit)
                if "custom_type" in data:
                    if data["custom_type"] not in ("", None) and data["custom_type"] not in TYPES:
                        return self._json({"error": "loại thiết bị không hợp lệ"}, 400)
                    fields["custom_type"] = data["custom_type"] or ""
                if "alert" in data:
                    if data["alert"] not in ("", None, "always", "never"):
                        return self._json({"error": "alert không hợp lệ"}, 400)
                    fields["alert"] = data["alert"] or ""
                if "known" in data:
                    fields["known"] = bool(data["known"])
                ok = db.update_device(mac, fields)
                if ok and action == "name":
                    return self._json({"ok": True, "name": fields["custom_name"]})
            if ok:
                self._json({"ok": True})
            else:
                self._json({"error": "không tìm thấy thiết bị"}, 404)

        def _set_config(self, data: dict):
            section, key = str(data.get("section", "")), str(data.get("key", ""))
            value = clean(data.get("value"), 300)
            if (section, key) not in config.KINDS:
                return self._json({"error": "thiết lập không tồn tại"}, 400)
            if (section, key) in SECRET_KEYS and value.startswith(MASK):
                return self._json({"ok": True, "unchanged": True})  # ô còn nguyên giá trị che
            try:
                config._convert(section, key, value, os.path.basename(config_path))
            except config.ConfigError as e:
                return self._json({"error": str(e)}, 400)
            config.set_values(config_path, section, {key: value})
            self._json({"ok": True})

    return ThreadingHTTPServer((host, port), Handler)
