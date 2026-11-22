"""Gửi thông báo ra ngoài mạng khi có thiết bị mới, thiết bị rời mạng hoặc quay lại.

Hai kênh, đều chỉ cần máy chạy afing gọi HTTPS ra Internet (không mở cổng nào vào mạng nhà):
- Telegram: tin nhắn từ một bot do bạn tạo.
- ntfy:     thông báo đẩy qua app ntfy, không cần tài khoản.

Cấu hình nằm trong file notify.json cạnh database (chứa token - đừng chia sẻ file này).
"""

import json
import logging
import os
import secrets
import threading
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import alias

log = logging.getLogger("afing.notify")

TELEGRAM_API = "https://api.telegram.org"
NTFY_SERVER = "https://ntfy.sh"
DEFAULT_LEAVE_MINUTES = 5

TYPE_LABELS = {
    "router": "Router", "network": "Network device", "computer": "Computer", "mobile": "Phone",
    "tablet": "Tablet", "tv": "TV", "media": "Media player", "speaker": "Speaker",
    "printer": "Printer", "camera": "Camera", "console": "Game console", "nas": "NAS",
    "appliance": "Appliance", "vacuum": "Robot vacuum", "iot": "IoT device", "wearable": "Wearable",
}


# ---------- cấu hình ----------

def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(path: str, cfg: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


def channels(cfg: dict) -> List[str]:
    found = []
    tg = cfg.get("telegram") or {}
    if tg.get("token") and tg.get("chat_id"):
        found.append("telegram")
    if (cfg.get("ntfy") or {}).get("topic"):
        found.append("ntfy")
    return found


# ---------- gửi ----------

def _post(url: str, body: bytes, headers: Dict[str, str]) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


def _explain(error: Exception) -> str:
    """Mô tả lỗi mà KHÔNG kèm URL, vì URL của Telegram chứa token."""
    if isinstance(error, urllib.error.HTTPError):
        detail = error.read(300).decode("utf-8", "replace")
        return f"HTTP {error.code} {detail}".strip()
    if isinstance(error, urllib.error.URLError):
        return f"không kết nối được ({error.reason})"
    return type(error).__name__


def send(cfg: dict, text: str) -> List[Tuple[str, Optional[str]]]:
    """Gửi `text` qua mọi kênh đã cấu hình. Trả [(kênh, lỗi hoặc None)]."""
    results = []
    for channel in channels(cfg):
        try:
            if channel == "telegram":
                tg = cfg["telegram"]
                _post(f"{TELEGRAM_API}/bot{tg['token']}/sendMessage",
                      json.dumps({"chat_id": tg["chat_id"], "text": text,
                                  "disable_web_page_preview": True}).encode(),
                      {"Content-Type": "application/json"})
            else:
                nt = cfg["ntfy"]
                server = (nt.get("server") or NTFY_SERVER).rstrip("/")
                _post(f"{server}/{nt['topic']}", text.encode(),
                      {"Title": "afing", "Content-Type": "text/plain; charset=utf-8"})
            results.append((channel, None))
        except Exception as e:
            results.append((channel, _explain(e)))
    return results


def telegram_find_chat(token: str) -> Optional[Tuple[int, str]]:
    """Tìm cuộc trò chuyện gần nhất đã nhắn cho bot -> (chat_id, tên)."""
    with urllib.request.urlopen(f"{TELEGRAM_API}/bot{token}/getUpdates", timeout=10) as resp:
        updates = json.load(resp).get("result", [])
    for update in reversed(updates):
        chat = (update.get("message") or update.get("channel_post") or {}).get("chat")
        if chat and "id" in chat:
            name = chat.get("title") or " ".join(
                filter(None, (chat.get("first_name"), chat.get("last_name")))) or str(chat["id"])
            return chat["id"], name
    return None


# ---------- nội dung ----------

def describe_device(dev: dict) -> str:
    name = dev.get("custom_name") or dev.get("hostname")
    head = " ".join(filter(None, (alias.icon(dev.get("alias")), dev.get("alias"))))
    if name:
        head = f"{head} — {name}" if head else name
    kind = " · ".join(filter(None, (TYPE_LABELS.get(dev.get("device_type")), dev.get("os"))))
    if kind:
        head += f" ({kind})"
    detail = " · ".join(filter(None, (dev.get("ip"), dev.get("mac"), dev.get("vendor"))))
    return f"{head}\n{detail}"


class Notifier:
    """Biến các sự kiện của từng lượt quét thành thông báo.

    Thiết bị chập chờn (điện thoại ngủ, sóng yếu) không gây báo liên tục: chỉ báo "rời mạng" khi
    thiết bị vắng mặt liên tục `leave_after_minutes` phút, và chỉ báo "quay lại" cho thiết bị đã
    được báo rời mạng.
    """

    def __init__(self, config_path: str, devices: Callable[[], List[dict]],
                 sender: Callable[[dict, str], list] = send):
        self.config_path = config_path
        self._devices = devices
        self._sender = sender
        self._pending_leave: Dict[str, int] = {}  # mac -> thời điểm bắt đầu vắng mặt

    def active_channels(self) -> List[str]:
        return channels(load_config(self.config_path))

    def process(self, events: List[dict], now: int, network: str = "") -> List[str]:
        """Xử lý sự kiện của một lượt quét; trả các dòng thông báo đã gửi đi (để test)."""
        cfg = load_config(self.config_path)
        if not channels(cfg):
            self._pending_leave.clear()
            return []
        leave_after = float(cfg.get("leave_after_minutes", DEFAULT_LEAVE_MINUTES)) * 60
        devices = {d["mac"]: d for d in self._devices()}
        new = [e for e in events if e["type"] == "new"]

        lines = []
        if len(new) > 1 and len(new) == len(devices):
            # Lượt quét đầu tiên trên một database trống: gộp thành một tin thay vì báo từng máy.
            lines.append(f"✅ afing is now watching {network or 'your network'}: "
                         f"{len(new)} devices found.")
            new = []
        for ev in new:
            lines.append("🆕 New device\n" + describe_device(devices.get(ev["mac"], ev)))
        for ev in events:
            mac = ev["mac"]
            if ev["type"] == "offline":
                self._pending_leave[mac] = ev["ts"]
            elif ev["type"] == "online":
                if self._pending_leave.pop(mac, None) is None:
                    lines.append("🟢 Back online\n" + describe_device(devices.get(mac, ev)))
        for mac, since in list(self._pending_leave.items()):
            if now - since >= leave_after:
                del self._pending_leave[mac]
                dev = devices.get(mac)
                if dev and not dev["is_online"]:
                    lines.append("🔴 Left the network\n" + describe_device(dev))

        if lines:
            text = "\n\n".join(lines)
            threading.Thread(target=self._deliver, args=(cfg, text), daemon=True).start()
        return lines

    def _deliver(self, cfg: dict, text: str) -> None:
        for channel, error in self._sender(cfg, text):
            if error:
                log.warning("Không gửi được thông báo qua %s: %s", channel, error)


# ---------- cài đặt qua dòng lệnh ----------

def setup(config_path: str, ask: Callable[[str], str] = input, out: Callable[[str], None] = print) -> int:
    cfg = load_config(config_path)
    out("Nhận thông báo qua kênh nào?\n"
        "  1. Telegram (khuyên dùng)\n"
        "  2. ntfy (không cần tài khoản, cài app ntfy trên điện thoại)")
    choice = ask("Chọn 1 hoặc 2: ").strip()
    if choice == "1":
        out("\nTạo bot: trong Telegram, nhắn /newbot cho @BotFather và làm theo hướng dẫn. "
            "BotFather sẽ đưa một token dạng 123456:ABC-...")
        token = ask("Dán token của bot: ").strip()
        ask("Giờ mở bot vừa tạo trong Telegram, bấm Start (hoặc nhắn một chữ bất kỳ), "
            "rồi quay lại đây nhấn Enter...")
        try:
            chat = telegram_find_chat(token)
        except Exception as e:
            out(f"Lỗi: không hỏi được Telegram: {_explain(e)}. Kiểm tra lại token và kết nối mạng.")
            return 1
        if not chat:
            out("Lỗi: bot chưa nhận được tin nhắn nào. Hãy nhắn cho bot rồi chạy lại lệnh này.")
            return 1
        cfg["telegram"] = {"token": token, "chat_id": chat[0]}
        out(f"Sẽ gửi thông báo tới: {chat[1]}")
    elif choice == "2":
        topic = ((cfg.get("ntfy") or {}).get("topic")) or "afing-" + secrets.token_hex(8)
        cfg["ntfy"] = {"topic": topic}
        out(f"\nCài app ntfy trên điện thoại, bấm + và đăng ký (subscribe) chủ đề:\n\n    {topic}\n\n"
            "Ai biết tên chủ đề này đều đọc được thông báo, nên đừng chia sẻ nó.")
        ask("Đăng ký xong thì nhấn Enter để gửi tin thử...")
    else:
        out("Lỗi: lựa chọn không hợp lệ.")
        return 1
    save_config(config_path, cfg)
    out(f"Đã lưu cấu hình vào {config_path}")
    return test(config_path, out)


def test(config_path: str, out: Callable[[str], None] = print) -> int:
    cfg = load_config(config_path)
    if not channels(cfg):
        out("Chưa cấu hình kênh thông báo nào. Chạy lệnh notify-setup trước.")
        return 1
    failed = False
    for channel, error in send(cfg, "✅ afing test notification. Alerts are working."):
        out(f"  {channel}: " + (f"LỖI - {error}" if error else "đã gửi, hãy kiểm tra điện thoại"))
        failed = failed or bool(error)
    return 1 if failed else 0


def disable(config_path: str, out: Callable[[str], None] = print) -> int:
    if os.path.exists(config_path):
        os.remove(config_path)
    out("Đã tắt thông báo và xoá cấu hình.")
    return 0
