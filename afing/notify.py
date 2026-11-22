"""Gửi thông báo ra ngoài mạng khi có thiết bị mới, thiết bị rời mạng hoặc quay lại.

Hai kênh, đều chỉ cần máy chạy afing gọi HTTPS ra Internet (không mở cổng nào vào mạng nhà):
- Telegram: tin nhắn từ một bot do bạn tạo.
- ntfy:     thông báo đẩy qua app ntfy, không cần tài khoản.

Cấu hình nằm trong mục [notify] của afing.cfg (chứa token - đừng chia sẻ file này).
"""

import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import alias, config, i18n

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
    """Đọc mục [notify] của afing.cfg thành dict; chỉ chứa những gì đã được cấu hình."""
    try:
        settings = config.load(path)
    except config.ConfigError as e:
        log.warning("Bỏ qua cấu hình thông báo: %s", e)
        return {}
    get = lambda key: settings[("notify", key)]
    cfg: dict = {}
    if get("telegram_token") or get("telegram_chat_id"):
        chat = get("telegram_chat_id")
        cfg["telegram"] = {"token": get("telegram_token"),
                           "chat_id": int(chat) if chat.lstrip("-").isdigit() else chat}
    if get("ntfy_topic"):
        cfg["ntfy"] = {"topic": get("ntfy_topic")}
        if get("ntfy_server").rstrip("/") != NTFY_SERVER:
            cfg["ntfy"]["server"] = get("ntfy_server")
    if get("leave_after_minutes") != DEFAULT_LEAVE_MINUTES:
        cfg["leave_after_minutes"] = get("leave_after_minutes")
    return cfg


def save_config(path: str, cfg: dict) -> None:
    """Ghi dict cấu hình vào mục [notify] của afing.cfg, giữ nguyên phần còn lại của file."""
    tg, nt = cfg.get("telegram") or {}, cfg.get("ntfy") or {}
    config.set_values(path, "notify", {
        "telegram_token": tg.get("token", ""),
        "telegram_chat_id": tg.get("chat_id", ""),
        "ntfy_topic": nt.get("topic", ""),
        "ntfy_server": nt.get("server") or NTFY_SERVER,
        "leave_after_minutes": cfg.get("leave_after_minutes", DEFAULT_LEAVE_MINUTES),
    })


def migrate_legacy(json_path: str, cfg_path: str) -> None:
    """Chuyển cấu hình từ notify.json của bản cũ sang afing.cfg (một lần)."""
    if not os.path.exists(json_path):
        return
    try:
        with open(json_path, encoding="utf-8") as f:
            old = json.load(f)
        if isinstance(old, dict) and channels(old) and not channels(load_config(cfg_path)):
            save_config(cfg_path, old)
        os.remove(json_path)
    except (OSError, ValueError):
        pass


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


def split_message(text: str, limit: int = 3500) -> List[str]:
    """Cắt tin dài thành nhiều phần theo ranh giới dòng (Telegram và ntfy giới hạn khoảng 4096)."""
    parts, current = [], ""
    for line in text.split("\n"):
        line = line[:limit]
        if current and len(current) + 1 + len(line) > limit:
            parts.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    return parts + [current] if current else parts


def send(cfg: dict, text: str, buttons: Optional[list] = None) -> List[Tuple[str, Optional[str]]]:
    """Gửi `text` qua mọi kênh đã cấu hình. Trả [(kênh, lỗi hoặc None)].

    `buttons` là các hàng nút bấm [[(nhãn, dữ liệu), ...], ...] hiện dưới tin (chỉ Telegram).
    """
    results = []
    for channel in channels(cfg):
        try:
            parts = split_message(text, 3500 if channel == "telegram" else 1200)
            for index, part in enumerate(parts):
                if channel == "telegram":
                    tg = cfg["telegram"]
                    payload = {"chat_id": tg["chat_id"], "text": part,
                               "disable_web_page_preview": True}
                    if buttons and index == len(parts) - 1:
                        payload["reply_markup"] = {"inline_keyboard": [
                            [{"text": label, "callback_data": data} for label, data in row]
                            for row in buttons]}
                    _post(f"{TELEGRAM_API}/bot{tg['token']}/sendMessage",
                          json.dumps(payload).encode(), {"Content-Type": "application/json"})
                else:
                    nt = cfg["ntfy"]
                    server = (nt.get("server") or NTFY_SERVER).rstrip("/")
                    _post(f"{server}/{nt['topic']}", part.encode(),
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

def rules(path: str) -> dict:
    """Quy tắc thông báo và ngôn ngữ từ afing.cfg; file hỏng thì dùng mặc định."""
    try:
        cfg = config.load(path)
    except config.ConfigError:
        return {"language": "en", "new_device_alerts": True, "presence_alerts": "all",
                "quiet_hours": None}
    return {"language": cfg[("web", "language")],
            "new_device_alerts": cfg[("notify", "new_device_alerts")],
            "presence_alerts": cfg[("notify", "presence_alerts")],
            "quiet_hours": cfg[("notify", "quiet_hours")]}


def in_quiet_hours(quiet: Optional[Tuple[int, int]], now: float) -> bool:
    if not quiet:
        return False
    local = time.localtime(now)
    minute = local.tm_hour * 60 + local.tm_min
    start, end = quiet
    return start <= minute < end if start <= end else (minute >= start or minute < end)


def describe_device(dev: dict, lang: str = "en") -> str:
    """Mô tả thiết bị trong tin báo sự kiện; chưa biết tên thì dùng model/hãng thay cho tên."""
    name = dev.get("custom_name") or dev.get("hostname")
    if not name and (dev.get("vendor") or dev.get("model") or dev.get("os")):
        name = i18n.describe_unnamed(lang, dev)
    head = " ".join(filter(None, (alias.icon(dev.get("alias")), dev.get("alias"))))
    if name:
        head = f"{head} — {name}" if head else name
    kind = " · ".join(filter(None, (
        i18n.type_label(lang, dev.get("custom_type") or dev.get("device_type")), dev.get("os"))))
    if kind:
        head += f" ({kind})"
    detail = " · ".join(filter(None, (dev.get("ip"), dev.get("mac"))))
    facts = i18n.facts(lang, dict(dev, os=None))  # hệ điều hành đã nằm ở dòng đầu
    if facts.lower() in head.lower():  # không lặp lại thứ đã nằm ở dòng tên
        facts = ""
    return "\n".join(filter(None, (head, facts, detail)))


class Notifier:
    """Biến các sự kiện của từng lượt quét thành thông báo.

    - Thiết bị chập chờn (điện thoại ngủ, sóng yếu) không gây báo liên tục: chỉ báo "rời mạng"
      khi thiết bị vắng mặt liên tục `leave_after_minutes` phút, và chỉ báo "quay lại" cho thiết
      bị đã được báo rời mạng.
    - Báo rời mạng / quay lại theo `presence_alerts` (all | unknown | none), giờ yên lặng, và
      thiết lập riêng của từng thiết bị (alert = always | never).
    - Thiết bị mới luôn được báo (trừ khi tắt `new_device_alerts`), kèm nút đánh dấu quen/lạ.
    - Đang /mute thì không gửi gì.
    """

    def __init__(self, config_path: str, devices: Callable[[], List[dict]],
                 sender: Callable[..., list] = None,
                 muted_until: Callable[[], float] = lambda: 0.0):
        self.config_path = config_path
        self._devices = devices
        self._sender = sender or send
        self._muted_until = muted_until
        self._pending_leave: Dict[str, int] = {}  # mac -> thời điểm bắt đầu vắng mặt
        self._silent_leave: set = set()           # rời mạng nhưng không báo -> quay lại cũng không báo

    def active_channels(self) -> List[str]:
        return channels(load_config(self.config_path))

    @staticmethod
    def _wants_presence(dev: Optional[dict], rule: dict, now: float) -> bool:
        if not dev or dev.get("alert") == "never":
            return False
        if dev.get("alert") == "always":
            return True
        mode = rule["presence_alerts"]
        if mode == "none" or (mode == "unknown" and dev.get("known")):
            return False
        return not in_quiet_hours(rule["quiet_hours"], now)

    def process(self, events: List[dict], now: int, network: str = "") -> List[str]:
        """Xử lý sự kiện của một lượt quét; trả các dòng thông báo đã gửi đi (để test)."""
        cfg = load_config(self.config_path)
        if not channels(cfg):
            self._pending_leave.clear()
            self._silent_leave.clear()
            return []
        rule = rules(self.config_path)
        lang = rule["language"]
        leave_after = float(cfg.get("leave_after_minutes", DEFAULT_LEAVE_MINUTES)) * 60
        devices = {d["mac"]: d for d in self._devices()}
        new = [e for e in events if e["type"] == "new"]

        messages: List[Tuple[str, Optional[list]]] = []  # (nội dung, nút bấm)
        plain: List[str] = []
        if len(new) > 1 and len(new) == len(devices):
            # Lượt quét đầu tiên trên một database trống: gộp thành một tin thay vì báo từng máy.
            plain.append(i18n.t(lang, "watching", network=network or i18n.t(lang, "your_network"),
                                count=len(new)))
            new = []
        if rule["new_device_alerts"]:
            for ev in new:
                text = i18n.t(lang, "new_device") + "\n" + describe_device(devices.get(ev["mac"], ev), lang)
                buttons = [[(i18n.t(lang, "btn_known"), f"known:{ev['mac']}"),
                            (i18n.t(lang, "btn_unknown"), f"unknown:{ev['mac']}")]]
                messages.append((text, buttons))
        for ev in events:
            mac = ev["mac"]
            if ev["type"] == "offline":
                self._pending_leave[mac] = ev["ts"]
            elif ev["type"] == "online":
                if self._pending_leave.pop(mac, None) is not None:
                    continue  # chập chờn: chưa kịp báo rời mạng
                if mac in self._silent_leave:
                    self._silent_leave.discard(mac)
                elif self._wants_presence(devices.get(mac), rule, now):
                    plain.append(i18n.t(lang, "back") + "\n" + describe_device(devices[mac], lang))
        for mac, since in list(self._pending_leave.items()):
            if now - since >= leave_after:
                del self._pending_leave[mac]
                dev = devices.get(mac)
                if not dev or dev["is_online"]:
                    continue
                if self._wants_presence(dev, rule, now):
                    plain.append(i18n.t(lang, "left") + "\n" + describe_device(dev, lang))
                else:
                    self._silent_leave.add(mac)

        lines = plain + [text for text, _ in messages]
        if plain:
            messages.insert(0, ("\n\n".join(plain), None))
        if not messages or now < self._muted_until():
            return []
        threading.Thread(target=self._deliver, args=(cfg, messages), daemon=True).start()
        return lines

    def _deliver(self, cfg: dict, messages: List[Tuple[str, Optional[list]]]) -> None:
        for text, buttons in messages:
            for channel, error in self._sender(cfg, text, buttons=buttons):
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
    for channel, error in send(cfg, i18n.t(rules(config_path)["language"], "test")):
        out(f"  {channel}: " + (f"LỖI - {error}" if error else "đã gửi, hãy kiểm tra điện thoại"))
        failed = failed or bool(error)
    return 1 if failed else 0


def disable(config_path: str, out: Callable[[str], None] = print) -> int:
    keep = load_config(config_path).get("leave_after_minutes", DEFAULT_LEAVE_MINUTES)
    save_config(config_path, {"leave_after_minutes": keep})
    out("Đã tắt thông báo và xoá token khỏi file cấu hình.")
    return 0
