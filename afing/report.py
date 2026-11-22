"""Báo cáo thiết bị online/offline: gửi định kỳ, hoặc theo yêu cầu bằng lệnh nhắn cho bot Telegram.

Cấu hình ở mục [report] của afing.cfg.
"""

import ipaddress
import json
import logging
import threading
import time
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import alias, config, notify

log = logging.getLogger("afing.report")

HELP = (
    "afing commands:\n"
    "/report - all devices, online and offline\n"
    "/online - devices online now\n"
    "/offline - devices currently offline\n"
    "/help - this message"
)


def settings(path: str) -> dict:
    """Mục [report] của afing.cfg; file hỏng thì coi như tắt hết."""
    try:
        cfg = config.load(path)
    except config.ConfigError:
        return {"times": [], "interval_minutes": 0, "offline_days": 7, "telegram_commands": False}
    return {key: cfg[("report", key)]
            for key in ("times", "interval_minutes", "offline_days", "telegram_commands")}


def ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} hr ago"
    days = seconds // 86400
    return f"{days} day{'s' if days > 1 else ''} ago"


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "under 1 min"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        hours, minutes = seconds // 3600, seconds % 3600 // 60
        return f"{hours} hr {minutes} min" if minutes else f"{hours} hr"
    days, hours = seconds // 86400, seconds % 86400 // 3600
    text = f"{days} day{'s' if days > 1 else ''}"
    return f"{text} {hours} hr" if hours else text


def clock(ts: float) -> str:
    return time.strftime("%d %b %H:%M", time.localtime(ts))


def _line(dev: dict, when: str) -> str:
    """Hai dòng cho một thiết bị: tên/loại, rồi IP · MAC · thời gian."""
    head = " ".join(filter(None, (alias.icon(dev.get("alias")), dev.get("alias"))))
    name = dev.get("custom_name") or dev.get("hostname")
    if name:
        head = f"{head} — {name}" if head else name
    head = " · ".join(filter(None, (head, notify.TYPE_LABELS.get(dev.get("device_type")))))
    return f"{head}\n    {dev['ip']} · {dev['mac']}\n    {when}"


def build(devices: List[dict], now: float, network: str = "", which: str = "all",
          offline_days: float = 7, online_since: Optional[Dict[str, int]] = None) -> str:
    """Soạn báo cáo dạng văn bản. `which`: all | online | offline.

    `online_since` là {mac: thời điểm bắt đầu lần online hiện tại}; thiếu thì dùng lúc thấy lần đầu.
    """
    online_since = online_since or {}

    def online_time(d):
        since = online_since.get(d["mac"], d["first_seen"])
        return f"online {duration(now - since)} (since {clock(since)})"

    online = sorted((d for d in devices if d["is_online"]),
                    key=lambda d: ipaddress.ip_address(d["ip"]))
    offline = sorted((d for d in devices if not d["is_online"]), key=lambda d: -d["last_seen"])
    lines = [f"📊 afing report{' · ' + network if network else ''}",
             f"{clock(now)} · "
             f"{len(online)} online · {len(offline)} offline"]
    if which in ("all", "online"):
        lines += ["", f"🟢 ONLINE ({len(online)})"]
        lines += [_line(d, online_time(d)) for d in online] or ["(none)"]
    if which in ("all", "offline"):
        recent = [d for d in offline
                  if not offline_days or now - d["last_seen"] <= offline_days * 86400]
        lines += ["", f"⚪ OFFLINE ({len(offline)})"]
        lines += [_line(d, f"last seen {clock(d['last_seen'])} ({ago(now - d['last_seen'])})")
                  for d in recent] or ["(none)"]
        hidden = len(offline) - len(recent)
        if hidden and recent:
            lines.append(f"(+{hidden} not seen for over {offline_days:g} days)")
        elif hidden:
            lines[-1] = f"({hidden} not seen for over {offline_days:g} days)"
    return "\n".join(lines)


class Schedule:
    """Quyết định lúc nào tới hạn gửi báo cáo định kỳ. Gọi `due(now)` ở mỗi lượt quét."""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self._last: Optional[float] = None
        self._interval: float = 0
        self._next: float = 0

    def due(self, now: float) -> bool:
        s = settings(self.config_path)
        if self._last is None:  # lượt đầu: chỉ ghi mốc, không gửi bù các giờ đã qua
            self._last = now
        fire = False
        # Giờ cố định trong ngày: tới hạn nếu mốc giờ nằm giữa lượt kiểm tra trước và lượt này.
        for day in {time.localtime(self._last)[:3], time.localtime(now)[:3]}:
            for hour, minute in s["times"]:
                at = time.mktime(day + (hour, minute, 0, 0, 0, -1))
                if self._last < at <= now:
                    fire = True
        interval = s["interval_minutes"] * 60
        if interval != self._interval:  # vừa bật hoặc vừa đổi chu kỳ: tính lại từ bây giờ
            self._interval, self._next = interval, now + interval
        elif interval and now >= self._next:
            fire = True
            self._next = now + interval
        self._last = now
        return fire


class Reporter:
    def __init__(self, config_path: str, devices: Callable[[], List[dict]], network: str = "",
                 sender: Callable[[dict, str], list] = notify.send,
                 online_since: Callable[[], Dict[str, int]] = dict):
        self.config_path = config_path
        self._devices = devices
        self._online_since = online_since
        self.network = network
        self._sender = sender
        self._schedule = Schedule(config_path)

    def text(self, which: str = "all", now: Optional[float] = None) -> str:
        return build(self._devices(), time.time() if now is None else now, self.network, which,
                     settings(self.config_path)["offline_days"], self._online_since())

    def tick(self, now: float) -> bool:
        """Gọi ở mỗi lượt quét; gửi báo cáo nếu tới hạn. Trả True nếu đã gửi."""
        if not self._schedule.due(now):
            return False
        cfg = notify.load_config(self.config_path)
        if not notify.channels(cfg):
            return False
        threading.Thread(target=self._deliver, args=(cfg, self.text(now=now)), daemon=True).start()
        return True

    def _deliver(self, cfg: dict, text: str) -> None:
        for channel, error in self._sender(cfg, text):
            if error:
                log.warning("Không gửi được báo cáo qua %s: %s", channel, error)


class TelegramCommands:
    """Luồng nền nhận lệnh nhắn cho bot (/report, /online, /offline) và trả lời.

    Chỉ trả thông tin thiết bị cho đúng cuộc trò chuyện đã cấu hình (telegram_chat_id). Người lạ
    nhắn cho bot chỉ nhận được ID cuộc trò chuyện của chính họ khi gõ /start hoặc /chatid.
    """

    def __init__(self, config_path: str, reporter: Reporter):
        self.config_path = config_path
        self.reporter = reporter
        self._stop = threading.Event()
        self._offset: Optional[int] = None
        self._token: Optional[str] = None
        self._thread = threading.Thread(target=self._run, name="afing-telegram", daemon=True)

    def start(self) -> "TelegramCommands":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def replies(self, update: dict, allowed_chat) -> List[Tuple[object, str]]:
        """Một update của Telegram -> [(chat_id, nội dung trả lời)]."""
        message = update.get("message") or update.get("channel_post") or {}
        chat_id = (message.get("chat") or {}).get("id")
        words = (message.get("text") or "").strip().split()
        if chat_id is None or not words:
            return []
        command = words[0].lstrip("/").split("@")[0].lower()
        if str(chat_id) != str(allowed_chat):
            if command in ("start", "chatid"):
                return [(chat_id, f"This chat's ID is {chat_id}.\nTo receive afing alerts here, set "
                                  f"telegram_chat_id = {chat_id} in the [notify] section of afing.cfg.")]
            return []
        if command in ("report", "all", "status"):
            return [(chat_id, self.reporter.text("all"))]
        if command in ("online", "offline"):
            return [(chat_id, self.reporter.text(command))]
        return [(chat_id, HELP)]

    def _call(self, token: str, method: str, params: dict, timeout: float) -> list:
        url = f"{notify.TELEGRAM_API}/bot{token}/{method}?" + urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.load(resp).get("result", [])

    def poll_once(self, wait: int = 25) -> int:
        """Một vòng hỏi Telegram có lệnh mới không. Trả số tin trả lời đã gửi."""
        cfg = notify.load_config(self.config_path)
        tg = cfg.get("telegram") or {}
        if "telegram" not in notify.channels(cfg) or not settings(self.config_path)["telegram_commands"]:
            self._stop.wait(15)
            return 0
        token = tg["token"]
        if token != self._token:  # bot mới (hoặc vừa khởi động): bỏ qua các lệnh cũ còn tồn
            self._token = token
            pending = self._call(token, "getUpdates", {"offset": -1, "timeout": 0}, 15)
            self._offset = pending[-1]["update_id"] + 1 if pending else 0
        updates = self._call(token, "getUpdates", {
            "offset": self._offset, "timeout": wait, "allowed_updates": '["message","channel_post"]',
        }, wait + 10)
        sent = 0
        for update in updates:
            self._offset = update["update_id"] + 1
            for chat_id, text in self.replies(update, tg["chat_id"]):
                for part in notify.split_message(text):
                    notify._post(f"{notify.TELEGRAM_API}/bot{token}/sendMessage",
                                 json.dumps({"chat_id": chat_id, "text": part,
                                             "disable_web_page_preview": True}).encode(),
                                 {"Content-Type": "application/json"})
                    sent += 1
        return sent

    def _run(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                self.poll_once()
                failures = 0
            except Exception as e:
                failures += 1
                if failures in (1, 10):  # không lặp lại cùng một lỗi mỗi phút
                    log.warning("Không nhận được lệnh từ Telegram: %s", notify._explain(e))
                self._stop.wait(min(60, 5 * failures))
