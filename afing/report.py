"""Báo cáo thiết bị online/offline và điều khiển afing bằng lệnh nhắn cho bot Telegram.

Cấu hình ở mục [report] của afing.cfg.
"""

import ipaddress
import json
import logging
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import alias, config, i18n, notify

log = logging.getLogger("afing.report")

HELP = i18n.t("en", "help")


def settings(path: str) -> dict:
    """Mục [report] của afing.cfg; file hỏng thì coi như tắt hết."""
    try:
        cfg = config.load(path)
    except config.ConfigError:
        return {"times": [], "interval_minutes": 0, "offline_days": 7, "telegram_commands": False}
    return {key: cfg[("report", key)]
            for key in ("times", "interval_minutes", "offline_days", "telegram_commands")}


def ago(seconds: float, lang: str = "en") -> str:
    return i18n.ago(lang, seconds)


def duration(seconds: float, lang: str = "en") -> str:
    return i18n.duration(lang, seconds)


def clock(ts: float) -> str:
    return time.strftime("%d %b %H:%M", time.localtime(ts))


def label(dev: dict) -> str:
    """Tên gọi ngắn của thiết bị: "🐿️ Squirrel — MDs-phone"."""
    head = " ".join(filter(None, (alias.icon(dev.get("alias")), dev.get("alias"))))
    name = dev.get("custom_name") or dev.get("hostname")
    if name:
        head = f"{head} — {name}" if head else name
    return head or dev["mac"]


def _line(dev: dict, when: str, lang: str) -> str:
    """Ba dòng cho một thiết bị: tên/loại, rồi IP · MAC, rồi thời gian."""
    kind = i18n.type_label(lang, dev.get("custom_type") or dev.get("device_type"))
    head = " · ".join(filter(None, (label(dev), kind)))
    return f"{head}\n    {dev['ip']} · {dev['mac']}\n    {when}"


def build(devices: List[dict], now: float, network: str = "", which: str = "all",
          offline_days: float = 7, online_since: Optional[Dict[str, int]] = None,
          lang: str = "en") -> str:
    """Soạn báo cáo dạng văn bản. `which`: all | online | offline.

    `online_since` là {mac: thời điểm bắt đầu lần online hiện tại}; thiếu thì dùng lúc thấy lần đầu.
    """
    online_since = online_since or {}
    T = lambda key, **kw: i18n.t(lang, key, **kw)

    def online_time(d):
        since = online_since.get(d["mac"], d["first_seen"])
        return T("online_for", duration=i18n.duration(lang, now - since), since=clock(since))

    online = sorted((d for d in devices if d["is_online"]),
                    key=lambda d: ipaddress.ip_address(d["ip"]))
    offline = sorted((d for d in devices if not d["is_online"]), key=lambda d: -d["last_seen"])
    lines = [T("report") + (" · " + network if network else ""),
             f"{clock(now)} · {T('online_count', n=len(online))} · "
             f"{T('offline_count', n=len(offline))}"]
    if which in ("all", "online"):
        lines += ["", T("online_head", n=len(online))]
        lines += [_line(d, online_time(d), lang) for d in online] or [T("none")]
    if which in ("all", "offline"):
        recent = [d for d in offline
                  if not offline_days or now - d["last_seen"] <= offline_days * 86400]
        lines += ["", T("offline_head", n=len(offline))]
        lines += [_line(d, T("last_seen", at=clock(d["last_seen"]),
                             ago=i18n.ago(lang, now - d["last_seen"])), lang)
                  for d in recent] or [T("none")]
        hidden = len(offline) - len(recent)
        if hidden and recent:
            lines.append(T("hidden_more", n=hidden, days=f"{offline_days:g}"))
        elif hidden:
            lines[-1] = T("hidden_only", n=hidden, days=f"{offline_days:g}")
    return "\n".join(lines)


def people(devices: List[dict]) -> List[dict]:
    """Gom thiết bị theo người dùng: [{name, home, devices (đang online), last_seen}]."""
    groups: Dict[str, dict] = {}
    for d in devices:
        name = (d.get("person") or "").strip()
        if not name:
            continue
        g = groups.setdefault(name.lower(), {"name": name, "home": False, "devices": [],
                                             "last_seen": 0})
        g["last_seen"] = max(g["last_seen"], d["last_seen"])
        if d["is_online"]:
            g["home"] = True
            g["devices"].append(d)
    return sorted(groups.values(), key=lambda g: g["name"].lower())


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
                 sender: Callable[..., list] = None,
                 online_since: Callable[[], Dict[str, int]] = dict):
        self.config_path = config_path
        self._devices = devices
        self._online_since = online_since
        self.network = network
        self._sender = sender or notify.send
        self._schedule = Schedule(config_path)

    def language(self) -> str:
        return notify.rules(self.config_path)["language"]

    def text(self, which: str = "all", now: Optional[float] = None) -> str:
        return build(self._devices(), time.time() if now is None else now, self.network, which,
                     settings(self.config_path)["offline_days"], self._online_since(),
                     self.language())

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


def parse_span(text: str) -> Optional[int]:
    """"2h", "30m", "1d", "45" (phút) -> số giây."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([mhd]?)", text.strip().lower())
    if not m or float(m.group(1)) <= 0:
        return None
    return int(float(m.group(1)) * {"m": 60, "": 60, "h": 3600, "d": 86400}[m.group(2)])


class TelegramCommands:
    """Luồng nền nhận lệnh nhắn cho bot và các lần bấm nút dưới tin "thiết bị mới".

    Chỉ làm theo lệnh từ đúng cuộc trò chuyện đã cấu hình (telegram_chat_id). Người lạ nhắn cho
    bot chỉ nhận được ID cuộc trò chuyện của chính họ khi gõ /start hoặc /chatid.

    `db` (afing.db.Database) cần cho các lệnh sửa dữ liệu: /rename, /known, /mute.
    """

    def __init__(self, config_path: str, reporter: Reporter, db=None):
        self.config_path = config_path
        self.reporter = reporter
        self.db = db
        self._stop = threading.Event()
        self._offset: Optional[int] = None
        self._token: Optional[str] = None
        self._thread = threading.Thread(target=self._run, name="afing-telegram", daemon=True)

    def start(self) -> "TelegramCommands":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    # ----- tìm thiết bị theo chữ người dùng gõ -----

    def _match(self, query: str) -> List[dict]:
        q = query.strip().lower()
        devices = self.reporter._devices()
        exact = [d for d in devices if q in ((d.get("alias") or "").lower(),
                                             (d.get("custom_name") or "").lower(),
                                             (d.get("hostname") or "").lower(), d["mac"], d["ip"])]
        if exact:
            return exact
        return [d for d in devices if any(q in (d.get(k) or "").lower() for k in (
            "alias", "custom_name", "hostname", "ip", "mac", "vendor", "model", "person"))]

    def _one(self, query: str, lang: str):
        """Tìm đúng một thiết bị; không được thì trả (None, câu giải thích)."""
        found = self._match(query)
        if not found:
            return None, i18n.t(lang, "no_match", q=query)
        if len(found) > 1:
            return None, i18n.t(lang, "many_match", q=query, n=len(found),
                                list="\n".join(label(d) for d in found[:10]))
        return found[0], None

    # ----- xử lý một update -----

    def replies(self, update: dict, allowed_chat) -> List[Tuple[object, str]]:
        """Một update của Telegram -> [(chat_id, nội dung trả lời)]."""
        lang = self.reporter.language()
        T = lambda key, **kw: i18n.t(lang, key, **kw)

        callback = update.get("callback_query")
        if callback:  # bấm nút dưới tin "thiết bị mới"
            chat_id = ((callback.get("message") or {}).get("chat") or {}).get("id")
            action, _, mac = (callback.get("data") or "").partition(":")
            if str(chat_id) != str(allowed_chat) or not self.db or action not in ("known", "unknown"):
                return []
            dev = self.db.device(mac)
            if not dev:
                return []
            self.db.update_device(mac, {"known": action == "known"})
            return [(chat_id, T("marked_known" if action == "known" else "marked_unknown",
                                alias=label(dev)))]

        message = update.get("message") or update.get("channel_post") or {}
        chat_id = (message.get("chat") or {}).get("id")
        text = (message.get("text") or "").strip()
        if chat_id is None or not text:
            return []
        first, _, rest = text.partition(" ")
        command, rest = first.lstrip("/").split("@")[0].lower(), rest.strip()
        if str(chat_id) != str(allowed_chat):
            if command in ("start", "chatid"):
                return [(chat_id, T("chat_id", id=chat_id))]
            return []

        if command in ("report", "all", "status"):
            return [(chat_id, self.reporter.text("all"))]
        if command in ("online", "offline"):
            return [(chat_id, self.reporter.text(command))]
        if command == "who":
            groups = people(self.reporter._devices())
            if not groups:
                return [(chat_id, T("who_empty"))]
            now = time.time()
            lines = [T("who_head")]
            for g in groups:
                if g["home"]:
                    lines.append(T("home", name=g["name"], devices=", ".join(
                        d.get("alias") or d["mac"] for d in g["devices"])))
                else:
                    lines.append(T("away", name=g["name"], ago=i18n.ago(lang, now - g["last_seen"])))
            return [(chat_id, "\n".join(lines))]
        if command == "find":
            if not rest:
                return [(chat_id, T("find_usage"))]
            found = self._match(rest)
            if not found:
                return [(chat_id, T("find_none", q=rest))]
            now = time.time()
            since = self.reporter._online_since()
            lines = []
            for d in found[:15]:
                when = (T("online_for", duration=i18n.duration(lang, now - since.get(d["mac"], d["first_seen"])),
                          since=clock(since.get(d["mac"], d["first_seen"])))
                        if d["is_online"] else
                        T("last_seen", at=clock(d["last_seen"]), ago=i18n.ago(lang, now - d["last_seen"])))
                lines.append(("🟢 " if d["is_online"] else "⚪ ") + _line(d, when, lang))
            return [(chat_id, "\n".join(lines))]
        if command == "rename" and self.db:
            target, sep, new_name = rest.partition("=")
            new_name = re.sub(r"[\x00-\x1f\x7f]", "", new_name).strip()[:80]
            if not sep or not target.strip() or not new_name:
                return [(chat_id, T("rename_usage"))]
            dev, problem = self._one(target, lang)
            if not dev:
                return [(chat_id, problem)]
            self.db.update_device(dev["mac"], {"custom_name": new_name})
            return [(chat_id, T("renamed", alias=dev.get("alias") or dev["mac"], name=new_name))]
        if command == "known" and self.db:
            if not rest:
                return [(chat_id, T("known_usage"))]
            dev, problem = self._one(rest, lang)
            if not dev:
                return [(chat_id, problem)]
            self.db.update_device(dev["mac"], {"known": True})
            return [(chat_id, T("marked_known", alias=label(dev)))]
        if command == "mute" and self.db:
            seconds = parse_span(rest) if rest else None
            if not seconds:
                return [(chat_id, T("mute_usage"))]
            until = time.time() + seconds
            self.db.set_state("mute_until", str(int(until)))
            return [(chat_id, T("muted", until=clock(until)))]
        if command == "unmute" and self.db:
            self.db.set_state("mute_until", "0")
            return [(chat_id, T("unmuted"))]
        return [(chat_id, T("help"))]

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
            "offset": self._offset, "timeout": wait,
            "allowed_updates": '["message","channel_post","callback_query"]',
        }, wait + 10)
        sent = 0
        for update in updates:
            self._offset = update["update_id"] + 1
            if update.get("callback_query"):  # tắt biểu tượng "đang xử lý" trên nút vừa bấm
                try:
                    notify._post(f"{notify.TELEGRAM_API}/bot{token}/answerCallbackQuery",
                                 json.dumps({"callback_query_id": update["callback_query"].get("id")}).encode(),
                                 {"Content-Type": "application/json"})
                except Exception:
                    pass
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
