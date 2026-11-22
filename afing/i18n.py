"""Chuỗi hiển thị trong tin nhắn và báo cáo, bằng tiếng Anh và tiếng Việt.

Ngôn ngữ chọn ở `[web] language` trong afing.cfg (dashboard có bảng chuỗi riêng trong index.html).
"""

from typing import Optional

TEXT = {
    "en": {
        "new_device": "🆕 New device",
        "back": "🟢 Back online",
        "left": "🔴 Left the network",
        "watching": "✅ afing is now watching {network}: {count} devices found.",
        "your_network": "your network",
        "test": "✅ afing test notification. Alerts are working.",
        "report": "📊 afing report",
        "online_count": "{n} online", "offline_count": "{n} offline",
        "online_head": "🟢 ONLINE ({n})", "offline_head": "⚪ OFFLINE ({n})",
        "none": "(none)",
        "online_for": "online {duration} (since {since})",
        "last_seen": "last seen {at} ({ago})",
        "hidden_more": "(+{n} not seen for over {days} days)",
        "hidden_only": "({n} not seen for over {days} days)",
        "just_now": "just now", "min_ago": "{n} min ago", "hr_ago": "{n} hr ago",
        "day_ago": "{n} day ago", "days_ago": "{n} days ago",
        "under_min": "under 1 min", "min": "{n} min", "hr": "{n} hr", "hr_min": "{h} hr {m} min",
        "day": "{n} day", "days": "{n} days", "day_hr": "{d} {h} hr",
        "help": ("afing commands:\n"
                 "/report - all devices, online and offline\n"
                 "/online - devices online now\n"
                 "/offline - devices currently offline\n"
                 "/who - who is home\n"
                 "/find <text> - search by alias, name, IP or MAC\n"
                 "/rename <alias> = <new name>\n"
                 "/known <alias> - mark a device as known\n"
                 "/mute <2h|30m> - pause alerts, /unmute - resume\n"
                 "/help - this message"),
        "chat_id": ("This chat's ID is {id}.\nTo receive afing alerts here, set "
                    "telegram_chat_id = {id} in the [notify] section of afing.cfg."),
        "who_head": "🏠 Who is home",
        "home": "🟢 {name} — home ({devices})",
        "away": "⚪ {name} — away (last seen {ago})",
        "who_empty": ("No devices are assigned to a person yet. Open a device on the dashboard and "
                      "fill in \"Belongs to\"."),
        "find_usage": "Usage: /find <text>",
        "find_none": "No device matches \"{q}\".",
        "rename_usage": "Usage: /rename <alias or current name> = <new name>",
        "no_match": "No device matches \"{q}\".",
        "many_match": "\"{q}\" matches {n} devices; be more specific:\n{list}",
        "renamed": "✅ {alias} is now named \"{name}\".",
        "known_usage": "Usage: /known <alias or name>",
        "marked_known": "✅ {alias} marked as known.",
        "marked_unknown": "{alias} left as unknown.",
        "mute_usage": "Usage: /mute 2h  (or 30m, 1d)",
        "muted": "🔕 Alerts paused until {until}. Send /unmute to resume.",
        "unmuted": "🔔 Alerts resumed.",
        "btn_known": "✅ I know this device", "btn_unknown": "🚫 Unknown",
        "state_online": "online", "state_offline": "offline",
        "device_of": "{vendor} device",
        "private_mac": "unnamed device with a private (random) MAC",
        "private_mac_hint": "Private MAC: usually a phone, tablet or laptop hiding its real address",
        "unnamed": "unnamed device",
        "types": {
            "router": "Router", "network": "Network device", "computer": "Computer",
            "mobile": "Phone", "tablet": "Tablet", "tv": "TV", "media": "Media player",
            "speaker": "Speaker", "printer": "Printer", "camera": "Camera",
            "console": "Game console", "nas": "NAS", "appliance": "Appliance",
            "vacuum": "Robot vacuum", "iot": "IoT device", "wearable": "Wearable",
        },
    },
    "vi": {
        "new_device": "🆕 Thiết bị mới",
        "back": "🟢 Đã quay lại mạng",
        "left": "🔴 Đã rời mạng",
        "watching": "✅ afing bắt đầu theo dõi {network}: tìm thấy {count} thiết bị.",
        "your_network": "mạng của bạn",
        "test": "✅ Tin thử từ afing. Thông báo đang hoạt động.",
        "report": "📊 Báo cáo afing",
        "online_count": "{n} trực tuyến", "offline_count": "{n} ngoại tuyến",
        "online_head": "🟢 TRỰC TUYẾN ({n})", "offline_head": "⚪ NGOẠI TUYẾN ({n})",
        "none": "(không có)",
        "online_for": "trực tuyến {duration} (từ {since})",
        "last_seen": "thấy lần cuối {at} ({ago})",
        "hidden_more": "(+{n} thiết bị không thấy quá {days} ngày)",
        "hidden_only": "({n} thiết bị không thấy quá {days} ngày)",
        "just_now": "vừa xong", "min_ago": "{n} phút trước", "hr_ago": "{n} giờ trước",
        "day_ago": "{n} ngày trước", "days_ago": "{n} ngày trước",
        "under_min": "dưới 1 phút", "min": "{n} phút", "hr": "{n} giờ", "hr_min": "{h} giờ {m} phút",
        "day": "{n} ngày", "days": "{n} ngày", "day_hr": "{d} {h} giờ",
        "help": ("Các lệnh của afing:\n"
                 "/report - mọi thiết bị, trực tuyến và ngoại tuyến\n"
                 "/online - thiết bị đang trực tuyến\n"
                 "/offline - thiết bị đang ngoại tuyến\n"
                 "/who - ai đang ở nhà\n"
                 "/find <chữ> - tìm theo alias, tên, IP hoặc MAC\n"
                 "/rename <alias> = <tên mới>\n"
                 "/known <alias> - đánh dấu thiết bị quen\n"
                 "/mute <2h|30m> - tạm tắt thông báo, /unmute - bật lại\n"
                 "/help - xem lại danh sách này"),
        "chat_id": ("ID của cuộc trò chuyện này là {id}.\nĐể nhận thông báo afing tại đây, đặt "
                    "telegram_chat_id = {id} trong mục [notify] của afing.cfg."),
        "who_head": "🏠 Ai đang ở nhà",
        "home": "🟢 {name} — ở nhà ({devices})",
        "away": "⚪ {name} — vắng (thấy lần cuối {ago})",
        "who_empty": ("Chưa có thiết bị nào được gán cho người dùng. Mở một thiết bị trên dashboard "
                      "và điền mục \"Của ai\"."),
        "find_usage": "Cách dùng: /find <chữ cần tìm>",
        "find_none": "Không có thiết bị nào khớp \"{q}\".",
        "rename_usage": "Cách dùng: /rename <alias hoặc tên hiện tại> = <tên mới>",
        "no_match": "Không có thiết bị nào khớp \"{q}\".",
        "many_match": "\"{q}\" khớp {n} thiết bị; hãy ghi rõ hơn:\n{list}",
        "renamed": "✅ {alias} giờ có tên \"{name}\".",
        "known_usage": "Cách dùng: /known <alias hoặc tên>",
        "marked_known": "✅ Đã đánh dấu {alias} là thiết bị quen.",
        "marked_unknown": "{alias} vẫn là thiết bị lạ.",
        "mute_usage": "Cách dùng: /mute 2h  (hoặc 30m, 1d)",
        "muted": "🔕 Tạm tắt thông báo tới {until}. Nhắn /unmute để bật lại.",
        "unmuted": "🔔 Đã bật lại thông báo.",
        "btn_known": "✅ Thiết bị quen", "btn_unknown": "🚫 Thiết bị lạ",
        "state_online": "trực tuyến", "state_offline": "ngoại tuyến",
        "device_of": "thiết bị {vendor}",
        "private_mac": "thiết bị chưa rõ tên, dùng MAC riêng tư (ngẫu nhiên)",
        "private_mac_hint": "MAC riêng tư: thường là điện thoại, máy tính bảng hoặc laptop đang giấu địa chỉ thật",
        "unnamed": "thiết bị chưa rõ tên",
        "types": {
            "router": "Router", "network": "Thiết bị mạng", "computer": "Máy tính",
            "mobile": "Điện thoại", "tablet": "Máy tính bảng", "tv": "Tivi",
            "media": "Đầu phát media", "speaker": "Loa", "printer": "Máy in", "camera": "Camera",
            "console": "Máy chơi game", "nas": "NAS", "appliance": "Đồ gia dụng",
            "vacuum": "Robot hút bụi", "iot": "Thiết bị IoT", "wearable": "Thiết bị đeo",
        },
    },
}


def t(lang: str, key: str, **values) -> str:
    text = TEXT.get(lang, TEXT["en"]).get(key) or TEXT["en"][key]
    return text.format(**values) if values else text


def type_label(lang: str, code: Optional[str]) -> Optional[str]:
    return TEXT.get(lang, TEXT["en"])["types"].get(code) if code else None


def describe_unnamed(lang: str, dev: dict) -> str:
    """Mô tả thay cho tên khi chưa biết tên thiết bị, dựa trên những gì afing biết về nó.

    Ưu tiên: model > "iPhone" (điện thoại chạy iOS) > hãng sản xuất > ghi chú MAC riêng tư.
    """
    from .oui import RANDOM_MAC
    if dev.get("model"):
        return dev["model"]
    kind = dev.get("custom_type") or dev.get("device_type")
    if kind == "mobile" and (dev.get("os") or "").startswith("iOS"):
        return "iPhone"
    vendor = dev.get("vendor")
    if vendor == RANDOM_MAC:
        return t(lang, "private_mac")
    if vendor:
        return t(lang, "device_of", vendor=vendor)
    return t(lang, "unnamed")


def facts(lang: str, dev: dict) -> str:
    """Dòng "hãng · model · hệ điều hành" (bỏ phần không biết) để giúp nhận ra thiết bị."""
    from .oui import RANDOM_MAC
    vendor = dev.get("vendor")
    if vendor == RANDOM_MAC:
        vendor = t(lang, "private_mac_hint")
    model = dev.get("model")
    if model and vendor and vendor.split()[0].lower() in model.lower():
        vendor = None  # model đã nêu hãng, vd "Samsung Electronics UN43TU6900"
    return " · ".join(filter(None, (vendor, model, dev.get("os"))))


def ago(lang: str, seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return t(lang, "just_now")
    if seconds < 3600:
        return t(lang, "min_ago", n=seconds // 60)
    if seconds < 86400:
        return t(lang, "hr_ago", n=seconds // 3600)
    days = seconds // 86400
    return t(lang, "days_ago" if days > 1 else "day_ago", n=days)


def duration(lang: str, seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return t(lang, "under_min")
    if seconds < 3600:
        return t(lang, "min", n=seconds // 60)
    if seconds < 86400:
        hours, minutes = seconds // 3600, seconds % 3600 // 60
        return t(lang, "hr_min", h=hours, m=minutes) if minutes else t(lang, "hr", n=hours)
    days, hours = seconds // 86400, seconds % 86400 // 3600
    text = t(lang, "days" if days > 1 else "day", n=days)
    return t(lang, "day_hr", d=text, h=hours) if hours else text
