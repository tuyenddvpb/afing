"""Đoán loại thiết bị và hệ điều hành từ các dấu hiệu đã thu được.

Đây là suy luận theo luật, không phải sự thật: luật nào khớp trước thì thắng, xếp từ dấu hiệu
chắc chắn (dịch vụ thiết bị tự quảng bá) tới dấu hiệu yếu (hãng sản xuất card mạng).
Không đủ dấu hiệu thì trả None chứ không đoán bừa.
"""

import re
from typing import Iterable, Optional, Tuple

# Mã loại -> nhãn hiển thị (dashboard có bảng tương ứng trong index.html).
TYPES = {
    "router": "Router", "network": "Thiết bị mạng", "computer": "Máy tính", "mobile": "Điện thoại",
    "tablet": "Máy tính bảng", "tv": "Tivi", "media": "Đầu phát media", "speaker": "Loa",
    "printer": "Máy in", "camera": "Camera", "console": "Máy chơi game", "nas": "NAS",
    "appliance": "Đồ gia dụng", "vacuum": "Robot hút bụi", "iot": "Thiết bị IoT",
    "wearable": "Thiết bị đeo",
}

Guess = Tuple[Optional[str], Optional[str]]

# Luật theo chữ trong tên + model: (regex, loại, hệ điều hành).
TEXT_RULES = [
    (r"iphone", "mobile", "iOS"),
    (r"ipad", "tablet", "iPadOS"),
    (r"macbook|imac|mac ?mini|mac ?pro|mac ?studio|^mac\d", "computer", "macOS"),
    (r"apple ?tv", "tv", "tvOS"),
    (r"homepod|audioaccessory", "speaker", None),
    (r"watch", "wearable", None),
    (r"chromecast|fire ?tv|\bshield\b|\broku\b|mi ?box", "media", None),
    (r"\[tv\]|bravia|tizen|webos|smart ?tv|android ?tv|\btv\b|\b(un|ua|qa|qn|ue)\d\d[a-z]", "tv", None),
    (r"playstation|\bps[345]\b|xbox|nintendo", "console", None),
    (r"deebot|roborock|roomba|vacuum|dreame", "vacuum", None),
    (r"wash|dryer|fridge|refrigerator|air ?con|aircon|purifier|oven|dishwasher", "appliance", None),
    (r"laserjet|deskjet|officejet|envy \d|^brw|^brn|\bdcp-|\bmfc-|\bhl-|ecotank|pixma|printer", "printer", None),
    (r"ipcam|ip ?camera|camera|hikvision|dahua|ezviz|imou|\bcam\b|doorbell", "camera", None),
    (r"synology|diskstation|qnap|\bnas\b|truenas|readynas", "nas", None),
    (r"echo|sonos|google[- ]?home|nest[- ]?(mini|audio|hub)|soundbar|speaker", "speaker", None),
    (r"surface", "tablet", "Windows"),
    (r"^(desktop|laptop|win)-[a-z0-9]+$|[-_]pc$|^pc[-_]|thinkpad|latitude|optiplex", "computer", "Windows"),
    (r"raspberrypi|raspberry|ubuntu|debian|\blinux\b", "computer", "Linux"),
    (r"galaxy|redmi|\bpoco\b|pixel|oppo|vivo|realme|oneplus|^android|\bsm-[a-z]\d", "mobile", "Android"),
    (r"^esp[-_]|esp32|esp8266|tasmota|shelly|sonoff|tuya|smart ?plug|\bbulb\b", "iot", None),
]

# Luật theo hãng (từ MAC) - yếu nhất, chỉ dùng cho hãng gần như chỉ làm một loại thiết bị.
VENDOR_RULES = [
    (r"espressif|tuya|shelly|itead|shenzhen bilian", "iot", None),
    (r"hikvision|dahua|ezviz|reolink|arlo", "camera", None),
    (r"brother|canon|epson|lexmark|kyocera|ricoh", "printer", None),
    (r"sonos", "speaker", None),
    (r"nintendo|sony interactive", "console", None),
    (r"raspberry pi", "computer", "Linux"),
    (r"synology|qnap", "nas", None),
    (r"ecovacs|roborock|irobot", "vacuum", None),
    (r"tp-link|zte|ubiquiti|mikrotik|routerboard|netgear|d-link|tenda|totolink|draytek|ruckus|aruba"
     r"|cisco|juniper|fiberhome", "network", None),
    (r"dell|lenovo|hewlett packard|asustek|micro-star|giga-byte|gigabyte|acer|\bintel\b", "computer", None),
]


def _match(rules, text: str) -> Guess:
    for pattern, type_, os_ in rules:
        if re.search(pattern, text):
            return type_, os_
    return None, None


def _from_services(services: set, text: str) -> Guess:
    if services & {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"}:
        return "printer", None
    if "_androidtvremote2._tcp" in services:
        return "tv", "Android TV"
    if "_googlecast._tcp" in services:
        if re.search(r"home|nest|speaker|audio", text):
            return "speaker", None
        return ("media", None) if "chromecast" in text else ("tv", None)
    if "_amzn-wplay._tcp" in services:
        return "media", "Fire OS"
    if "_sonos._tcp" in services:
        return "speaker", None
    if "_esphomelib._tcp" in services:
        return "iot", None
    if "_workstation._tcp" in services:
        return "computer", "Linux"
    return None, None


def _from_upnp(upnp_type: str) -> Guess:
    t = upnp_type.lower()
    if "internetgateway" in t or "wandevice" in t or "wfadevice" in t:
        return "router", None
    if "printer" in t:
        return "printer", None
    if "mediarenderer" in t or "dial" in t or "tvdevice" in t:
        return "tv", None
    if "mediaserver" in t:
        return "nas", None
    return None, None


def _from_dhcp(vendor_class: str, fingerprint: str) -> Guess:
    """Vendor class (option 60) là dấu hiệu chắc; Apple không gửi nên phải nhìn vân tay (option 55)."""
    vc = vendor_class.lower()
    if vc.startswith("msft"):
        return "computer", "Windows"
    m = re.match(r"android-dhcp-(\d+)", vc)
    if m:
        return "mobile", f"Android {m.group(1)}"
    if vc.startswith("dhcpcd") or "udhcp" in vc or "linux" in vc:
        return None, "Linux"  # máy tính, router hay đồ IoT đều có thể chạy Linux
    params = fingerprint.split(",")
    if not vc and fingerprint.startswith("1,121,3,6,15") and "119" in params and "252" in params:
        # Thiết bị Apple. macOS xin thêm option 95 (LDAP); iOS/iPadOS thì không.
        return ("computer", "macOS") if "95" in params else ("mobile", "iOS")
    return None, None


def classify(
    vendor: Optional[str] = None,
    name: Optional[str] = None,
    model: Optional[str] = None,
    services: Iterable[str] = (),
    upnp_type: Optional[str] = None,
    sources: Iterable[str] = (),
    is_gateway: bool = False,
    dhcp: Optional[dict] = None,
) -> Guess:
    """Trả (mã loại, hệ điều hành); phần nào không đủ dấu hiệu thì là None.

    `dhcp` là thông tin nghe được từ gói DHCP: {"hostname", "vendor_class", "fingerprint"}.
    """
    dhcp = dhcp or {}
    text = " ".join(filter(None, (name, model, dhcp.get("hostname")))).lower()
    vendor_l = (vendor or "").lower()
    services, sources = set(services), set(sources)

    guesses = [
        ("router", None) if is_gateway else (None, None),
        _match(TEXT_RULES[:5], text),            # sản phẩm Apple nêu rõ tên: chắc hơn dịch vụ
        _from_services(services, text),
        _match(TEXT_RULES, text),
        _from_upnp(upnp_type or ""),
        _from_dhcp(dhcp.get("vendor_class") or "", dhcp.get("fingerprint") or ""),
        _match(VENDOR_RULES, vendor_l),
        # Trả lời NetBIOS mà không phải máy in/NAS/TV (đã bắt ở trên) thì gần như chắc là Windows.
        ("computer", "Windows") if "nb" in sources else (None, None),
        ("computer", None) if services & {"_smb._tcp", "_afpovertcp._tcp", "_ssh._tcp",
                                          "_sftp-ssh._tcp", "_rfb._tcp"} else (None, None),
    ]
    type_ = next((t for t, _ in guesses if t), None)
    os_ = next((o for t, o in guesses if o and t in (type_, None)), None)

    if not os_:
        both = text + " " + vendor_l
        if type_ == "tv":
            os_ = "Tizen" if "samsung" in both else "webOS" if re.search(r"\blg\b|webos", both) else None
        elif type_ in ("computer", "tablet") and "nb" in sources:
            os_ = "Windows"
        elif "_companion-link._tcp" in services and "apple" in vendor_l and not type_:
            os_ = None  # thiết bị Apple nhưng chưa rõ iPhone/iPad/Mac
    return type_, os_
