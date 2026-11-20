"""Nghe thụ động các gói DHCP mà thiết bị phát ra khi vào mạng.

Mỗi khi kết nối Wi-Fi/LAN, thiết bị broadcast gói DISCOVER/REQUEST tới cổng UDP 67, trong đó có:
- option 12: tên máy do chính thiết bị khai (vd "iPhone-cua-Me", "DESKTOP-AB12");
- option 60: vendor class (vd "android-dhcp-14", "MSFT 5.0");
- option 55: danh sách tham số xin cấp - thứ tự đặc trưng cho từng hệ điều hành ("vân tay").

afing chỉ nghe, không bao giờ trả lời, nên không ảnh hưởng tới DHCP server của router.
Cần quyền root/admin vì phải mở cổng 67. Gói gia hạn IP gửi thẳng tới router nên không nghe
được: thiết bị chỉ lộ diện khi kết nối (lại) vào mạng.
"""

import logging
import re
import socket
import threading
from typing import Callable, Dict, Optional

from .names import clean_name
from .scanner import norm_mac

log = logging.getLogger("afing.dhcp")

MAGIC_COOKIE = b"\x63\x82\x53\x63"
MESSAGE_TYPES = {1: "DISCOVER", 3: "REQUEST", 8: "INFORM"}  # các loại do client gửi mà ta quan tâm


def parse_options(data: bytes) -> Dict[int, bytes]:
    options, off = {}, 0
    while off < len(data):
        code = data[off]
        if code == 255:  # end
            break
        if code == 0:    # pad
            off += 1
            continue
        if off + 1 >= len(data):
            break
        length = data[off + 1]
        value = data[off + 2 : off + 2 + length]
        if len(value) < length:
            break  # gói bị cắt cụt
        options[code] = options.get(code, b"") + value  # RFC 3396: option lặp lại thì nối
        off += 2 + length
    return options


def _text(raw: Optional[bytes], limit: int = 64) -> Optional[str]:
    if not raw:
        return None
    text = re.sub(r"[^\x20-\x7e]", "", raw.decode("utf-8", "replace")).strip()
    return text[:limit] or None


def parse_packet(data: bytes) -> Optional[dict]:
    """Gói DHCP từ client -> {"mac", "type", "hostname", "vendor_class", "fingerprint",
    "requested_ip"}; trả None nếu không phải gói client hợp lệ."""
    if len(data) < 240 or data[0] != 1 or data[236:240] != MAGIC_COOKIE:
        return None  # op=1 là BOOTREQUEST (client -> server)
    if data[1] != 1 or data[2] != 6:
        return None  # chỉ nhận Ethernet/Wi-Fi (MAC 6 byte)
    mac = norm_mac(data[28:34].hex(":"))
    if not mac:
        return None
    options = parse_options(data[240:])
    msg_type = MESSAGE_TYPES.get((options.get(53) or b"\0")[0])
    if not msg_type:
        return None

    # option 12 là tên máy; vài thiết bị chỉ gửi option 81 (FQDN: 3 byte cờ + tên).
    hostname = clean_name(_text(options.get(12), 80))
    if not hostname and len(options.get(81, b"")) > 3:
        hostname = clean_name(_text(options[81][3:], 80))
    requested = options.get(50)
    ciaddr = data[12:16]
    ip = requested if requested and len(requested) == 4 else ciaddr if any(ciaddr) else None
    return {
        "mac": mac,
        "type": msg_type,
        "hostname": hostname,
        "vendor_class": _text(options.get(60)),
        "fingerprint": ",".join(str(b) for b in options.get(55, b"")[:64]) or None,
        "requested_ip": socket.inet_ntoa(ip) if ip else None,
    }


class DhcpListener:
    """Luồng nền nghe cổng DHCP và gọi `on_packet(info)` cho mỗi gói client hợp lệ."""

    def __init__(self, on_packet: Callable[[dict], None], host: str = "", port: int = 67):
        self.on_packet = on_packet
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._sock.bind((host, port))
            self._sock.settimeout(1.0)
        except OSError:
            self._sock.close()
            raise
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._run, name="afing-dhcp", daemon=True)

    def start(self) -> "DhcpListener":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(3)
        self._sock.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, _ = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue  # vd Windows báo ICMP lỗi qua recvfrom
            info = parse_packet(data)
            if info:
                try:
                    self.on_packet(info)
                except Exception:
                    log.exception("Xử lý gói DHCP lỗi")


def why_unavailable(error: OSError) -> str:
    if isinstance(error, PermissionError):
        return "cần chạy bằng sudo/quyền admin để mở cổng 67"
    return f"không mở được cổng 67 ({error.strerror or error}) - máy này đang chạy DHCP server?"
