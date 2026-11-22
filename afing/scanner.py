"""Quét thiết bị trong subnet -> {ip: mac}.

Hai cách:
- "arp":     ARP scan chủ động bằng scapy (cần `pip install scapy` + quyền root/admin).
             Chính xác nhất: thiết bị rời mạng được phát hiện ngay ở lượt quét kế tiếp.
- "passive": không cần thư viện hay quyền đặc biệt. Gửi 1 gói UDP rỗng tới mọi IP để
             hệ điều hành tự phân giải ARP, sau đó đọc bảng ARP của hệ điều hành.
"""

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import struct
import time
from typing import Dict, Optional

from .netinfo import SYSTEM, NetInfo, run

log = logging.getLogger("afing.scanner")

_MAC = r"[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}"
_DEAD_STATES = {"FAILED", "INCOMPLETE", "NONE"}


def norm_mac(raw: str) -> Optional[str]:
    """Chuẩn hoá về dạng aa:bb:cc:dd:ee:ff; trả None nếu không phải MAC của một thiết bị."""
    parts = re.split(r"[:-]", raw.strip())
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if octets[0] & 1 or not any(octets):  # broadcast/multicast hoặc toàn 0
        return None
    return ":".join(f"{o:02x}" for o in octets)


def parse_ip_neigh(text: str) -> Dict[str, str]:
    """Đầu ra `ip -4 neigh show` (Linux)."""
    found = {}
    for line in text.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s.*lladdr\s+(" + _MAC + r")\s.*?(\w+)\s*$", line)
        if m and m.group(3) not in _DEAD_STATES:
            mac = norm_mac(m.group(2))
            if mac:
                found[m.group(1)] = mac
    return found


def parse_proc_arp(text: str) -> Dict[str, str]:
    """Nội dung /proc/net/arp (Linux, dự phòng khi không có lệnh `ip`)."""
    found = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and int(cols[2], 16) & 0x2:  # cờ ATF_COM: đã phân giải xong
            mac = norm_mac(cols[3])
            if mac:
                found[cols[0]] = mac
    return found


def parse_arp_a(text: str) -> Dict[str, str]:
    """Đầu ra `arp -a` của Windows và `arp -an` của macOS/BSD."""
    found = {}
    pattern = r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?(" + _MAC + r")(?![0-9a-fA-F:-])"
    for m in re.finditer(pattern, text):
        mac = norm_mac(m.group(2))
        if mac:
            found[m.group(1)] = mac
    return found


def read_arp_table() -> Dict[str, str]:
    if SYSTEM == "Linux":
        out = run(["ip", "-4", "neigh", "show"])
        if out:
            return parse_ip_neigh(out)
        try:
            with open("/proc/net/arp") as f:
                return parse_proc_arp(f.read())
        except OSError:
            return {}
    return parse_arp_a(run(["arp", "-a"] if SYSTEM == "Windows" else ["arp", "-an"]))


def poke(network: ipaddress.IPv4Network, skip_ip: str) -> None:
    """Gửi 1 gói UDP rỗng (cổng discard) tới mọi host để kích hoạt phân giải ARP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for n, host in enumerate(network.hosts()):
            if str(host) == skip_ip:
                continue
            try:
                s.sendto(b"\0", (str(host), 9))
            except OSError:
                pass
            if n % 64 == 63:
                time.sleep(0.02)  # tránh tràn hàng đợi ARP của kernel
    finally:
        s.close()


def send_arp(ip: str) -> Optional[str]:
    """Windows: gửi một yêu cầu ARP thật tới `ip` (hàm SendARP của hệ điều hành, không cần quyền
    admin hay Npcap). Trả MAC nếu thiết bị trả lời, None nếu không. Có thể mất vài giây khi
    thiết bị không còn trong mạng."""
    import ctypes
    dest = struct.unpack("<L", socket.inet_aton(ip))[0]
    buf = (ctypes.c_ubyte * 6)()
    size = ctypes.c_ulong(6)
    rc = ctypes.windll.iphlpapi.SendARP(ctypes.c_ulong(dest), ctypes.c_ulong(0),
                                        ctypes.byref(buf), ctypes.byref(size))
    if rc != 0 or size.value != 6:
        return None
    return norm_mac(":".join(f"{b:02x}" for b in buf))


def confirm_present(candidates: Dict[str, str], probe=None) -> Dict[str, str]:
    """Lọc bảng ARP của Windows: chỉ giữ thiết bị còn trả lời ARP ngay lúc này.

    Bảng ARP của Windows giữ thiết bị đã rời mạng thêm nhiều phút; hỏi lại từng địa chỉ giúp phát
    hiện rời mạng ngay ở lượt quét kế tiếp. Các địa chỉ được hỏi song song.
    """
    probe = probe or send_arp
    if not candidates:
        return {}
    present: Dict[str, str] = {}

    def check(ip):
        try:
            return ip, probe(ip)
        except Exception:
            return ip, candidates[ip]  # không hỏi được (thiếu API?): tin bảng ARP như trước

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(candidates))) as pool:
        for ip, mac in pool.map(check, candidates):
            if mac:
                present[ip] = mac
    return present


class Scanner:
    def __init__(self, net: NetInfo, method: str = "auto"):
        self.net = net
        self.method = "passive"
        if method in ("auto", "arp"):
            reason = self._scapy_unavailable()
            if reason is None:
                self.method = "arp"
            elif method == "arp":
                raise RuntimeError(f"Không dùng được ARP scan: {reason}")
            else:
                log.info("Dùng chế độ passive (%s)", reason)

    @staticmethod
    def _scapy_unavailable() -> Optional[str]:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return "không có quyền root"
        try:
            import scapy.all  # noqa: F401
        except Exception:
            return "chưa cài scapy"
        return None

    def scan(self) -> Dict[str, str]:
        if self.method == "arp":
            try:
                found = self._scan_arp()
            except Exception as e:  # thiếu Npcap, card mạng không hỗ trợ...
                log.warning("ARP scan lỗi (%s) - chuyển sang chế độ passive", e)
                self.method = "passive"
                found = self._scan_passive()
        else:
            found = self._scan_passive()
        if self.net.mac:
            found[self.net.ip] = self.net.mac  # máy đang quét không có trong bảng ARP của chính nó
        return found

    def _scan_arp(self) -> Dict[str, str]:
        from scapy.all import ARP, Ether, srp

        kwargs = {"iface": self.net.iface} if self.net.iface else {}
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.net.network)),
            timeout=2, retry=1, verbose=0, **kwargs,
        )
        found = {}
        for _, reply in answered:
            mac = norm_mac(reply.hwsrc)
            if mac:
                found[reply.psrc] = mac
        return found

    def _scan_passive(self) -> Dict[str, str]:
        poke(self.net.network, self.net.ip)
        time.sleep(1.0)
        poke(self.net.network, self.net.ip)
        time.sleep(0.5)
        network = self.net.network
        found = {
            ip: mac
            for ip, mac in read_arp_table().items()
            if ipaddress.ip_address(ip) in network
        }
        if SYSTEM == "Windows":
            found = confirm_present(found)
        return found
