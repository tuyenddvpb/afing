"""Tự dò thông tin mạng của máy đang chạy: IP, subnet, gateway, MAC."""

import ipaddress
import os
import platform
import re
import socket
import struct
import subprocess
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

SYSTEM = platform.system()  # "Linux", "Darwin", "Windows"
IP_RE = r"(\d{1,3}(?:\.\d{1,3}){3})"
# Subnet lớn hơn mức này sẽ bị thu về /24 quanh IP của máy (trừ khi chỉ định --subnet).
MIN_AUTO_PREFIX = 22


@dataclass
class NetInfo:
    network: ipaddress.IPv4Network
    ip: str
    mac: Optional[str] = None
    gateway: Optional[str] = None
    iface: Optional[str] = None


def run(cmd, timeout=5) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, text=True, errors="replace"
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def local_ip(target: str = "192.0.2.1") -> str:
    """IP nguồn mà hệ điều hành sẽ dùng để đi tới `target` (không gửi gói nào)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def parse_prefix_linux(text: str, ip: str) -> Tuple[Optional[int], Optional[str]]:
    """Đầu ra `ip -o -4 addr show` -> (prefix, tên card mạng)."""
    for line in text.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+" + re.escape(ip) + r"/(\d+)", line)
        if m:
            return int(m.group(2)), m.group(1)
    return None, None


def _mask_to_prefix(mask: str) -> Optional[int]:
    try:
        if mask.lower().startswith("0x"):
            mask = str(ipaddress.IPv4Address(int(mask, 16)))
        return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    except ValueError:
        return None


def parse_mask_ifconfig(text: str, ip: str) -> Optional[int]:
    """Đầu ra `ifconfig` (macOS/BSD) -> prefix."""
    m = re.search(r"inet\s+" + re.escape(ip) + r"\s+netmask\s+(\S+)", text)
    return _mask_to_prefix(m.group(1)) if m else None


def parse_mask_ipconfig(text: str, ip: str) -> Optional[int]:
    """Đầu ra `ipconfig` (Windows, mọi ngôn ngữ): mask nằm ở dòng ngay sau dòng IP."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])", line):
            for nxt in lines[i + 1 : i + 3]:
                m = re.search(IP_RE, nxt)
                if m:
                    prefix = _mask_to_prefix(m.group(1))
                    if prefix:
                        return prefix
    return None


def parse_gateway(text: str, system: str) -> Optional[str]:
    if system == "Linux":
        m = re.search(r"default via " + IP_RE, text)
    elif system == "Windows":
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+" + IP_RE, text, re.M)
    else:
        m = re.search(r"gateway:\s*" + IP_RE, text)
    return m.group(1) if m else None


def _linux_ioctl_info(ip: str) -> Tuple[Optional[int], Optional[str]]:
    """Linux không có lệnh `ip`: hỏi thẳng kernel -> (prefix, tên card mạng)."""
    try:
        import fcntl
        ifaces = os.listdir("/sys/class/net")
    except (ImportError, OSError):
        return None, None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for iface in ifaces:
            req = struct.pack("256s", iface.encode()[:15])
            try:
                addr = socket.inet_ntoa(fcntl.ioctl(s, 0x8915, req)[20:24])  # SIOCGIFADDR
                if addr == ip:
                    mask = socket.inet_ntoa(fcntl.ioctl(s, 0x891B, req)[20:24])  # SIOCGIFNETMASK
                    return _mask_to_prefix(mask), iface
            except OSError:
                continue
    finally:
        s.close()
    return None, None


def parse_proc_route(text: str) -> Optional[str]:
    """Nội dung /proc/net/route -> IP gateway mặc định."""
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and cols[1] == "00000000" and int(cols[3], 16) & 0x2:
            return socket.inet_ntoa(struct.pack("<L", int(cols[2], 16)))
    return None


def _gateway() -> Optional[str]:
    if SYSTEM == "Linux":
        out = run(["ip", "-4", "route", "show", "default"])
        if not out:
            try:
                with open("/proc/net/route") as f:
                    return parse_proc_route(f.read())
            except OSError:
                return None
    elif SYSTEM == "Windows":
        out = run(["route", "print", "-4", "0.0.0.0"])
    else:
        out = run(["route", "-n", "get", "default"])
    return parse_gateway(out, SYSTEM)


def _own_mac(iface: Optional[str]) -> Optional[str]:
    if iface:
        try:
            with open(f"/sys/class/net/{iface}/address") as f:
                mac = f.read().strip().lower()
            if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) and mac != "00:00:00:00:00:00":
                return mac
        except OSError:
            pass
    node = uuid.getnode()
    if (node >> 40) & 1:  # uuid tự bịa MAC ngẫu nhiên khi không đọc được MAC thật
        return None
    return ":".join(f"{(node >> s) & 0xFF:02x}" for s in range(40, -1, -8))


def detect(subnet: Optional[str] = None) -> NetInfo:
    """Dò mạng hiện tại. `subnet` (vd "192.168.1.0/24") ghi đè phần tự dò."""
    forced = ipaddress.ip_network(subnet, strict=False) if subnet else None
    try:
        ip = local_ip(str(forced.network_address + 1)) if forced else local_ip()
    except OSError as e:
        raise RuntimeError(
            "Không xác định được IP của máy (chưa kết nối mạng?). "
            "Hãy chỉ định subnet bằng --subnet, ví dụ --subnet 192.168.1.0/24"
        ) from e

    prefix, iface = None, None
    if SYSTEM == "Linux":
        prefix, iface = parse_prefix_linux(run(["ip", "-o", "-4", "addr", "show"]), ip)
        if iface is None:
            prefix, iface = _linux_ioctl_info(ip)
    elif SYSTEM == "Windows":
        prefix = parse_mask_ipconfig(run(["ipconfig"]), ip)
    else:
        prefix = parse_mask_ifconfig(run(["ifconfig"]), ip)

    if forced:
        network = forced
    else:
        if prefix is None or prefix < MIN_AUTO_PREFIX or prefix > 30:
            prefix = 24
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)

    return NetInfo(network=network, ip=ip, mac=_own_mac(iface), gateway=_gateway(), iface=iface)
