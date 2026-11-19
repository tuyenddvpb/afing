"""Tìm tên thiết bị từ IP bằng 3 nguồn: reverse DNS (router), mDNS/Bonjour, NetBIOS."""

import concurrent.futures
import re
import socket
import struct
import threading
import time
from typing import Dict, Iterable, List, Optional, Tuple

MDNS_ADDR = ("224.0.0.251", 5353)
TYPE_PTR = 12


def clean_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().rstrip(".")
    for suffix in (".local", ".lan", ".home", ".localdomain"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return name[:80] or None


# ---------- DNS wire format (dùng cho mDNS) ----------

def build_query(name: str, qtype: int = TYPE_PTR, unicast_reply: bool = False) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"
    qclass = 1 | (0x8000 if unicast_reply else 0)
    return struct.pack("!6H", 0, 0, 1, 0, 0, 0) + labels + struct.pack("!2H", qtype, qclass)


def read_name(data: bytes, off: int) -> Tuple[str, int]:
    """Đọc tên DNS (có nén con trỏ). Trả (tên, offset ngay sau tên tại vị trí gốc)."""
    labels, end, hops = [], None, 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("vòng lặp con trỏ DNS")
            continue
        labels.append(data[off + 1 : off + 1 + length].decode("utf-8", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def parse_ptr_records(data: bytes) -> List[Tuple[str, str]]:
    """Trả danh sách (tên được hỏi, tên đích) của mọi bản ghi PTR trong gói trả lời."""
    out = []
    try:
        _, _, qd, an, ns, ar = struct.unpack("!6H", data[:12])
        off = 12
        for _ in range(qd):
            _, off = read_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = read_name(data, off)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[off : off + 10])
            off += 10
            if rtype == TYPE_PTR:
                out.append((name, read_name(data, off)[0]))
            off += rdlen
    except (IndexError, struct.error, ValueError):
        pass  # gói hỏng: giữ những gì đã đọc được
    return out


def _reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def mdns_lookup(ips: Iterable[str], local_ip: str, wait: float = 1.5) -> Dict[str, str]:
    wanted = {_reverse_name(ip).lower(): ip for ip in ips}
    found: Dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        for rname in wanted:
            s.sendto(build_query(rname, unicast_reply=True), MDNS_ADDR)
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            data, _ = s.recvfrom(4096)
            for name, target in parse_ptr_records(data):
                ip = wanted.get(name.lower())
                if ip and target:
                    found[ip] = target
    except OSError:
        pass  # hết thời gian chờ hoặc mạng không cho multicast
    finally:
        s.close()
    return found


# ---------- NetBIOS (máy Windows, NAS, máy in...) ----------

NBSTAT_QUERY = (
    struct.pack("!6H", 0x4146, 0, 1, 0, 0, 0)
    + b"\x20CK" + b"A" * 30 + b"\0"   # tên "*" mã hoá kiểu NetBIOS
    + struct.pack("!2H", 0x21, 1)     # NBSTAT, IN
)


def parse_nbstat(data: bytes) -> Optional[str]:
    try:
        off = 12
        while data[off]:
            off += 1 + data[off]
        off += 1 + 10  # byte kết thúc tên + type, class, ttl, rdlength
        count = data[off]
        off += 1
        fallback = None
        for i in range(count):
            entry = data[off + 18 * i : off + 18 * (i + 1)]
            if len(entry) < 18:
                break
            name = entry[:15].decode("ascii", "ignore").strip()
            suffix, flags = entry[15], struct.unpack("!H", entry[16:18])[0]
            if flags & 0x8000 or not name:  # tên nhóm (workgroup), không phải tên máy
                continue
            if suffix == 0x00:
                return name
            if suffix == 0x20:
                fallback = name
        return fallback
    except IndexError:
        return None


def netbios_lookup(ips: Iterable[str], wait: float = 1.5) -> Dict[str, str]:
    found: Dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for ip in ips:
            try:
                s.sendto(NBSTAT_QUERY, (ip, 137))
            except OSError:
                pass
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                data, (src, _) = s.recvfrom(2048)
            except ConnectionError:
                continue  # Windows báo ICMP "port unreachable" qua recvfrom
            name = parse_nbstat(data)
            if name:
                found[src] = name
    except OSError:
        pass
    finally:
        s.close()
    return found


# ---------- Reverse DNS ----------

def rdns_lookup(ips: Iterable[str], wait: float = 3.0) -> Dict[str, str]:
    ips = list(ips)
    found: Dict[str, str] = {}
    if not ips:
        return found

    def one(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(ips)))
    futures = {pool.submit(one, ip): ip for ip in ips}
    done, _ = concurrent.futures.wait(futures, timeout=wait)
    for fut in done:
        name, ip = fut.result(), futures[fut]
        if name and name != ip and not name.endswith(".in-addr.arpa"):
            found[ip] = name
    pool.shutdown(wait=False, cancel_futures=True)
    return found


def resolve_names(ips: Iterable[str], local_ip: str) -> Dict[str, str]:
    """Chạy song song cả 3 nguồn; ưu tiên rDNS > mDNS > NetBIOS."""
    ips = list(ips)
    if not ips:
        return {}
    results: Dict[str, Dict[str, str]] = {}

    def worker(key, fn, *args):
        try:
            results[key] = fn(*args)
        except Exception:
            results[key] = {}

    threads = [
        threading.Thread(target=worker, args=("rdns", rdns_lookup, ips), daemon=True),
        threading.Thread(target=worker, args=("mdns", mdns_lookup, ips, local_ip), daemon=True),
        threading.Thread(target=worker, args=("nb", netbios_lookup, ips), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    names = {}
    for ip in ips:
        for key in ("rdns", "mdns", "nb"):
            name = clean_name(results.get(key, {}).get(ip))
            if name:
                names[ip] = name
                break
    return names
