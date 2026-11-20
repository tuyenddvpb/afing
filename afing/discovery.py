"""Nhận diện thiết bị qua các giao thức tự quảng bá: mDNS service discovery và UPnP/SSDP.

Khác với names.py (hỏi "IP này tên gì"), ở đây ta hỏi cả mạng "ai cung cấp dịch vụ gì"
rồi đọc tên thân thiện và model mà thiết bị tự khai.
"""

import concurrent.futures
import html
import re
import socket
import struct
import threading
import time
import urllib.request
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .names import MDNS_ADDR, TYPE_PTR, clean_name, read_name, resolve_names

TYPE_TXT = 16
SSDP_ADDR = ("239.255.255.250", 1900)
MAX_XML_BYTES = 512 * 1024

# (loại dịch vụ, nguồn tên, khoá TXT chứa model) - xếp theo độ tin cậy giảm dần.
# Nguồn tên: None = dùng tên instance; chuỗi = khoá TXT; False = dịch vụ này không cho tên.
SERVICES: List[Tuple[str, object, Optional[str]]] = [
    ("_googlecast._tcp.local", "fn", "md"),          # Chromecast, Google/Nest, Android TV
    ("_airplay._tcp.local", None, "model"),          # Apple TV, HomePod, TV hỗ trợ AirPlay
    ("_companion-link._tcp.local", None, None),      # iPhone, iPad, Mac
    ("_androidtvremote2._tcp.local", None, None),
    ("_amzn-wplay._tcp.local", "n", None),           # Fire TV, Echo
    ("_sonos._tcp.local", None, None),
    ("_hap._tcp.local", None, "md"),                 # thiết bị HomeKit
    ("_esphomelib._tcp.local", "friendly_name", "board"),
    ("_ipp._tcp.local", None, "ty"),                 # máy in
    ("_ipps._tcp.local", None, "ty"),
    ("_printer._tcp.local", None, "ty"),
    ("_pdl-datastream._tcp.local", None, "ty"),
    ("_raop._tcp.local", "@", "am"),                 # AirPlay audio: instance dạng "MAC@Tên"
    ("_smb._tcp.local", None, None),                 # máy tính, NAS
    ("_afpovertcp._tcp.local", None, None),
    ("_rfb._tcp.local", None, None),
    ("_sftp-ssh._tcp.local", None, None),
    ("_ssh._tcp.local", None, None),
    ("_workstation._tcp.local", "[", None),          # Linux/avahi: "tên [mac]"
    ("_device-info._tcp.local", False, "model"),
    ("_http._tcp.local", None, None),
]


# ---------- mDNS service discovery ----------

def build_browse_query(services: Iterable[str]) -> bytes:
    """Một gói hỏi PTR cho nhiều loại dịch vụ, yêu cầu trả lời unicast."""
    questions = b""
    count = 0
    for name in services:
        questions += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
        questions += struct.pack("!2H", TYPE_PTR, 0x8001)
        count += 1
    return struct.pack("!6H", 0, 0, count, 0, 0, 0) + questions


def parse_txt(rdata: bytes) -> Dict[str, str]:
    out, off = {}, 0
    while off < len(rdata):
        length = rdata[off]
        item = rdata[off + 1 : off + 1 + length].decode("utf-8", "replace")
        off += 1 + length
        key, sep, value = item.partition("=")
        if sep and key:
            out.setdefault(key.lower(), value)
    return out


def parse_mdns_packet(data: bytes) -> Tuple[List[Tuple[str, str]], Dict[str, Dict[str, str]]]:
    """Trả (các bản ghi PTR [(tên, đích)], các bản ghi TXT {tên viết thường: {khoá: giá trị}})."""
    ptrs: List[Tuple[str, str]] = []
    txts: Dict[str, Dict[str, str]] = {}
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
                ptrs.append((name, read_name(data, off)[0]))
            elif rtype == TYPE_TXT:
                txts[name.lower()] = parse_txt(data[off : off + rdlen])
            off += rdlen
    except (IndexError, struct.error, ValueError):
        pass  # gói hỏng: giữ những gì đã đọc được
    return ptrs, txts


def summarize_services(ptrs: List[Tuple[str, str]], txts: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """Chọn tên + model tốt nhất từ các dịch vụ mà MỘT thiết bị quảng bá."""
    instances: Dict[str, List[Tuple[str, Dict[str, str]]]] = {}
    for service, target in ptrs:
        service = service.lower()
        if target.lower().endswith("." + service):
            label = target[: -(len(service) + 1)]
            instances.setdefault(service, []).append((label, txts.get(target.lower(), {})))
    # _device-info thường chỉ đi kèm dưới dạng TXT, không có PTR riêng.
    for name, txt in txts.items():
        if name.endswith("._device-info._tcp.local"):
            instances.setdefault("_device-info._tcp.local", []).append(("", txt))

    name = model = None
    for service, name_src, model_key in SERVICES:
        for label, txt in instances.get(service, []):
            if not name and name_src is not False:
                if name_src is None:
                    candidate = label
                elif name_src == "@":
                    candidate = label.split("@", 1)[-1]
                elif name_src == "[":
                    candidate = label.split(" [", 1)[0]
                else:
                    candidate = txt.get(name_src)
                name = clean_name(candidate)
            if not model and model_key:
                model = clean_name(txt.get(model_key))
    return {k: v for k, v in (("name", name), ("model", model)) if v}


def service_types(ptrs: List[Tuple[str, str]]) -> List[str]:
    """Các loại dịch vụ đã biết mà thiết bị quảng bá, bỏ đuôi ".local" (vd "_ipp._tcp")."""
    known = {s[0] for s in SERVICES}
    return sorted({svc.lower()[: -len(".local")] for svc, _ in ptrs if svc.lower() in known})


def mdns_services(local_ip: str, wait: float = 3.0) -> Dict[str, Dict[str, str]]:
    """Hỏi cả mạng về các dịch vụ phổ biến. Trả {ip: {"name":..., "model":...}}."""
    per_ip: Dict[str, Tuple[list, dict]] = {}
    query = build_browse_query(s[0] for s in SERVICES)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.sendto(query, MDNS_ADDR)
        start = time.monotonic()
        resent = False
        while (left := start + wait - time.monotonic()) > 0:
            if not resent and time.monotonic() - start > 1.0:
                s.sendto(query, MDNS_ADDR)  # gói UDP multicast dễ rớt trên Wi-Fi
                resent = True
            s.settimeout(min(left, 0.5))
            try:
                data, (src, _) = s.recvfrom(9000)
            except socket.timeout:
                continue
            ptrs, txts = parse_mdns_packet(data)
            acc = per_ip.setdefault(src, ([], {}))
            acc[0].extend(ptrs)
            acc[1].update(txts)
    except OSError:
        pass
    finally:
        s.close()
    found = {}
    for ip, (ptrs, txts) in per_ip.items():
        info: dict = summarize_services(ptrs, txts)
        services = service_types(ptrs)
        if services:
            info["services"] = services
        if info:
            found[ip] = info
    return found


# ---------- UPnP / SSDP ----------

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def parse_ssdp_headers(data: bytes) -> Dict[str, str]:
    headers = {}
    for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def _xml_tag(text: str, tag: str) -> Optional[str]:
    m = re.search(rf"<{tag}>\s*([^<]*?)\s*</{tag}>", text, re.I)
    return html.unescape(m.group(1)) if m and m.group(1) else None


def parse_device_xml(text: str) -> Dict[str, str]:
    """File mô tả thiết bị UPnP -> {"name": friendlyName, "model": "hãng model"}."""
    name = clean_name(_xml_tag(text, "friendlyName"))
    maker = _xml_tag(text, "manufacturer")
    model = _xml_tag(text, "modelName")
    if model and maker and maker.lower() not in model.lower():
        model = f"{maker} {model}"
    model = clean_name(model or maker)
    return {k: v for k, v in (("name", name), ("model", model)) if v}


def safe_location(location: str, src_ip: str) -> bool:
    """Chỉ tải mô tả từ chính thiết bị vừa trả lời, qua http - không theo URL trỏ đi nơi khác."""
    try:
        parts = urlsplit(location)
    except ValueError:
        return False
    return parts.scheme == "http" and parts.hostname == src_ip


def _fetch_description(location: str) -> Dict[str, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # không qua proxy
    try:
        with opener.open(location, timeout=2) as resp:
            text = resp.read(MAX_XML_BYTES).decode("utf-8", "replace")
    except (OSError, ValueError):
        return {}
    info: dict = parse_device_xml(text)
    upnp_type = parse_upnp_type(text)
    if upnp_type:
        info["upnp_type"] = upnp_type
    return info


def parse_upnp_type(text: str) -> Optional[str]:
    """"urn:schemas-upnp-org:device:MediaRenderer:1" -> "MediaRenderer"."""
    m = re.search(r"<deviceType>[^<]*:device:([^:<]+)", text, re.I)
    return m.group(1).strip() if m else None


def ssdp_discover(local_ip: str, wait: float = 3.0) -> Dict[str, Dict[str, str]]:
    """Gửi M-SEARCH rồi tải file mô tả của từng thiết bị trả lời. Trả {ip: {...}}."""
    locations: Dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.sendto(MSEARCH, SSDP_ADDR)
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            data, (src, _) = s.recvfrom(4096)
            headers = parse_ssdp_headers(data)
            location = headers.get("location", "")
            if not safe_location(location, src):
                continue
            if src not in locations or headers.get("st") == "upnp:rootdevice":
                locations[src] = location
    except OSError:
        pass  # hết thời gian chờ hoặc mạng không cho multicast
    finally:
        s.close()
    if not locations:
        return {}

    found = {}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futures = {pool.submit(_fetch_description, loc): ip for ip, loc in locations.items()}
    done, _ = concurrent.futures.wait(futures, timeout=4)
    for fut in done:
        info = fut.result()
        if info:
            found[futures[fut]] = info
    pool.shutdown(wait=False, cancel_futures=True)
    return found


# ---------- Tổng hợp ----------

def identify(ips: Iterable[str], local_ip: str) -> Dict[str, Dict[str, str]]:
    """Chạy song song mọi nguồn. Trả {ip: {"name", "model", "services", "upnp_type", "sources"}}
    (thiếu khoá nếu không rõ).

    Ưu tiên tên: dịch vụ mDNS > UPnP friendlyName > tên máy (rDNS/mDNS/NetBIOS).
    Kết quả có thể gồm cả IP ngoài `ips`, vì mDNS/SSDP hỏi cả mạng.
    """
    ips = list(ips)
    results: Dict[str, dict] = {}
    sources: Dict[str, set] = {}

    def worker(key, fn, *args):
        try:
            results[key] = fn(*args)
        except Exception:
            results[key] = {}

    threads = [
        threading.Thread(target=worker, args=("host", resolve_names, ips, local_ip, sources),
                         daemon=True),
        threading.Thread(target=worker, args=("mdns", mdns_services, local_ip), daemon=True),
        threading.Thread(target=worker, args=("ssdp", ssdp_discover, local_ip), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    mdns, ssdp, host = (results.get(k, {}) for k in ("mdns", "ssdp", "host"))
    merged = {}
    for ip in set(mdns) | set(ssdp) | set(host):
        m, u = mdns.get(ip, {}), ssdp.get(ip, {})
        info = {
            "name": m.get("name") or u.get("name") or host.get(ip),
            "model": m.get("model") or u.get("model"),
            "services": m.get("services"),
            "upnp_type": u.get("upnp_type"),
            "sources": sources.get(ip),
        }
        merged[ip] = {k: v for k, v in info.items() if v}
    return merged
