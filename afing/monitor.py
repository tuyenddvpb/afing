"""Vòng lặp quét liên tục: quét -> ghi DB -> dò tên thiết bị."""

import logging
import threading
import time
from typing import Dict, Optional

from .classify import classify
from .db import Database
from .discovery import identify
from .netinfo import NetInfo
from .oui import OuiTable
from .scanner import Scanner

log = logging.getLogger("afing.monitor")

RETRY_UNNAMED = 5 * 60   # thiết bị chưa có tên: thử dò lại sau 5 phút
REFRESH_NAMED = 60 * 60  # thiết bị đã có tên: làm mới sau 1 giờ

EVENT_LABELS = {
    "new": "Thiết bị MỚI",
    "online": "Kết nối lại",
    "offline": "Rời mạng",
    "ip_change": "Đổi IP",
}


def describe(info: dict, vendor: Optional[str], is_gateway: bool,
             dhcp: Optional[dict] = None) -> dict:
    """Gộp kết quả dò của một thiết bị với thông tin DHCP và loại + hệ điều hành suy đoán."""
    name, rank = info.get("name"), info.get("name_rank") or 1
    dhcp_name = (dhcp or {}).get("hostname")
    if dhcp_name and (not name or rank < 2):
        name, rank = dhcp_name, 2  # tên máy tự khai qua DHCP tốt hơn tên tra qua DNS/NetBIOS
    type_, os_ = classify(
        vendor=vendor, name=name, model=info.get("model"),
        services=info.get("services") or (), upnp_type=info.get("upnp_type"),
        sources=info.get("sources") or (), is_gateway=is_gateway, dhcp=dhcp,
    )
    return {"name": name, "name_rank": rank if name else None, "model": info.get("model"),
            "type": type_, "os": os_}


class Monitor:
    def __init__(self, net: NetInfo, scanner: Scanner, db: Database, oui: OuiTable,
                 interval: int = 10, offline_after: int = 45):
        self.net, self.scanner, self.db, self.oui = net, scanner, db, oui
        self.interval = interval
        self.offline_after = max(offline_after, interval * 2)
        self._stop = threading.Event()
        self.notifier = None  # notify.Notifier, gán từ ngoài nếu dùng thông báo
        self._name_due: Dict[str, float] = {}
        self._dhcp_fresh: set = set()  # MAC vừa có gói DHCP mới, cần nhận diện lại ngay
        self.status = {
            "network": str(net.network),
            "local_ip": net.ip,
            "gateway": net.gateway,
            "method": scanner.method,
            "interval": interval,
            "last_scan": None,
            "scan_seconds": None,
            "scan_count": 0,
            "error": None,
            "dhcp": False,
            "dhcp_packets": 0,
            "notify": [],
        }

    def on_dhcp(self, info: dict) -> None:
        """Gọi từ luồng nghe DHCP cho mỗi gói client."""
        self.db.record_dhcp(info, int(time.time()))
        self._dhcp_fresh.add(info["mac"])
        self.status["dhcp_packets"] += 1
        log.info("%-12s %-15s %s %s", "DHCP " + info["type"], info["requested_ip"] or "?",
                 info["mac"], " | ".join(filter(None, (info["hostname"], info["vendor_class"]))))

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.run, name="afing-monitor", daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.scan_once()
                self.status["error"] = None
            except Exception as e:
                log.exception("Lượt quét lỗi")
                self.status["error"] = str(e)
            self._stop.wait(max(1.0, self.interval - (time.monotonic() - started)))

    def scan_once(self) -> Dict[str, str]:
        started = time.monotonic()
        seen = self.scanner.scan()
        now = int(time.time())
        events = self.db.apply_scan(
            seen, now, self.offline_after,
            vendor_lookup=self.oui.lookup, self_mac=self.net.mac, gateway_ip=self.net.gateway,
        )
        for ev in events:
            log.info("%-12s %-15s %s %s", EVENT_LABELS[ev["type"]], ev["ip"], ev["mac"],
                     ev["detail"] or "")
        self.status.update(
            method=self.scanner.method,
            last_scan=now,
            scan_seconds=round(time.monotonic() - started, 2),
            scan_count=self.status["scan_count"] + 1,
        )
        self._resolve_names(seen)
        if self.notifier:  # sau khi dò tên, để thông báo có tên/loại thiết bị
            try:
                self.status["notify"] = self.notifier.active_channels()
                self.notifier.process(events, now, str(self.net.network))
            except Exception:
                log.exception("Xử lý thông báo lỗi")
        return seen

    def _resolve_names(self, seen: Dict[str, str]) -> None:
        mono = time.monotonic()
        fresh, self._dhcp_fresh = self._dhcp_fresh, set()
        due = {ip: mac for ip, mac in seen.items()
               if mac in fresh or self._name_due.get(mac, 0) <= mono}
        self._dhcp_fresh |= fresh - set(due.values())  # thiết bị chưa hiện trong lượt quét này
        if not due:
            return
        found = identify(due.keys(), self.net.ip)
        dhcp = self.db.dhcp_clients()
        # mDNS/SSDP hỏi cả mạng nên kết quả có thể gồm cả thiết bị chưa tới hạn dò.
        updates = {}
        for ip in set(due) | (set(found) & set(seen)):
            mac = seen[ip]
            updates[mac] = describe(found.get(ip, {}), self.oui.lookup(mac),
                                    ip == self.net.gateway, dhcp.get(mac))
        self.db.set_identities(updates)
        for ip, mac in due.items():
            self._name_due[mac] = mono + (REFRESH_NAMED if updates[mac]["name"] else RETRY_UNNAMED)
