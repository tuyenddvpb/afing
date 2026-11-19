"""Vòng lặp quét liên tục: quét -> ghi DB -> dò tên thiết bị."""

import logging
import threading
import time
from typing import Dict, Optional

from .db import Database
from .names import resolve_names
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


class Monitor:
    def __init__(self, net: NetInfo, scanner: Scanner, db: Database, oui: OuiTable,
                 interval: int = 10, offline_after: int = 45):
        self.net, self.scanner, self.db, self.oui = net, scanner, db, oui
        self.interval = interval
        self.offline_after = max(offline_after, interval * 2)
        self._stop = threading.Event()
        self._name_due: Dict[str, float] = {}
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
        }

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
        return seen

    def _resolve_names(self, seen: Dict[str, str]) -> None:
        mono = time.monotonic()
        due = {ip: mac for ip, mac in seen.items() if self._name_due.get(mac, 0) <= mono}
        if not due:
            return
        names = resolve_names(due.keys(), self.net.ip)
        self.db.set_hostnames({due[ip]: name for ip, name in names.items()})
        for ip, mac in due.items():
            self._name_due[mac] = mono + (REFRESH_NAMED if ip in names else RETRY_UNNAMED)
