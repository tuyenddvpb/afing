"""Lưu thiết bị và lịch sử sự kiện vào SQLite."""

import sqlite3
import threading
from typing import Callable, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    hostname    TEXT,             -- tên tự dò được (DNS/mDNS/NetBIOS)
    custom_name TEXT,             -- tên do người dùng đặt trên web
    vendor      TEXT,
    is_online   INTEGER NOT NULL DEFAULT 1,
    is_self     INTEGER NOT NULL DEFAULT 0,
    is_gateway  INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL, -- epoch giây
    last_seen   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    mac    TEXT NOT NULL,
    type   TEXT NOT NULL,         -- new | online | offline | ip_change
    ip     TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class Database:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def apply_scan(
        self,
        seen: Dict[str, str],
        now: int,
        offline_after: int,
        vendor_lookup: Optional[Callable[[str], Optional[str]]] = None,
        self_mac: Optional[str] = None,
        gateway_ip: Optional[str] = None,
    ) -> List[dict]:
        """Ghi kết quả một lượt quét ({ip: mac}). Trả về các sự kiện vừa phát sinh."""
        events: List[dict] = []

        def emit(mac, type_, ip, detail=None):
            events.append({"ts": now, "mac": mac, "type": type_, "ip": ip, "detail": detail})

        with self._lock, self._conn:
            c = self._conn
            known = {r["mac"]: r for r in c.execute("SELECT * FROM devices")}
            by_mac = {mac: ip for ip, mac in seen.items()}  # 1 MAC nhiều IP: giữ 1 IP
            for mac, ip in by_mac.items():
                vendor = vendor_lookup(mac) if vendor_lookup else None
                flags = (int(mac == self_mac), int(ip == gateway_ip))
                old = known.get(mac)
                if old is None:
                    c.execute(
                        "INSERT INTO devices (mac, ip, vendor, is_online, is_self, is_gateway,"
                        " first_seen, last_seen) VALUES (?,?,?,1,?,?,?,?)",
                        (mac, ip, vendor, *flags, now, now),
                    )
                    emit(mac, "new", ip)
                    continue
                if old["ip"] != ip:
                    emit(mac, "ip_change", ip, f"{old['ip']} → {ip}")
                if not old["is_online"]:
                    emit(mac, "online", ip)
                c.execute(
                    "UPDATE devices SET ip=?, vendor=COALESCE(vendor, ?), is_online=1,"
                    " is_self=?, is_gateway=?, last_seen=? WHERE mac=?",
                    (ip, vendor, *flags, now, mac),
                )
            gone = c.execute(
                "SELECT mac, ip FROM devices WHERE is_online=1 AND last_seen < ?",
                (now - offline_after,),
            ).fetchall()
            for row in gone:
                c.execute("UPDATE devices SET is_online=0 WHERE mac=?", (row["mac"],))
                emit(row["mac"], "offline", row["ip"])
            c.executemany(
                "INSERT INTO events (ts, mac, type, ip, detail) VALUES (:ts,:mac,:type,:ip,:detail)",
                events,
            )
        return events

    def set_hostnames(self, names_by_mac: Dict[str, str]) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "UPDATE devices SET hostname=? WHERE mac=?",
                [(name, mac) for mac, name in names_by_mac.items()],
            )

    def set_custom_name(self, mac: str, name: Optional[str]) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE devices SET custom_name=? WHERE mac=?", (name or None, mac)
            )
            return cur.rowcount > 0

    def devices(self) -> List[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM devices").fetchall()
        return [dict(r) for r in rows]

    def events(self, limit: int = 50) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.*, COALESCE(d.custom_name, d.hostname) AS name, d.vendor AS vendor"
                " FROM events e LEFT JOIN devices d ON d.mac = e.mac"
                " ORDER BY e.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
