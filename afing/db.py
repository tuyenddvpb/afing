"""Lưu thiết bị và lịch sử sự kiện vào SQLite."""

import sqlite3
import threading

from . import alias
from .oui import LEGACY_RANDOM_MAC, RANDOM_MAC
from typing import Callable, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    hostname    TEXT,             -- tên tự dò được (DNS/mDNS/NetBIOS)
    custom_name TEXT,             -- tên do người dùng đặt trên web
    alias       TEXT,             -- bí danh tự gán (loài vật), cố định theo MAC
    vendor      TEXT,
    model       TEXT,             -- model thiết bị tự khai (mDNS/UPnP)
    device_type TEXT,             -- mã loại suy đoán (xem classify.TYPES)
    os          TEXT,             -- hệ điều hành suy đoán
    name_rank   INTEGER,          -- độ tin cậy của hostname: 3 mDNS/UPnP, 2 DHCP, 1 DNS/NetBIOS
    custom_type TEXT,             -- loại do người dùng chọn (ưu tiên hơn device_type)
    known       INTEGER NOT NULL DEFAULT 0,  -- 1 = người dùng đã xác nhận là thiết bị quen
    person      TEXT,             -- thiết bị này của ai (để biết ai đang ở nhà)
    notes       TEXT,
    alert       TEXT,             -- NULL = theo thiết lập chung | 'always' | 'never'
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
CREATE TABLE IF NOT EXISTS state (     -- vài giá trị trạng thái nhỏ (vd tắt thông báo tới lúc nào)
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS dhcp_clients (  -- thông tin nghe được từ gói DHCP, theo MAC
    mac          TEXT PRIMARY KEY,
    hostname     TEXT,
    vendor_class TEXT,
    fingerprint  TEXT,
    last_seen    INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            columns = {r["name"] for r in self._conn.execute("PRAGMA table_info(devices)")}
            for column, kind in (("model", "TEXT"), ("device_type", "TEXT"), ("os", "TEXT"),
                                 ("name_rank", "INTEGER"), ("alias", "TEXT"),
                                 ("custom_type", "TEXT"), ("known", "INTEGER NOT NULL DEFAULT 0"),
                                 ("person", "TEXT"), ("notes", "TEXT"),
                                 ("alert", "TEXT")):  # DB tạo từ bản cũ
                if column not in columns:
                    self._conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {kind}")
            self._migrate_labels()
            self._backfill_aliases()
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_alias ON devices(alias)")

    def _migrate_labels(self) -> None:
        """Đổi các nhãn tiếng Việt mà bản cũ đã lưu (bí danh, "MAC ngẫu nhiên") sang nhãn hiện tại."""
        self._conn.execute("UPDATE devices SET vendor=? WHERE vendor=?",
                           (RANDOM_MAC, LEGACY_RANDOM_MAC))
        for r in self._conn.execute("SELECT mac, alias FROM devices").fetchall():
            new = alias.from_legacy(r["alias"])
            if new:
                self._conn.execute("UPDATE devices SET alias=? WHERE mac=?", (new, r["mac"]))

    def _backfill_aliases(self) -> None:
        """Gán bí danh cho các thiết bị chưa có (DB tạo từ bản cũ), theo thứ tự xuất hiện."""
        rows = self._conn.execute("SELECT mac, alias FROM devices ORDER BY first_seen, mac").fetchall()
        used = set()
        for r in rows:
            # Chưa có bí danh, hoặc trùng với thiết bị xuất hiện trước nó: gán con vật mới.
            if not r["alias"] or r["alias"] in used:
                taken = used | {x["alias"] for x in rows if x["alias"]}
                name = alias.pick(r["mac"], taken)
                self._conn.execute("UPDATE devices SET alias=? WHERE mac=?", (name, r["mac"]))
                used.add(name)
            else:
                used.add(r["alias"])

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
            aliases = {r["alias"] for r in known.values()}
            by_mac = {mac: ip for ip, mac in seen.items()}  # 1 MAC nhiều IP: giữ 1 IP
            for mac, ip in by_mac.items():
                vendor = vendor_lookup(mac) if vendor_lookup else None
                flags = (int(mac == self_mac), int(ip == gateway_ip))
                old = known.get(mac)
                if old is None:
                    name = alias.pick(mac, aliases)
                    aliases.add(name)
                    c.execute(
                        "INSERT INTO devices (mac, ip, vendor, alias, is_online, is_self,"
                        " is_gateway, first_seen, last_seen) VALUES (?,?,?,?,1,?,?,?,?)",
                        (mac, ip, vendor, name, *flags, now, now),
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

    def set_identities(self, info_by_mac: Dict[str, dict]) -> None:
        """Ghi {mac: {"name", "name_rank", "model", "type", "os"}} vừa dò được.

        Thiếu khoá thì giữ giá trị cũ. Tên chỉ bị thay khi tên mới đáng tin bằng hoặc hơn tên cũ,
        để tên tốt (vd từ mDNS) không bị tên kém hơn ghi đè ở lượt dò mà mDNS không trả lời.
        """
        with self._lock, self._conn:
            self._conn.executemany(
                "UPDATE devices SET"
                " hostname=CASE WHEN :ok THEN :name ELSE hostname END,"
                " name_rank=CASE WHEN :ok THEN :rank ELSE name_rank END,"
                " model=COALESCE(:model, model), device_type=COALESCE(:type, device_type),"
                " os=COALESCE(:os, os) WHERE mac=:mac"
                .replace(":ok", "(:name IS NOT NULL AND :rank >= COALESCE(name_rank, 0))"),
                [{"name": i.get("name"), "rank": i.get("name_rank") or 1, "model": i.get("model"),
                  "type": i.get("type"), "os": i.get("os"), "mac": mac}
                 for mac, i in info_by_mac.items()],
            )

    def record_dhcp(self, info: dict, now: int) -> None:
        """Lưu thông tin từ một gói DHCP; gói sau thiếu trường nào thì giữ giá trị cũ của trường đó."""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO dhcp_clients (mac, hostname, vendor_class, fingerprint, last_seen)"
                " VALUES (:mac, :hostname, :vendor_class, :fingerprint, :now)"
                " ON CONFLICT(mac) DO UPDATE SET"
                " hostname=COALESCE(excluded.hostname, hostname),"
                " vendor_class=COALESCE(excluded.vendor_class, vendor_class),"
                " fingerprint=COALESCE(excluded.fingerprint, fingerprint),"
                " last_seen=excluded.last_seen",
                {**info, "now": now},
            )

    def dhcp_clients(self) -> Dict[str, dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM dhcp_clients").fetchall()
        return {r["mac"]: dict(r) for r in rows}

    def set_custom_name(self, mac: str, name: Optional[str]) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE devices SET custom_name=? WHERE mac=?", (name or None, mac)
            )
            return cur.rowcount > 0

    EDITABLE = ("custom_name", "custom_type", "person", "notes", "alert", "known")

    def update_device(self, mac: str, fields: Dict[str, object]) -> bool:
        """Sửa các trường người dùng được phép sửa. Chuỗi rỗng được lưu thành NULL."""
        fields = {k: v for k, v in fields.items() if k in self.EDITABLE}
        if not fields:
            return self.device(mac) is not None
        values = [int(bool(v)) if k == "known" else (v or None) for k, v in fields.items()]
        with self._lock, self._conn:
            cur = self._conn.execute(
                f"UPDATE devices SET {', '.join(k + '=?' for k in fields)} WHERE mac=?",
                (*values, mac))
            return cur.rowcount > 0

    def mark_all_known(self) -> int:
        with self._lock, self._conn:
            return self._conn.execute("UPDATE devices SET known=1 WHERE known=0").rowcount

    def delete_device(self, mac: str) -> bool:
        """Xoá thiết bị cùng lịch sử của nó. Nếu nó còn trong mạng, lượt quét sau sẽ thấy lại như mới."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM events WHERE mac=?", (mac,))
            self._conn.execute("DELETE FROM dhcp_clients WHERE mac=?", (mac,))
            return self._conn.execute("DELETE FROM devices WHERE mac=?", (mac,)).rowcount > 0

    def merge_devices(self, source: str, target: str) -> bool:
        """Gộp `source` (dòng cũ, vd MAC trước khi đổi) vào `target` (dòng giữ lại).

        `target` nhận bí danh, tên, loại, người dùng, ghi chú, trạng thái quen và lịch sử của
        `source`; `source` bị xoá. Trường nào `source` để trống thì giữ giá trị của `target`.
        """
        if source == target:
            return False
        with self._lock, self._conn:
            c = self._conn
            src = c.execute("SELECT * FROM devices WHERE mac=?", (source,)).fetchone()
            dst = c.execute("SELECT * FROM devices WHERE mac=?", (target,)).fetchone()
            if not src or not dst:
                return False
            c.execute("UPDATE events SET mac=? WHERE mac=?", (target, source))
            c.execute("DELETE FROM dhcp_clients WHERE mac=?", (source,))
            c.execute("DELETE FROM devices WHERE mac=?", (source,))  # nhả bí danh (cột là duy nhất)
            c.execute(
                "UPDATE devices SET alias=?, custom_name=COALESCE(?, custom_name),"
                " custom_type=COALESCE(?, custom_type), person=COALESCE(?, person),"
                " notes=COALESCE(?, notes), alert=COALESCE(?, alert), known=MAX(known, ?),"
                " first_seen=MIN(first_seen, ?) WHERE mac=?",
                (src["alias"], src["custom_name"], src["custom_type"], src["person"],
                 src["notes"], src["alert"], src["known"], src["first_seen"], target))
            return True

    def devices(self) -> List[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM devices").fetchall()
        return [dict(r) for r in rows]

    def device(self, mac: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        return dict(row) if row else None

    def device_events(self, mac: str, limit: int = 200) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ?", (mac, limit)).fetchall()
        return [dict(r) for r in rows]

    def sessions(self, mac: str, since: int, now: int) -> List[List[int]]:
        """Các quãng online của thiết bị từ `since` tới `now`: [[bắt đầu, kết thúc], ...]."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, type FROM events WHERE mac=? AND type IN ('new','online','offline')"
                " ORDER BY id", (mac,)).fetchall()
            dev = self._conn.execute("SELECT is_online FROM devices WHERE mac=?", (mac,)).fetchone()
        spans, start = [], None
        for r in rows:
            if r["type"] == "offline":
                if start is not None:
                    spans.append([start, r["ts"]])
                    start = None
            elif start is None:
                start = r["ts"]
        if start is not None and dev and dev["is_online"]:
            spans.append([start, now])
        return [[max(a, since), b] for a, b in spans if b > since]

    def get_state(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_state(self, key: str, value: Optional[str]) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO state (key, value) VALUES (?, ?)"
                               " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def all_events(self) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.ts, e.type, e.mac, e.ip, e.detail, d.alias,"
                " COALESCE(d.custom_name, d.hostname) AS name"
                " FROM events e LEFT JOIN devices d ON d.mac = e.mac ORDER BY e.id").fetchall()
        return [dict(r) for r in rows]

    def online_since(self) -> Dict[str, int]:
        """{mac: thời điểm bắt đầu lần online gần nhất} - từ sự kiện "new"/"online" mới nhất."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT mac, MAX(ts) AS ts FROM events WHERE type IN ('new', 'online') GROUP BY mac"
            ).fetchall()
        return {r["mac"]: r["ts"] for r in rows}

    def events(self, limit: int = 50) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.*, COALESCE(d.custom_name, d.hostname) AS name, d.vendor AS vendor,"
                " d.alias AS alias"
                " FROM events e LEFT JOIN devices d ON d.mac = e.mac"
                " ORDER BY e.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
