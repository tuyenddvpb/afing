"""Giao diện dòng lệnh của afing."""

import argparse
import ipaddress
import logging
import os
import threading

from . import __version__
from .db import Database
from .monitor import Monitor
from .names import resolve_names
from .netinfo import detect
from .oui import OuiTable
from .scanner import Scanner
from .web import make_server

log = logging.getLogger("afing")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="afing", description="Quét và theo dõi thiết bị trong mạng LAN/Wi-Fi."
    )
    p.add_argument("--version", action="version", version=f"afing {__version__}")
    p.add_argument("command", nargs="?", default="run", choices=["run", "scan", "update-oui"],
                   help="run: quét liên tục + web (mặc định) | scan: quét 1 lần rồi in ra |"
                        " update-oui: tải bảng hãng sản xuất")
    p.add_argument("--subnet", help="subnet cần quét, vd 192.168.1.0/24 (mặc định: tự dò)")
    p.add_argument("--interval", type=int, default=10, help="số giây giữa 2 lượt quét (10)")
    p.add_argument("--offline-after", type=int, default=45,
                   help="không thấy thiết bị quá số giây này thì coi là đã rời mạng (45)")
    p.add_argument("--method", choices=["auto", "arp", "passive"], default="auto",
                   help="arp: ARP scan bằng scapy (cần root) | passive: đọc bảng ARP của HĐH")
    p.add_argument("--db", default="afing.db", help="đường dẫn file SQLite (afing.db)")
    p.add_argument("--host", default="127.0.0.1",
                   help="địa chỉ web lắng nghe; dùng 0.0.0.0 để máy khác trong LAN xem được")
    p.add_argument("--port", type=int, default=8080, help="cổng web (8080)")
    p.add_argument("--no-web", action="store_true", help="chỉ quét và ghi DB, không mở web")
    p.add_argument("--no-oui-download", action="store_true",
                   help="không tự tải bảng hãng sản xuất từ IEEE ở lần chạy đầu")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    oui = OuiTable(os.path.join(os.path.dirname(os.path.abspath(args.db)), "oui.csv"))

    if args.command == "update-oui":
        print(f"Đã tải {oui.download()} hãng sản xuất về {oui.path}")
        return 0

    try:
        net = detect(args.subnet)
        scanner = Scanner(net, args.method)
    except (RuntimeError, ValueError) as e:
        print(f"Lỗi: {e}")
        return 1
    log.info("Mạng %s | IP máy này %s | gateway %s | chế độ quét: %s",
             net.network, net.ip, net.gateway or "?", scanner.method)

    if args.command == "scan":
        seen = scanner.scan()
        names = resolve_names(seen.keys(), net.ip)
        print(f"{'IP':<16}{'MAC':<19}{'TÊN':<28}HÃNG")
        for ip in sorted(seen, key=ipaddress.ip_address):
            print(f"{ip:<16}{seen[ip]:<19}{names.get(ip, '-'):<28}{oui.lookup(seen[ip]) or '-'}")
        print(f"\n{len(seen)} thiết bị")
        return 0

    if not len(oui) and not args.no_oui_download:
        def fetch():
            try:
                log.info("Đã tải bảng hãng sản xuất (%d hãng)", oui.download())
            except Exception as e:
                log.warning("Không tải được bảng hãng sản xuất (%s). "
                            "Thử lại sau bằng: python -m afing update-oui", e)
        threading.Thread(target=fetch, daemon=True).start()

    db = Database(args.db)
    monitor = Monitor(net, scanner, db, oui, args.interval, args.offline_after)
    thread = monitor.start()
    try:
        if args.no_web:
            while thread.is_alive():
                thread.join(1)
        else:
            server = make_server(args.host, args.port, db, monitor)
            shown = "localhost" if args.host in ("127.0.0.1", "0.0.0.0") else args.host
            log.info("Dashboard: http://%s:%d  (Ctrl+C để dừng)", shown, args.port)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        thread.join(5)
        db.close()
    return 0
