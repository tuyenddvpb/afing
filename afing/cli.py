"""Giao diện dòng lệnh của afing."""

import argparse
import ipaddress
import logging
import os
import threading
import time

from . import __version__
from .db import Database
from .dhcp import DhcpListener, why_unavailable
from .classify import TYPES
from .monitor import Monitor, describe
from .discovery import identify, mdns_probe, summarize_services
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
    p.add_argument("command", nargs="?", default="run", choices=["run", "scan", "dhcp", "mdns", "update-oui"],
                   help="run: quét liên tục + web (mặc định) | scan: quét 1 lần rồi in ra |"
                        " dhcp: chỉ nghe và in gói DHCP (để thử) | mdns: in mọi thứ nghe được qua mDNS (để thử) | update-oui: tải bảng hãng sản xuất")
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
    p.add_argument("--no-dhcp", action="store_true",
                   help="không nghe gói DHCP (mặc định có nghe nếu đủ quyền mở cổng 67)")
    p.add_argument("--no-oui-download", action="store_true",
                   help="không tự tải bảng hãng sản xuất từ IEEE ở lần chạy đầu")
    return p


def show_mdns(net) -> int:
    """Lệnh `mdns`: in mọi bản ghi mDNS nghe được, để biết thiết bị nào tự khai những gì."""
    wait = 12
    print(f"Đang hỏi và nghe mDNS trong {wait} giây (giữ thiết bị cần thử mở khoá màn hình)...",
          flush=True)
    per_ip, joined = mdns_probe(net.ip, wait)
    print("Nghe nhóm multicast cổng 5353: " + ("được" if joined else "KHÔNG mở được, chỉ nghe "
          "trả lời trực tiếp"))
    if not per_ip:
        print("Không thiết bị nào trả lời mDNS. Nếu trong mạng có máy in, tivi, Apple TV, "
              "Chromecast... thì có thể tường lửa của máy này đang chặn UDP 5353.")
        return 0
    for ip in sorted(per_ip, key=ipaddress.ip_address):
        ptrs, txts = per_ip[ip]
        info = summarize_services(ptrs, txts)
        print(f"\n{ip}   tên={info.get('name', '-')}   model={info.get('model', '-')}")
        for service, target in sorted(set(ptrs)):
            print(f"    {service}  ->  {target}")
        for name, txt in sorted(txts.items()):
            shown = ", ".join(f"{k}={v[:40]}" for k, v in list(txt.items())[:8])
            print(f"    TXT {name}: {shown}")
    print(f"\n{len(per_ip)} thiết bị trả lời mDNS")
    return 0


def listen_dhcp(oui: OuiTable) -> int:
    """Lệnh `dhcp`: in từng gói DHCP nghe được kèm loại/hệ điều hành suy ra, để kiểm tra nhanh."""
    def show(info):
        vendor = oui.lookup(info["mac"])
        d = describe({}, vendor, False, info)
        print(f"{time.strftime('%H:%M:%S')}  {info['type']:<9}{info['requested_ip'] or '?':<16}"
              f"{info['mac']}  tên={info['hostname'] or '-'}  "
              f"loại={TYPES.get(d['type'], '-')}  hđh={d['os'] or '-'}  "
              f"vendor-class={info['vendor_class'] or '-'}  vân-tay={info['fingerprint'] or '-'}",
              flush=True)

    try:
        listener = DhcpListener(show).start()
    except OSError as e:
        print(f"Lỗi: {why_unavailable(e)}")
        return 1
    print("Đang nghe DHCP. Tắt rồi bật lại Wi-Fi trên một thiết bị để thấy gói của nó. "
          "Ctrl+C để dừng.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        listener.stop()
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    oui = OuiTable(os.path.join(os.path.dirname(os.path.abspath(args.db)), "oui.csv"))

    if args.command == "update-oui":
        print(f"Đã tải {oui.download()} hãng sản xuất về {oui.path}")
        return 0

    if args.command == "dhcp":
        return listen_dhcp(oui)

    try:
        net = detect(args.subnet)
        scanner = Scanner(net, args.method)
    except (RuntimeError, ValueError) as e:
        print(f"Lỗi: {e}")
        return 1
    log.info("Mạng %s | IP máy này %s | gateway %s | chế độ quét: %s",
             net.network, net.ip, net.gateway or "?", scanner.method)

    if args.command == "mdns":
        return show_mdns(net)

    if args.command == "scan":
        seen = scanner.scan()
        print(f"Tìm thấy {len(seen)} thiết bị, đang dò tên (khoảng 5 giây)...")
        found = identify(seen.keys(), net.ip)
        print("(Bí danh loài vật chỉ có ở chế độ chạy liên tục, vì cần database để nhớ.)")
        print(f"{'IP':<16}{'MAC':<19}{'LOẠI':<16}{'TÊN':<28}{'MODEL':<26}{'HĐH':<12}HÃNG")
        for ip in sorted(seen, key=ipaddress.ip_address):
            vendor = oui.lookup(seen[ip])
            d = describe(found.get(ip, {}), vendor, ip == net.gateway)
            print(f"{ip:<16}{seen[ip]:<19}{TYPES.get(d['type'], '-'):<16}{d['name'] or '-':<28}"
                  f"{d['model'] or '-':<26}{d['os'] or '-':<12}{vendor or '-'}")
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
    listener = None
    if not args.no_dhcp:
        try:
            listener = DhcpListener(monitor.on_dhcp).start()
            monitor.status["dhcp"] = True
            log.info("Đang nghe DHCP: tên thiết bị sẽ hiện khi chúng kết nối (lại) vào mạng")
        except OSError as e:
            log.info("Không nghe DHCP (%s)", why_unavailable(e))
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
        if listener:
            listener.stop()
        monitor.stop()
        thread.join(5)
        db.close()
    return 0
