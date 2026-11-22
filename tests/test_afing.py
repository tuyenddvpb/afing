import ipaddress
import json
import os
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import socket
import time

from afing import alias, autostart, cli, config, dhcp, notify, report, discovery, names, netinfo, scanner
from afing.classify import TYPES, classify
from afing.monitor import describe
from afing.db import Database
from afing.monitor import Monitor
from afing.oui import RANDOM_MAC, OuiTable
from afing.web import make_server


class ParserTests(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(scanner.norm_mac("A-B-C-D-E-F"), "0a:0b:0c:0d:0e:0f")
        self.assertEqual(scanner.norm_mac("0:1c:42:0:0:8"), "00:1c:42:00:00:08")
        self.assertIsNone(scanner.norm_mac("ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(scanner.norm_mac("01:00:5e:00:00:fb"))
        self.assertIsNone(scanner.norm_mac("00:00:00:00:00:00"))
        self.assertIsNone(scanner.norm_mac("(incomplete)"))

    def test_ip_neigh(self):
        text = (
            "192.168.1.1 dev wlan0 lladdr a4:91:b1:11:22:33 REACHABLE\n"
            "192.168.1.20 dev wlan0 lladdr 3c:22:fb:aa:bb:cc STALE\n"
            "192.168.1.30 dev wlan0 lladdr 3c:22:fb:aa:bb:dd router DELAY\n"
            "192.168.1.40 dev wlan0  FAILED\n"
            "192.168.1.41 dev wlan0 lladdr 11:22:33:44:55:66 FAILED\n"
            "192.168.1.50 dev wlan0  INCOMPLETE\n"
        )
        self.assertEqual(scanner.parse_ip_neigh(text), {
            "192.168.1.1": "a4:91:b1:11:22:33",
            "192.168.1.20": "3c:22:fb:aa:bb:cc",
            "192.168.1.30": "3c:22:fb:aa:bb:dd",
        })

    def test_proc_arp(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         a4:91:b1:11:22:33     *        wlan0\n"
            "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
        )
        self.assertEqual(scanner.parse_proc_arp(text), {"192.168.1.1": "a4:91:b1:11:22:33"})

    def test_arp_a_windows(self):
        text = (
            "\nInterface: 192.168.1.5 --- 0x4\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           a4-91-b1-11-22-33     dynamic\n"
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
            "  224.0.0.251           01-00-5e-00-00-fb     static\n"
        )
        self.assertEqual(scanner.parse_arp_a(text), {"192.168.1.1": "a4:91:b1:11:22:33"})

    def test_arp_a_macos(self):
        text = (
            "? (192.168.1.1) at a4:91:b1:11:22:33 on en0 ifscope [ethernet]\n"
            "? (192.168.1.7) at 0:1c:42:0:0:8 on en0 ifscope [ethernet]\n"
            "? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n"
            "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        )
        self.assertEqual(scanner.parse_arp_a(text), {
            "192.168.1.1": "a4:91:b1:11:22:33",
            "192.168.1.7": "00:1c:42:00:00:08",
        })

    def test_netmask_parsers(self):
        linux = "2: wlan0    inet 192.168.1.5/24 brd 192.168.1.255 scope global wlan0\\ valid\n"
        self.assertEqual(netinfo.parse_prefix_linux(linux, "192.168.1.5"), (24, "wlan0"))
        mac = "\tinet 10.0.0.12 netmask 0xfffffe00 broadcast 10.0.1.255\n"
        self.assertEqual(netinfo.parse_mask_ifconfig(mac, "10.0.0.12"), 23)
        win = (
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.5\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
        )
        self.assertEqual(netinfo.parse_mask_ipconfig(win, "192.168.1.5"), 24)
        self.assertIsNone(netinfo.parse_mask_ipconfig(win, "192.168.1.50"))

    def test_gateway_parsers(self):
        self.assertEqual(
            netinfo.parse_gateway("default via 192.168.1.1 dev wlan0 proto dhcp\n", "Linux"),
            "192.168.1.1")
        self.assertEqual(
            netinfo.parse_gateway("   gateway: 10.0.0.1\n  interface: en0\n", "Darwin"), "10.0.0.1")
        self.assertEqual(
            netinfo.parse_gateway(
                "          0.0.0.0          0.0.0.0      192.168.1.1      192.168.1.5     25\n",
                "Windows"),
            "192.168.1.1")


    def test_proc_route(self):
        text = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n"
        )
        self.assertEqual(netinfo.parse_proc_route(text), "192.168.1.1")


class NameTests(unittest.TestCase):
    def test_mdns_roundtrip_with_compression(self):
        qname = "5.1.168.192.in-addr.arpa"
        query = names.build_query(qname, unicast_reply=True)
        header = struct.pack("!6H", 0, 0x8400, 1, 1, 0, 0)
        target = b"\x07MacBook\x05local\x00"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
        reply = header + query[12:] + answer
        self.assertEqual(names.parse_ptr_records(reply), [(qname, "MacBook.local")])
        self.assertEqual(names.clean_name("MacBook.local."), "MacBook")

    def test_dns_garbage_is_ignored(self):
        self.assertEqual(names.parse_ptr_records(b"\x00" * 5), [])
        loop = struct.pack("!6H", 0, 0, 0, 1, 0, 0) + b"\xc0\x0c"
        self.assertEqual(names.parse_ptr_records(loop), [])

    def test_nbstat(self):
        def entry(name, suffix, flags):
            return name.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags)

        body = bytes([3]) + entry("WORKGROUP", 0x00, 0x8400) + entry("DESKTOP-PC", 0x00, 0x0400) \
            + entry("DESKTOP-PC", 0x20, 0x0400)
        reply = names.NBSTAT_QUERY[:12] + names.NBSTAT_QUERY[12:46] \
            + struct.pack("!HHIH", 0x21, 1, 0, len(body)) + body
        self.assertEqual(names.parse_nbstat(reply), "DESKTOP-PC")
        self.assertIsNone(names.parse_nbstat(b"\x00" * 20))


def dns_name(name):
    return b"".join(bytes([len(p)]) + p for p in name) + b"\0"


def dns_record(name, rtype, rdata):
    return dns_name(name) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def txt_rdata(*items):
    return b"".join(bytes([len(i)]) + i for i in items)


class DiscoveryTests(unittest.TestCase):
    def packet(self, *records):
        return struct.pack("!6H", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)

    def test_browse_query_is_parseable(self):
        q = discovery.build_browse_query(s[0] for s in discovery.SERVICES)
        self.assertEqual(struct.unpack("!6H", q[:12])[2], len(discovery.SERVICES))
        self.assertEqual(discovery.parse_mdns_packet(q), ([], {}))

    def test_chromecast(self):
        svc = [b"_googlecast", b"_tcp", b"local"]
        inst = [b"Chromecast-Ultra-8f3a"] + svc
        pkt = self.packet(
            dns_record(svc, 12, dns_name(inst)),
            dns_record(inst, 16, txt_rdata(b"id=8f3a", b"md=Chromecast Ultra", "fn=TV phòng khách".encode())),
        )
        ptrs, txts = discovery.parse_mdns_packet(pkt)
        self.assertEqual(discovery.summarize_services(ptrs, txts),
                         {"name": "TV phòng khách", "model": "Chromecast Ultra"})

    def test_apple_and_priority(self):
        raop = [b"_raop", b"_tcp", b"local"]
        link = [b"_companion-link", b"_tcp", b"local"]
        # tên instance có dấu chấm và ký tự ngoài ASCII
        mac_name = "MacBook của T. Anh".encode()
        pkt = self.packet(
            dns_record(raop, 12, dns_name([b"AABBCCDDEEFF@Loa bep"] + raop)),
            dns_record(link, 12, dns_name([mac_name] + link)),
            dns_record([mac_name, b"_device-info", b"_tcp", b"local"], 16, txt_rdata(b"model=MacBookPro18,3")),
        )
        ptrs, txts = discovery.parse_mdns_packet(pkt)
        self.assertEqual(discovery.summarize_services(ptrs, txts),
                         {"name": "MacBook của T. Anh", "model": "MacBookPro18,3"})
        self.assertEqual(discovery.summarize_services(ptrs[:1], {}), {"name": "Loa bep"})

    def test_unknown_service_and_garbage(self):
        svc = [b"_weird", b"_tcp", b"local"]
        ptrs, txts = discovery.parse_mdns_packet(self.packet(dns_record(svc, 12, dns_name([b"x"] + svc))))
        self.assertEqual(discovery.summarize_services(ptrs, txts), {})
        self.assertEqual(discovery.parse_mdns_packet(b"\xff" * 30), ([], {}))
        self.assertEqual(discovery.parse_txt(b"\x05ab=cd\x03key\x00\x09AB=second"), {"ab": "cd"})

    def test_probe_hears_multicast_announcement(self):
        try:
            local = netinfo.local_ip()
        except OSError:
            self.skipTest("không có mạng")
        svc = [b"_companion-link", b"_tcp", b"local"]
        inst = ["iPhone của Mẹ".encode()] + svc
        pkt = self.packet(dns_record(svc, 12, dns_name(inst)),
                          dns_record(inst, 16, txt_rdata(b"rpMd=iPhone14,5")))

        def announce():
            time.sleep(0.5)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
                s.sendto(pkt, names.MDNS_ADDR)
            except OSError:
                pass
            finally:
                s.close()

        threading.Thread(target=announce, daemon=True).start()
        per_ip, joined = discovery.mdns_probe(local, wait=1.5, include_self=True)
        if not joined:
            self.skipTest("không mở được cổng 5353")
        ptrs, txts = per_ip[local]
        self.assertEqual(discovery.summarize_services(ptrs, txts), {"name": "iPhone của Mẹ"})

    def test_ssdp_parsing(self):
        resp = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: upnp:rootdevice\r\n"
                b"Location: http://192.168.1.20:8060/dial/dd.xml\r\n\r\n")
        h = discovery.parse_ssdp_headers(resp)
        self.assertEqual(h["location"], "http://192.168.1.20:8060/dial/dd.xml")
        self.assertEqual(h["st"], "upnp:rootdevice")
        self.assertTrue(discovery.safe_location(h["location"], "192.168.1.20"))
        self.assertFalse(discovery.safe_location(h["location"], "192.168.1.21"))
        self.assertFalse(discovery.safe_location("https://192.168.1.20/x", "192.168.1.20"))
        self.assertFalse(discovery.safe_location("file:///etc/passwd", "192.168.1.20"))
        self.assertFalse(discovery.safe_location("http://[bad", "192.168.1.20"))

    def test_device_xml(self):
        xml = """<?xml version="1.0"?><root><device>
            <friendlyName>[TV] Samsung Q60 &amp; Soundbar</friendlyName>
            <manufacturer>Samsung Electronics</manufacturer>
            <modelName>QA55Q60</modelName>
            <deviceList><device><friendlyName>inner</friendlyName></device></deviceList>
        </device></root>"""
        self.assertEqual(discovery.parse_device_xml(xml), {
            "name": "[TV] Samsung Q60 & Soundbar", "model": "Samsung Electronics QA55Q60"})
        self.assertEqual(
            discovery.parse_device_xml("<manufacturer>Sonos</manufacturer><modelName>Sonos One</modelName>"),
            {"model": "Sonos One"})
        self.assertEqual(discovery.parse_device_xml("not xml"), {})

    def test_fetch_description_from_real_http_server(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<root><friendlyName>NAS nha</friendlyName><modelName>DS220</modelName></root>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/desc.xml"
            self.assertEqual(discovery._fetch_description(url), {"name": "NAS nha", "model": "DS220"})
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(discovery._fetch_description("http://127.0.0.1:1/x"), {})


class ClassifyTests(unittest.TestCase):
    def test_devices_from_a_real_home_network(self):
        cases = [
            # (kwargs, loại, hệ điều hành)
            (dict(vendor="Samsung Electronics Co.,Ltd", name="WashingMachine"), "appliance", None),
            (dict(vendor="Xiaomi Communications Co Ltd", name="Deebot"), "vacuum", None),
            (dict(vendor="Samsung Electronics Co.,Ltd", name="[TV] Samsung 6 Series (43)",
                  model="Samsung Electronics UN43TU6900", upnp_type="MediaRenderer"), "tv", "Tizen"),
            (dict(vendor="Brother Industries, LTD.", name="BRW3CEFA5735548",
                  model="Brother DCP-T530DW", services=["_ipp._tcp"], sources={"nb"}), "printer", None),
            (dict(vendor="Dell Inc.", name="DESKTOP-P1CKL66", sources={"nb"}), "computer", "Windows"),
            (dict(vendor="Intel Corporate", name="DESKTOP-O6P5QG4"), "computer", "Windows"),
            (dict(vendor=None, name="MD5-PC", sources={"nb"}), "computer", "Windows"),
            (dict(vendor="zte corporation", is_gateway=True), "router", None),
            (dict(vendor=RANDOM_MAC), None, None),
            (dict(vendor="Apple, Inc.", name="Mẹ", model="iPhone8,1"), "mobile", "iOS"),
        ]
        for kwargs, type_, os_ in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(classify(**kwargs), (type_, os_))

    def test_other_signals(self):
        self.assertEqual(classify(name="Phòng khách", model="Chromecast Ultra",
                                  services=["_googlecast._tcp"]), ("media", None))
        self.assertEqual(classify(name="Bếp", model="Google Nest Mini",
                                  services=["_googlecast._tcp"]), ("speaker", None))
        self.assertEqual(classify(name="MacBook của An", model="MacBookPro18,3",
                                  services=["_companion-link._tcp", "_smb._tcp"]), ("computer", "macOS"))
        self.assertEqual(classify(name="Apple TV", model="AppleTV6,2",
                                  services=["_airplay._tcp"]), ("tv", "tvOS"))
        self.assertEqual(classify(name="raspberrypi", services=["_workstation._tcp"]),
                         ("computer", "Linux"))
        self.assertEqual(classify(vendor="Espressif Inc."), ("iot", None))
        self.assertEqual(classify(vendor="TP-Link Corporation Limited"), ("network", None))
        self.assertEqual(classify(vendor="Samsung Electronics Co.,Ltd"), (None, None))
        self.assertEqual(classify(name="Galaxy-S21", vendor=RANDOM_MAC),
                         ("mobile", "Android"))
        self.assertEqual(classify(upnp_type="InternetGatewayDevice"), ("router", None))

    def test_every_rule_uses_a_known_type(self):
        from afing import classify as mod
        for _, type_, _ in mod.TEXT_RULES + mod.VENDOR_RULES:
            self.assertIn(type_, TYPES)

    def test_describe_and_extra_signals(self):
        self.assertEqual(
            describe({"name": "DESKTOP-AB12", "sources": {"nb"}}, "Dell Inc.", False),
            {"name": "DESKTOP-AB12", "name_rank": 1, "model": None, "type": "computer",
             "os": "Windows"})
        self.assertEqual(describe({}, RANDOM_MAC, True)["type"], "router")
        self.assertEqual(discovery.parse_upnp_type(
            "<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"), "MediaRenderer")
        self.assertIsNone(discovery.parse_upnp_type("<root/>"))
        ptrs = [("_ipp._tcp.local", "X._ipp._tcp.local"), ("_weird._tcp.local", "Y._weird._tcp.local")]
        self.assertEqual(discovery.service_types(ptrs), ["_ipp._tcp"])


def dhcp_packet(mac, msg_type=3, hostname=None, vendor_class=None, params=None,
                requested_ip=None, op=1):
    opts = bytes([53, 1, msg_type])
    if requested_ip:
        opts += bytes([50, 4]) + socket.inet_aton(requested_ip)
    if hostname:
        opts += bytes([0, 12, len(hostname)]) + hostname  # kèm 1 byte pad
    if vendor_class:
        opts += bytes([60, len(vendor_class)]) + vendor_class
    if params:
        opts += bytes([55, len(params)]) + bytes(params)
    header = struct.pack("!4BIHH", op, 1, 6, 0, 0x1234, 0, 0x8000) + b"\0" * 16
    chaddr = bytes.fromhex(mac.replace(":", "")) + b"\0" * 10
    return header + chaddr + b"\0" * 192 + dhcp.MAGIC_COOKIE + opts + b"\xff"


IOS_PARAMS = [1, 121, 3, 6, 15, 108, 114, 119, 162, 252]
MACOS_PARAMS = IOS_PARAMS + [95, 44, 46]
WINDOWS_PARAMS = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]


class DhcpTests(unittest.TestCase):
    def test_parse_iphone_request(self):
        pkt = dhcp_packet("da:a1:19:00:00:01", hostname=b"iPhone-cua-Me", params=IOS_PARAMS,
                          requested_ip="192.168.102.10")
        self.assertEqual(dhcp.parse_packet(pkt), {
            "mac": "da:a1:19:00:00:01", "type": "REQUEST", "hostname": "iPhone-cua-Me",
            "vendor_class": None, "fingerprint": "1,121,3,6,15,108,114,119,162,252",
            "requested_ip": "192.168.102.10"})

    def test_rejects_non_client_and_broken_packets(self):
        good = dhcp_packet("da:a1:19:00:00:01", hostname=b"x")
        self.assertIsNone(dhcp.parse_packet(dhcp_packet("da:a1:19:00:00:01", op=2)))       # server
        self.assertIsNone(dhcp.parse_packet(dhcp_packet("da:a1:19:00:00:01", msg_type=5)))  # ACK
        self.assertIsNone(dhcp.parse_packet(dhcp_packet("ff:ff:ff:ff:ff:ff")))
        self.assertIsNone(dhcp.parse_packet(good[:200]))
        self.assertIsNone(dhcp.parse_packet(good[:236] + b"XXXX" + good[240:]))
        self.assertIsNone(dhcp.parse_packet(b""))
        # option khai dài hơn dữ liệu thật: bỏ option đó, không đọc tràn
        cut = good[:240] + bytes([53, 1, 3, 12, 200]) + b"abc"
        self.assertIsNone(dhcp.parse_packet(cut)["hostname"])
        dirty = dhcp_packet("da:a1:19:00:00:01", hostname=b"<b>\x00\x07TV\xff", vendor_class=b"a\nb")
        self.assertEqual(dhcp.parse_packet(dirty)["hostname"], "<b>TV")
        self.assertEqual(dhcp.parse_packet(dirty)["vendor_class"], "ab")

    def test_os_from_dhcp(self):
        def guess(**kw):
            return classify(vendor=RANDOM_MAC, dhcp=kw)

        ios = ",".join(map(str, IOS_PARAMS))
        self.assertEqual(guess(fingerprint=ios), ("mobile", "iOS"))
        self.assertEqual(guess(fingerprint="1,121,3,6,15,119,252"), ("mobile", "iOS"))
        self.assertEqual(guess(fingerprint=ios, hostname="iPad-cua-An"), ("tablet", "iPadOS"))
        self.assertEqual(guess(fingerprint=ios, hostname="Apple-Watch"), ("wearable", None))
        self.assertEqual(guess(fingerprint=",".join(map(str, MACOS_PARAMS))), ("computer", "macOS"))
        self.assertEqual(guess(fingerprint=",".join(map(str, WINDOWS_PARAMS)),
                               vendor_class="MSFT 5.0"), ("computer", "Windows"))
        self.assertEqual(guess(vendor_class="android-dhcp-14"), ("mobile", "Android 14"))
        self.assertEqual(guess(vendor_class="udhcp 1.31.1"), (None, "Linux"))
        self.assertEqual(guess(fingerprint="1,3,6"), (None, None))
        # dịch vụ thiết bị tự quảng bá vẫn thắng vân tay DHCP
        self.assertEqual(classify(name="Apple TV", services=["_airplay._tcp"],
                                  dhcp={"fingerprint": ios}), ("tv", "tvOS"))

    def test_describe_name_priority(self):
        d = {"hostname": "iPhone-cua-Me", "fingerprint": ",".join(map(str, IOS_PARAMS))}
        self.assertEqual(describe({}, None, False, d), {
            "name": "iPhone-cua-Me", "name_rank": 2, "model": None, "type": "mobile", "os": "iOS"})
        self.assertEqual(describe({"name": "192-168-1-5.lan", "name_rank": 1}, None, False, d)["name"],
                         "iPhone-cua-Me")
        best = describe({"name": "iPhone của Mẹ", "name_rank": 3}, None, False, d)
        self.assertEqual((best["name"], best["name_rank"], best["os"]), ("iPhone của Mẹ", 3, "iOS"))

    def test_listener_end_to_end_into_monitor(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(os.path.join(tmp, "t.db"))
            net = netinfo.NetInfo(ipaddress.ip_network("127.0.0.0/30"), "127.0.0.1")
            fake = FakeScanner()
            monitor = Monitor(net, fake, db, OuiTable(os.path.join(tmp, "oui.csv")))
            mac = "da:a1:19:00:00:01"
            listener = dhcp.DhcpListener(monitor.on_dhcp, host="127.0.0.1", port=0).start()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b"garbage", ("127.0.0.1", listener.port))
                s.sendto(dhcp_packet(mac, hostname=b"iPhone-cua-Me", params=IOS_PARAMS),
                         ("127.0.0.1", listener.port))
                s.close()
                for _ in range(100):
                    if monitor.status["dhcp_packets"]:
                        break
                    time.sleep(0.02)
            finally:
                listener.stop()
            self.assertEqual(monitor.status["dhcp_packets"], 1)

            import afing.monitor as mon
            original, mon.identify = mon.identify, lambda ips, local_ip: {}
            try:
                monitor.scan_once()                 # iPhone chưa hiện trong lượt quét
                self.assertEqual(monitor._dhcp_fresh, {mac})
                fake.result = {"127.0.0.2": mac}
                monitor.scan_once()                 # thiết bị mới -> nhận diện bằng DHCP
                monitor._name_due[mac] = time.monotonic() + 999
                # gói DHCP sau thiếu hostname: giữ tên cũ, vẫn kích hoạt nhận diện lại
                monitor.on_dhcp(dhcp.parse_packet(dhcp_packet(mac, params=IOS_PARAMS)))
                monitor.scan_once()
            finally:
                mon.identify = original
            dev = db.devices()[0]
            self.assertEqual((dev["hostname"], dev["name_rank"], dev["device_type"], dev["os"]),
                             ("iPhone-cua-Me", 2, "mobile", "iOS"))
            self.assertEqual(monitor._dhcp_fresh, set())
            db.close()


class AliasTests(unittest.TestCase):
    def test_pick_is_deterministic_unique_and_never_runs_out(self):
        mac = "f8:10:93:3b:a5:03"
        first = alias.pick(mac, [])
        self.assertEqual(alias.pick(mac, []), first)
        self.assertIn(first, alias.ICONS)
        self.assertNotEqual(alias.pick(mac, [first]), first)
        forest, extra = len(alias.ANIMALS), len(alias.EXTRA)
        order = []
        for i in range(forest + extra + forest + 3):
            order.append(alias.pick(f"02:00:00:00:{i // 256:02x}:{i % 256:02x}", order))
        self.assertEqual(len(set(order)), len(order))                      # không bao giờ trùng
        forest_names = {a[1] for a in alias.ANIMALS}
        self.assertEqual(set(order[:forest]), forest_names)                # loài rừng trước
        self.assertEqual(set(order[forest:forest + extra]), {a[1] for a in alias.EXTRA})
        self.assertEqual(forest + extra, 100)
        self.assertTrue(all(a.endswith(" 2") for a in order[100:100 + forest]))
        self.assertTrue(all(a.endswith(" 3") for a in order[-3:]))
        # 100 loài, 100 tên khác nhau, 100 emoji khác nhau
        self.assertEqual(len(alias.ICONS), 100)
        self.assertEqual(len(set(alias.ICONS.values())), 100)

    def test_database_enforces_unique_aliases_and_repairs_duplicates(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.db")
            db = Database(path)
            macs = [f"02:00:00:00:00:{i:02x}" for i in range(3)]
            db.apply_scan({"10.0.0.1": macs[0]}, 1000, 45)
            db.apply_scan({"10.0.0.1": macs[0], "10.0.0.2": macs[1], "10.0.0.3": macs[2]}, 2000, 45)
            first = db.devices()
            keeper = next(d["alias"] for d in first if d["mac"] == macs[0])
            with self.assertRaises(sqlite3.IntegrityError):
                with db._conn:
                    db._conn.execute("UPDATE devices SET alias=?", (keeper,))
            # giả lập một database hỏng: bỏ ràng buộc rồi cho cả ba trùng nhau
            with db._conn:
                db._conn.execute("DROP INDEX idx_devices_alias")
                db._conn.execute("UPDATE devices SET alias=?", (keeper,))
            db.close()
            db = Database(path)
            fixed = {d["mac"]: d["alias"] for d in db.devices()}
            db.close()
            self.assertEqual(fixed[macs[0]], keeper)        # thiết bị xuất hiện trước giữ con vật
            self.assertEqual(len(set(fixed.values())), 3)

    def test_icon(self):
        self.assertEqual(alias.icon("Tiger"), "🐯")
        self.assertEqual(alias.icon("Tiger 12"), "🐯")
        self.assertEqual(alias.icon(None), "")
        self.assertEqual(alias.icon("Dinosaur"), "")
        self.assertEqual(alias.from_legacy("Hổ"), "Tiger")
        self.assertEqual(alias.from_legacy("Thỏ rừng 3"), "Hare 3")
        self.assertIsNone(alias.from_legacy("Tiger"))
        self.assertIsNone(alias.from_legacy(None))
        self.assertEqual(len(alias.LEGACY), len(alias.ANIMALS))

    def test_vietnamese_labels_from_older_versions_are_migrated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.db")
            db = Database(path)
            a, b = "da:a1:19:00:00:01", "3c:ef:a5:73:55:48"
            db.apply_scan({"10.0.0.2": a, "10.0.0.3": b}, 1000, 45)
            db.set_custom_name(b, "Máy in tầng 2")
            with db._conn:
                db._conn.execute("UPDATE devices SET alias='Sóc', vendor='MAC ngẫu nhiên (riêng tư)'"
                                 " WHERE mac=?", (a,))
                db._conn.execute("UPDATE devices SET alias='Hổ 2' WHERE mac=?", (b,))
            db.close()
            db = Database(path)
            devs = {d["mac"]: d for d in db.devices()}
            db.close()
            self.assertEqual((devs[a]["alias"], devs[a]["vendor"]), ("Squirrel", RANDOM_MAC))
            self.assertEqual((devs[b]["alias"], devs[b]["custom_name"]), ("Tiger 2", "Máy in tầng 2"))

    def test_alias_is_kept_across_reconnects_and_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.db")
            db = Database(path)
            a, b = "f8:10:93:3b:a5:03", "3c:ef:a5:73:55:48"
            db.apply_scan({"10.0.0.2": a, "10.0.0.3": b}, 1000, 45)
            before = {d["mac"]: d["alias"] for d in db.devices()}
            self.assertEqual(len(set(before.values())), 2)
            db.apply_scan({}, 5000, 45)                       # cả hai rời mạng
            db.close()
            db = Database(path)                               # khởi động lại afing
            db.apply_scan({"10.0.0.9": a, "10.0.0.8": b, "10.0.0.7": "02:00:00:00:00:09"}, 9000, 45)
            after = {d["mac"]: d["alias"] for d in db.devices()}
            self.assertEqual({m: after[m] for m in before}, before)
            self.assertEqual(len(set(after.values())), 3)
            self.assertEqual(db.events(1)[0]["alias"], after[db.events(1)[0]["mac"]])
            db.close()

    def test_old_database_gets_aliases(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT NOT NULL, hostname TEXT,"
                         " custom_name TEXT, vendor TEXT, is_online INTEGER NOT NULL DEFAULT 1,"
                         " is_self INTEGER NOT NULL DEFAULT 0, is_gateway INTEGER NOT NULL DEFAULT 0,"
                         " first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)")
            conn.executemany("INSERT INTO devices (mac, ip, first_seen, last_seen) VALUES (?,?,1,1)",
                             [("aa:aa:aa:aa:aa:01", "10.0.0.1"), ("aa:aa:aa:aa:aa:02", "10.0.0.2")])
            conn.commit()
            conn.close()
            db = Database(path)
            got = [d["alias"] for d in db.devices()]
            db.close()
            self.assertEqual(len(set(got)), 2)
            self.assertTrue(all(alias.icon(a) for a in got))
            db = Database(path)                               # mở lại: không gán lại
            self.assertEqual([d["alias"] for d in db.devices()], got)
            db.close()


class AutostartTests(unittest.TestCase):
    def test_launch_command(self):
        exe = r"C:\Tools\My Apps\afing.exe"
        extra = ["--db", r"C:\Tools\My Apps\afing.db", "--port", "8080"]
        self.assertEqual(autostart.launch_command(extra, True, exe, r"C:\x"), (
            exe, r'run --wait-network --db "C:\Tools\My Apps\afing.db" --port 8080',
            os.path.dirname(exe)))
        cmd, args, workdir = autostart.launch_command([], False, r"C:\Py\python.exe", r"C:\src\afing")
        self.assertEqual((cmd, args, workdir),
                         (r"C:\Py\python.exe", "-m afing run --wait-network", r"C:\src\afing"))

    def test_task_xml_is_well_formed_and_escaped(self):
        import xml.etree.ElementTree as ET
        xml = autostart.build_xml(r"C:\A&B\afing.exe", r'run --db "C:\A&B\<x>.db"', r"C:\A&B")
        root = ET.fromstring(xml.encode("utf-16"))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.find(".//t:Command", ns).text, r"C:\A&B\afing.exe")
        self.assertEqual(root.find(".//t:Arguments", ns).text, r'run --db "C:\A&B\<x>.db"')
        self.assertEqual(root.find(".//t:ExecutionTimeLimit", ns).text, "PT0S")   # không giới hạn
        self.assertEqual(root.find(".//t:UserId", ns).text, "S-1-5-18")           # SYSTEM
        self.assertIsNotNone(root.find(".//t:BootTrigger", ns))

    @unittest.skipIf(os.name == "nt", "chỉ kiểm tra thông báo trên hệ khác Windows")
    def test_refuses_on_non_windows(self):
        self.assertEqual(autostart.install([], 8080), 1)
        self.assertEqual(autostart.uninstall(), 1)


class FakeChatService:
    """Máy chủ HTTP giả đóng vai Telegram và ntfy, ghi lại mọi request nhận được."""

    def __init__(self, status=200):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        self.requests = []
        self.updates = [
            {"update_id": 1, "message": {"chat": {"id": 111, "first_name": "Old"}}},
            {"update_id": 2, "message": {"chat": {"id": 987654, "first_name": "Tuyen", "last_name": "D"}}},
        ]
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, body=b"{}"):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append((self.path, dict(self.headers), data))
                self._reply(b'{"ok":false,"description":"Unauthorized"}' if status != 200 else b"{}")

            def do_GET(self):
                from urllib.parse import parse_qs, urlsplit
                outer.requests.append((self.path, dict(self.headers), b""))
                query = parse_qs(urlsplit(self.path).query)
                offset = int(query.get("offset", ["0"])[0])
                found = outer.updates[-1:] if offset < 0 else \
                    [u for u in outer.updates if u["update_id"] >= offset]
                self._reply(json.dumps({"ok": True, "result": found}).encode())

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class NotifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg_path = os.path.join(self.tmp.name, "notify.json")
        self.db = Database(os.path.join(self.tmp.name, "t.db"))
        self.sent = []
        self.notifier = notify.Notifier(self.cfg_path, self.db.devices,
                                        sender=lambda cfg, text: self.sent.append(text) or [])
        self._urls = (notify.TELEGRAM_API, notify.NTFY_SERVER)

    def tearDown(self):
        notify.TELEGRAM_API, notify.NTFY_SERVER = self._urls
        self.db.close()
        self.tmp.cleanup()

    def enable(self, **extra):
        notify.save_config(self.cfg_path, {"ntfy": {"topic": "t"}, **extra})

    def scan(self, seen, now):
        events = self.db.apply_scan(seen, now, 45, vendor_lookup=lambda m: "Apple, Inc.")
        return self.notifier.process(events, now, "192.168.102.0/24")

    def test_disabled_sends_nothing(self):
        self.assertEqual(self.scan({"10.0.0.1": "aa:aa:aa:aa:aa:01"}, 1000), [])
        self.assertEqual(notify.channels({}), [])
        self.assertEqual(notify.channels({"telegram": {"token": "x"}}), [])  # thiếu chat_id

    def test_first_inventory_is_one_summary_then_new_devices_are_reported(self):
        self.enable()
        a, b, c = ("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", "f8:10:93:3b:a5:03")
        lines = self.scan({"10.0.0.1": a, "10.0.0.2": b}, 1000)
        self.assertEqual(lines, ["✅ afing is now watching 192.168.102.0/24: 2 devices found."])

        self.db.apply_scan({"10.0.0.1": a, "10.0.0.2": b, "10.0.0.28": c}, 1010, 45)
        self.db.set_identities({c: {"name": "MDs-phone", "name_rank": 2, "type": "mobile", "os": "iOS"}})
        events = [{"ts": 1010, "mac": c, "type": "new", "ip": "10.0.0.28", "detail": None}]
        (line,) = self.notifier.process(events, 1010)
        animal = self.db.devices()[2]["alias"]
        self.assertEqual(line, f"🆕 New device\n{alias.icon(animal)} {animal} — MDs-phone (Phone · iOS)"
                               f"\n10.0.0.28 · {c}")

    def test_leave_is_debounced_and_back_only_follows_a_reported_leave(self):
        self.enable(leave_after_minutes=5)
        a, b = "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"
        self.scan({"10.0.0.1": a, "10.0.0.2": b}, 1000)
        self.assertEqual(self.scan({"10.0.0.1": a}, 1100), [])       # b vắng: chưa báo
        self.assertEqual(self.scan({"10.0.0.1": a, "10.0.0.2": b}, 1200), [])  # chập chờn: im lặng
        self.assertEqual(self.scan({"10.0.0.1": a}, 1300), [])       # b vắng lần nữa
        self.assertEqual(self.scan({"10.0.0.1": a}, 1500), [])       # mới 200 giây
        (left,) = self.scan({"10.0.0.1": a}, 1300 + 301)
        self.assertTrue(left.startswith("🔴 Left the network\n"))
        self.assertIn(b, left)
        self.assertEqual(self.scan({"10.0.0.1": a}, 2000), [])       # không báo lặp
        (back,) = self.scan({"10.0.0.1": a, "10.0.0.2": b}, 3000)
        self.assertTrue(back.startswith("🟢 Back online\n"))
        import time as _t
        for _ in range(50):
            if len(self.sent) == 3:
                break
            _t.sleep(0.02)
        self.assertEqual(len(self.sent), 3)                          # summary, left, back

    def test_send_to_telegram_and_ntfy(self):
        svc = FakeChatService()
        notify.TELEGRAM_API = notify.NTFY_SERVER = svc.url
        try:
            cfg = {"telegram": {"token": "123:ABC", "chat_id": 987654}, "ntfy": {"topic": "afing-x"}}
            self.assertEqual(notify.send(cfg, "🆕 Thiết bị mới"), [("telegram", None), ("ntfy", None)])
            (tg_path, _, tg_body), (nt_path, nt_headers, nt_body) = svc.requests
            self.assertEqual(tg_path, "/bot123:ABC/sendMessage")
            self.assertEqual(json.loads(tg_body)["chat_id"], 987654)
            self.assertEqual(json.loads(tg_body)["text"], "🆕 Thiết bị mới")
            self.assertEqual((nt_path, nt_body.decode()), ("/afing-x", "🆕 Thiết bị mới"))
            self.assertEqual(notify.telegram_find_chat("123:ABC"), (987654, "Tuyen D"))
        finally:
            svc.close()

    def test_errors_are_reported_without_leaking_the_token(self):
        svc = FakeChatService(status=401)
        notify.TELEGRAM_API = svc.url
        try:
            ((channel, error),) = notify.send({"telegram": {"token": "SECRET:TOKEN", "chat_id": 1}}, "x")
        finally:
            svc.close()
        self.assertEqual(channel, "telegram")
        self.assertIn("401", error)
        self.assertNotIn("SECRET", error)
        notify.TELEGRAM_API = "http://127.0.0.1:1"
        ((_, error),) = notify.send({"telegram": {"token": "SECRET:TOKEN", "chat_id": 1}}, "x")
        self.assertNotIn("SECRET", error)

    def test_interactive_setup_test_and_disable(self):
        svc = FakeChatService()
        notify.TELEGRAM_API = notify.NTFY_SERVER = svc.url
        out = []
        try:
            answers = iter(["1", " 123:ABC ", ""])
            self.assertEqual(notify.setup(self.cfg_path, lambda q: next(answers), out.append), 0)
            self.assertEqual(notify.load_config(self.cfg_path)["telegram"],
                             {"token": "123:ABC", "chat_id": 987654})
            answers = iter(["2", ""])
            self.assertEqual(notify.setup(self.cfg_path, lambda q: next(answers), out.append), 0)
            cfg = notify.load_config(self.cfg_path)
            self.assertEqual(notify.channels(cfg), ["telegram", "ntfy"])
            self.assertRegex(cfg["ntfy"]["topic"], r"^afing-[0-9a-f]{16}$")
            self.assertEqual(notify.setup(self.cfg_path, lambda q: "9", out.append), 1)
        finally:
            svc.close()
        self.assertEqual(notify.disable(self.cfg_path, out.append), 0)
        self.assertEqual(notify.test(self.cfg_path, out.append), 1)
        self.assertEqual(notify.load_config(self.cfg_path), {})
        self.assertTrue(os.path.exists(self.cfg_path))    # tắt thông báo không xoá file cấu hình


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "afing.cfg")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text, encoding="utf-8"):
        with open(self.path, "w", encoding=encoding) as f:
            f.write(text)

    def settings(self, *argv, double_clicked=False):
        return cli.load_settings(["--config", self.path, *argv], double_clicked)

    def test_missing_file_and_template_give_the_same_defaults(self):
        missing = config.load(self.path).values
        self.assertTrue(config.ensure(self.path))
        self.assertFalse(config.ensure(self.path))
        self.assertEqual(config.load(self.path).values, missing)
        self.assertEqual(set(missing), set(config.KINDS))        # mẫu khai đủ mọi khoá
        self.assertEqual((missing["web", "port"], missing["web", "host"], missing["scan", "dhcp"],
                          missing["scan", "interval"], missing["notify", "leave_after_minutes"]),
                         (8080, "127.0.0.1", True, 10, 5.0))

    def test_file_values_cli_overrides_and_paths(self):
        self.write("[web]\nport = 9090\nhost = 0.0.0.0\n[scan]\ninterval = 30\ndhcp = no\n"
                   "[data]\nlog_file = logs.txt\n", encoding="utf-8-sig")  # có BOM như Notepad
        args, cfg_path, explicit = self.settings("scan")
        self.assertEqual((args.port, args.host, args.interval, args.no_dhcp, args.offline_after),
                         (9090, "0.0.0.0", 30, True, 45))
        self.assertEqual(args.db, os.path.join(self.tmp.name, "afing.db"))       # cạnh file cfg
        self.assertEqual(args.log_file, os.path.join(self.tmp.name, "logs.txt"))
        self.assertEqual((cfg_path, explicit), (self.path, {}))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "afing.cfg.tmp")))

        args, _, explicit = self.settings("scan", "--port", "7000", "--db", "x.db")
        self.assertEqual((args.port, args.host), (7000, "0.0.0.0"))             # dòng lệnh thắng
        self.assertEqual(args.db, os.path.abspath("x.db"))
        self.assertEqual(explicit, {("web", "port"): 7000, ("data", "database"): "x.db"})

    def test_run_creates_the_template_and_double_click_opens_browser(self):
        args, _, _ = self.settings(double_clicked=True)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual((args.command, args.open_browser, args.port, args.log_file),
                         ("run", True, 8080, None))
        self.assertFalse(self.settings()[0].open_browser)
        config.set_values(self.path, "web", {"open_browser": False, "enabled": False})
        args, _, _ = self.settings(double_clicked=True)
        self.assertEqual((args.open_browser, args.no_web), (False, True))

    def test_invalid_values_are_explained(self):
        for text, expect in [("[web]\nport = abc\n", "[web] port"),
                             ("[web]\nport = 70000\n", "1-65535"),
                             ("[scan]\ndhcp = maybe\n", "yes hoặc no"),
                             ("[scan]\ninterval = 0\n", "lớn hơn 0"),
                             ("[scan]\nmethod = magic\n", "auto, arp"),
                             ("port = 1\n", "không đọc được")]:
            self.write(text)
            with self.assertRaises(config.ConfigError) as ctx:
                config.load(self.path)
            self.assertIn(expect, str(ctx.exception))
        self.assertEqual(cli.run(["--config", self.path, "scan"]), 1)            # báo lỗi, không văng

    def test_set_values_keeps_comments_and_other_settings(self):
        config.ensure(self.path)
        config.set_values(self.path, "web", {"port": 8123})
        config.set_values(self.path, "notify", {"telegram_token": "123:ABC", "brand_new": "x"})
        config.set_values(self.path, "extra", {"k": "v"})
        with open(self.path, encoding="utf-8") as f:
            text = f.read()
        expected = config.TEMPLATE.replace("port = 8080", "port = 8123") \
            .replace("telegram_token =", "telegram_token = 123:ABC") \
            .replace("leave_after_minutes = 5\n", "leave_after_minutes = 5\nbrand_new = x\n")
        self.assertEqual(text, expected + "\n[extra]\nk = v")
        loaded = config.load(self.path)
        self.assertEqual((loaded["web", "port"], loaded["web", "host"]), (8123, "127.0.0.1"))

    def test_notify_settings_live_in_the_cfg_and_legacy_json_is_imported(self):
        config.ensure(self.path)
        legacy = os.path.join(self.tmp.name, "notify.json")
        with open(legacy, "w") as f:
            json.dump({"telegram": {"token": "123:ABC", "chat_id": -1009}, "leave_after_minutes": 2}, f)
        notify.migrate_legacy(legacy, self.path)
        self.assertFalse(os.path.exists(legacy))
        self.assertEqual(notify.load_config(self.path), {
            "telegram": {"token": "123:ABC", "chat_id": -1009}, "leave_after_minutes": 2.0})
        with open(self.path, encoding="utf-8") as f:
            self.assertIn("# Cổng của dashboard", f.read())                       # chú thích còn nguyên
        notify.disable(self.path, lambda s: None)
        self.assertEqual(notify.load_config(self.path), {"leave_after_minutes": 2.0})


class ReportTests(unittest.TestCase):
    NOW = 1_800_000_000

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = os.path.join(self.tmp.name, "afing.cfg")
        config.ensure(self.cfg)
        config.set_values(self.cfg, "notify", {"telegram_token": "123:ABC", "telegram_chat_id": 987654})
        self.db = Database(os.path.join(self.tmp.name, "t.db"))
        self.tv, self.phone, self.old = "68:72:c3:01:d6:be", "f8:10:93:3b:a5:03", "aa:aa:aa:aa:aa:09"
        self.db.apply_scan({"10.0.0.9": self.old}, self.NOW - 30 * 86400, 45)
        self.db.apply_scan({"10.0.0.4": self.tv, "10.0.0.28": self.phone}, self.NOW - 7200, 45)
        self.db.apply_scan({"10.0.0.4": self.tv}, self.NOW, 45)
        self.db.set_identities({self.tv: {"name": "[TV] Samsung", "type": "tv"},
                                self.phone: {"name": "MDs-phone", "type": "mobile"}})
        self.sent = []
        self.reporter = report.Reporter(self.cfg, self.db.devices, "10.0.0.0/24",
                                        sender=lambda cfg, text: self.sent.append(text) or [])
        self._api = notify.TELEGRAM_API

    def tearDown(self):
        notify.TELEGRAM_API = self._api
        self.db.close()
        self.tmp.cleanup()

    def alias_of(self, mac):
        a = next(d["alias"] for d in self.db.devices() if d["mac"] == mac)
        return f"{alias.icon(a)} {a}"

    def test_report_text(self):
        text = self.reporter.text(now=self.NOW)
        stamp = time.strftime("%d %b %H:%M", time.localtime(self.NOW))
        self.assertEqual(text.split("\n"), [
            "📊 afing report · 10.0.0.0/24",
            f"{stamp} · 1 online · 2 offline",
            "",
            "🟢 ONLINE (1)",
            f"{self.alias_of(self.tv)} — [TV] Samsung · TV · 10.0.0.4",
            "",
            "⚪ OFFLINE (2)",
            f"{self.alias_of(self.phone)} — MDs-phone · Phone · last seen 2 hr ago",
            "(+1 not seen for over 7 days)",
        ])
        online = self.reporter.text("online", self.NOW)
        self.assertIn("🟢 ONLINE (1)", online)
        self.assertNotIn("OFFLINE (", online)
        config.set_values(self.cfg, "report", {"offline_days": 0})
        self.assertIn("last seen 30 days ago", self.reporter.text("offline", self.NOW))
        self.assertEqual([report.ago(s) for s in (5, 600, 7300, 86400, 200000)],
                         ["just now", "10 min ago", "2 hr ago", "1 day ago", "2 days ago"])

    def test_split_message(self):
        text = "\n".join(f"line {i}" for i in range(400))
        parts = notify.split_message(text, 500)
        self.assertTrue(all(len(p) <= 500 for p in parts))
        self.assertEqual("\n".join(parts), text)
        self.assertEqual(notify.split_message("short"), ["short"])
        self.assertEqual(notify.split_message("x" * 50, 20), ["x" * 20])  # một dòng quá dài: cắt bớt

    def at(self, hour, minute, day_offset=0):
        base = time.localtime(self.NOW)
        return time.mktime(base[:3] + (hour, minute, 0, 0, 0, -1)) + day_offset * 86400

    def test_schedule_fixed_times(self):
        config.set_values(self.cfg, "report", {"times": "08:00, 21:30"})
        s = report.Schedule(self.cfg)
        self.assertFalse(s.due(self.at(9, 0)))            # khởi động sau 08:00: không gửi bù
        self.assertFalse(s.due(self.at(21, 29)))
        self.assertTrue(s.due(self.at(21, 30, 0) + 5))    # vừa qua mốc
        self.assertFalse(s.due(self.at(21, 31)))          # không gửi lặp
        self.assertFalse(s.due(self.at(23, 59)))
        self.assertTrue(s.due(self.at(8, 0, 1) + 3))      # 08:00 hôm sau
        self.assertTrue(s.due(self.at(21, 40, 1)))        # máy ngủ qua mốc 21:30: gửi khi thức
        config.set_values(self.cfg, "report", {"times": ""})
        self.assertFalse(s.due(self.at(21, 30, 2) + 1))   # đã tắt

    def test_schedule_interval_and_tick_sends(self):
        config.set_values(self.cfg, "report", {"interval_minutes": 60})
        t = self.NOW
        self.assertFalse(self.reporter.tick(t))
        self.assertFalse(self.reporter.tick(t + 3599))
        self.assertTrue(self.reporter.tick(t + 3600))
        self.assertFalse(self.reporter.tick(t + 3700))
        self.assertTrue(self.reporter.tick(t + 7200))
        config.set_values(self.cfg, "report", {"interval_minutes": 10})  # đổi chu kỳ: tính lại
        self.assertFalse(self.reporter.tick(t + 7300))
        self.assertTrue(self.reporter.tick(t + 7300 + 600))
        for _ in range(50):
            if len(self.sent) == 3:
                break
            time.sleep(0.02)
        self.assertEqual(len(self.sent), 3)
        self.assertTrue(self.sent[0].startswith("📊 afing report"))
        # chưa cấu hình kênh nào thì không gửi
        notify.disable(self.cfg, lambda s: None)
        self.assertFalse(self.reporter.tick(t + 7900 + 600))

    def test_config_times_validation_and_upgrade_of_old_cfg(self):
        config.set_values(self.cfg, "report", {"times": "8:05,21h30 , 00:00"})
        self.assertEqual(report.settings(self.cfg)["times"], [(8, 5), (21, 30), (0, 0)])
        for bad in ("25:00", "8", "08:60", "sáng"):
            config.set_values(self.cfg, "report", {"times": bad})
            with self.assertRaises(config.ConfigError):
                config.load(self.cfg)
        self.assertEqual(report.settings(self.cfg)["times"], [])     # file lỗi: coi như tắt

        old = os.path.join(self.tmp.name, "old.cfg")
        with open(old, "w", encoding="utf-8") as f:
            f.write("# của tôi\n[web]\nport = 9000\n\n[notify]\ntelegram_token = 1:A\n")
        self.assertEqual(config.upgrade(old), ["scan", "data", "report"])
        self.assertEqual(config.upgrade(old), [])
        loaded = config.load(old)
        self.assertEqual((loaded["web", "port"], loaded["notify", "telegram_token"]), (9000, "1:A"))
        with open(old, encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text.startswith("# của tôi\n[web]\nport = 9000\n"))
        self.assertIn("[report]\n# Báo cáo danh sách", text)

    def test_bot_commands_only_answer_the_configured_chat(self):
        bot = report.TelegramCommands(self.cfg, self.reporter)

        def ask(text, chat=987654):
            return bot.replies({"update_id": 1, "message": {"chat": {"id": chat}, "text": text}}, 987654)

        ((chat, text),) = ask("/report")
        self.assertEqual(chat, 987654)
        self.assertIn("🟢 ONLINE (1)", text)
        self.assertIn("⚪ OFFLINE (2)", text)
        self.assertNotIn("OFFLINE (", ask("/online@afing_bot")[0][1])
        self.assertNotIn("ONLINE (1)", ask("offline")[0][1])
        self.assertEqual(ask("/whatever")[0][1], report.HELP)
        self.assertEqual(ask("/help")[0][1], report.HELP)
        # người lạ: không lộ thiết bị; chỉ được biết ID cuộc trò chuyện của chính họ
        self.assertEqual(ask("/report", chat=555), [])
        ((chat, text),) = ask("/start", chat=555)
        self.assertEqual(chat, 555)
        self.assertIn("555", text)
        self.assertNotIn("10.0.0", text)
        self.assertEqual(bot.replies({"update_id": 2}, 987654), [])
        self.assertEqual(bot.replies({"message": {"chat": {"id": 987654}}}, 987654), [])  # ảnh, sticker

    def test_bot_polling_roundtrip(self):
        svc = FakeChatService()
        notify.TELEGRAM_API = svc.url
        bot = report.TelegramCommands(self.cfg, self.reporter)
        try:
            svc.updates.append({"update_id": 7, "message": {"chat": {"id": 987654}, "text": "/report"}})
            self.assertEqual(bot.poll_once(wait=0), 0)        # lệnh tồn từ trước khi khởi động: bỏ qua
            svc.updates.append({"update_id": 8, "message": {"chat": {"id": 987654}, "text": "/online"}})
            svc.updates.append({"update_id": 9, "message": {"chat": {"id": 555}, "text": "/report"}})
            self.assertEqual(bot.poll_once(wait=0), 1)
            posts = [(p, json.loads(b)) for p, _, b in svc.requests if b]
            self.assertEqual(len(posts), 1)
            self.assertEqual(posts[0][0], "/bot123:ABC/sendMessage")
            self.assertEqual(posts[0][1]["chat_id"], 987654)
            self.assertIn("🟢 ONLINE (1)", posts[0][1]["text"])
            self.assertEqual(bot.poll_once(wait=0), 0)        # không trả lời lại lệnh cũ
            self.assertIn("offset=10", svc.requests[-1][0])
        finally:
            svc.close()


class OuiTests(unittest.TestCase):
    def test_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "oui.csv")
            with open(path, "w", encoding="utf-8") as f:
                f.write("Registry,Assignment,Organization Name,Organization Address\n")
                f.write('MA-L,A491B1,"Technicolor, Inc.",Somewhere\n')
            oui = OuiTable(path)
            self.assertEqual(oui.lookup("a4:91:b1:11:22:33"), "Technicolor, Inc.")
            self.assertIsNone(oui.lookup("00:11:22:33:44:55"))
            self.assertEqual(oui.lookup("da:a1:19:00:00:01"), RANDOM_MAC)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def types(self, events):
        return sorted((e["type"], e["mac"]) for e in events)

    def test_lifecycle(self):
        a, b = "aa:aa:aa:aa:aa:aa", "bc:bc:bc:bc:bc:bc"
        ev = self.db.apply_scan({"10.0.0.1": a, "10.0.0.2": b}, 1000, 45, gateway_ip="10.0.0.1",
                                self_mac=b)
        self.assertEqual(self.types(ev), [("new", a), ("new", b)])

        # b vắng mặt nhưng chưa quá hạn -> vẫn online
        self.assertEqual(self.db.apply_scan({"10.0.0.1": a}, 1030, 45), [])
        ev = self.db.apply_scan({"10.0.0.1": a}, 1050, 45)
        self.assertEqual(self.types(ev), [("offline", b)])

        ev = self.db.apply_scan({"10.0.0.1": a, "10.0.0.9": b}, 1100, 45)
        self.assertEqual(self.types(ev), [("ip_change", b), ("online", b)])

        devs = {d["mac"]: d for d in self.db.devices()}
        self.assertEqual(devs[b]["ip"], "10.0.0.9")
        self.assertEqual((devs[b]["first_seen"], devs[b]["last_seen"]), (1000, 1100))
        self.assertEqual(devs[b]["is_online"], 1)
        self.assertEqual(len(self.db.events()), 5)

    def test_names_and_vendor_backfill(self):
        a = "aa:aa:aa:aa:aa:aa"
        self.db.apply_scan({"10.0.0.1": a}, 1000, 45)
        self.db.apply_scan({"10.0.0.1": a}, 1010, 45, vendor_lookup=lambda mac: "Acme")
        self.db.set_identities({a: {"name": "printer", "model": "LaserJet"}})
        self.db.set_identities({a: {"model": "LaserJet Pro", "type": "printer"}})  # thiếu tên -> giữ tên cũ
        self.db.set_identities({a: {"os": "Linux"}})
        self.assertEqual((self.db.devices()[0]["device_type"], self.db.devices()[0]["os"]),
                         ("printer", "Linux"))
        self.assertTrue(self.db.set_custom_name(a, "Máy in tầng 2"))
        self.assertFalse(self.db.set_custom_name("00:00:00:00:00:01", "x"))
        dev = self.db.devices()[0]
        self.assertEqual((dev["vendor"], dev["hostname"], dev["custom_name"], dev["model"]),
                         ("Acme", "printer", "Máy in tầng 2", "LaserJet Pro"))
        self.assertEqual(self.db.events()[0]["name"], "Máy in tầng 2")

    def test_better_name_is_not_overwritten_by_worse(self):
        a = "aa:aa:aa:aa:aa:aa"
        self.db.apply_scan({"10.0.0.1": a}, 1000, 45)
        self.db.set_identities({a: {"name": "host.lan", "name_rank": 1}})
        self.db.set_identities({a: {"name": "iPhone-cua-Me", "name_rank": 2}})
        self.db.set_identities({a: {"name": "host.lan", "name_rank": 1}})
        self.assertEqual(self.db.devices()[0]["hostname"], "iPhone-cua-Me")
        self.db.set_identities({a: {"name": "iPhone của Mẹ", "name_rank": 3}})
        self.db.set_identities({a: {"name": "iPhone-moi", "name_rank": 2}})
        self.assertEqual(self.db.devices()[0]["hostname"], "iPhone của Mẹ")

    def test_custom_name_survives_reconnect_with_new_ip(self):
        a = "f8:10:93:3b:a5:03"
        self.db.apply_scan({"10.0.0.28": a}, 1000, 45)
        self.db.set_custom_name(a, "iPhone của Mẹ")
        self.db.apply_scan({}, 2000, 45)                      # rời mạng
        self.assertEqual(self.db.devices()[0]["is_online"], 0)
        self.db.apply_scan({"10.0.0.77": a}, 90000, 45)       # hôm sau vào lại, IP khác
        self.db.set_identities({a: {"name": "MDs-phone", "name_rank": 2}})
        devs = self.db.devices()
        self.assertEqual(len(devs), 1)
        self.assertEqual((devs[0]["custom_name"], devs[0]["ip"], devs[0]["is_online"],
                          devs[0]["first_seen"]), ("iPhone của Mẹ", "10.0.0.77", 1, 1000))

    def test_same_mac_two_ips(self):
        a = "aa:aa:aa:aa:aa:aa"
        self.db.apply_scan({"10.0.0.1": a, "10.0.0.2": a}, 1000, 45)
        self.assertEqual(len(self.db.devices()), 1)


class FakeScanner:
    method = "fake"

    def __init__(self):
        self.result = {}

    def scan(self):
        return dict(self.result)


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "t.db"))
        net = netinfo.NetInfo(ipaddress.ip_network("127.0.0.0/30"), "127.0.0.1")
        self.scanner = FakeScanner()
        self.monitor = Monitor(net, self.scanner, self.db,
                               OuiTable(os.path.join(self.tmp.name, "oui.csv")))
        self.monitor._resolve_names = lambda seen: None
        self.server = make_server("127.0.0.1", 0, self.db, self.monitor)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.db.close()
        self.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path) as r:
            return r.read()

    def post(self, path, body, ctype="application/json"):
        req = urllib.request.Request(self.base + path, data=body, headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_state_and_rename(self):
        mac = "aa:aa:aa:aa:aa:aa"
        self.scanner.result = {"127.0.0.2": mac}
        self.monitor.scan_once()

        self.assertIn(b"afing", self.get("/"))
        state = json.loads(self.get("/api/state"))
        self.assertEqual(state["status"]["scan_count"], 1)
        self.assertEqual([d["mac"] for d in state["devices"]], [mac])
        self.assertEqual(state["devices"][0]["alias"], alias.pick(mac, []))
        self.assertTrue(state["devices"][0]["alias_icon"])
        self.assertEqual(state["events"][0]["alias"], state["devices"][0]["alias"])
        self.assertEqual(state["events"][0]["type"], "new")

        url = f"/api/devices/{mac}/name"
        self.assertEqual(self.post(url, b"name=x", "application/x-www-form-urlencoded"), 415)
        self.assertEqual(self.post(url, b"{nope"), 400)
        self.assertEqual(self.post("/api/devices/aa:aa:aa:aa:aa:ab/name", b'{"name":"x"}'), 404)
        self.assertEqual(self.post(url, json.dumps({"name": " TV phòng khách "}).encode()), 200)
        state = json.loads(self.get("/api/state"))
        self.assertEqual(state["devices"][0]["custom_name"], "TV phòng khách")


if __name__ == "__main__":
    unittest.main()
