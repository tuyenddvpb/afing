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

from afing import alias, dhcp, discovery, names, netinfo, scanner
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
        used = set()
        for i in range(len(alias.ANIMALS) * 2 + 3):
            used.add(alias.pick(f"02:00:00:00:{i // 256:02x}:{i % 256:02x}", used))
        self.assertEqual(len(used), len(alias.ANIMALS) * 2 + 3)
        self.assertEqual(sum(1 for a in used if a.endswith(" 2")), len(alias.ANIMALS))
        self.assertEqual(len(alias.ICONS), len(alias.ANIMALS))  # không trùng tên

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
