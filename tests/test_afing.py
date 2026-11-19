import ipaddress
import json
import os
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from afing import names, netinfo, scanner
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
        self.db.set_hostnames({a: "printer"})
        self.assertTrue(self.db.set_custom_name(a, "Máy in tầng 2"))
        self.assertFalse(self.db.set_custom_name("00:00:00:00:00:01", "x"))
        dev = self.db.devices()[0]
        self.assertEqual((dev["vendor"], dev["hostname"], dev["custom_name"]),
                         ("Acme", "printer", "Máy in tầng 2"))
        self.assertEqual(self.db.events()[0]["name"], "Máy in tầng 2")

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
