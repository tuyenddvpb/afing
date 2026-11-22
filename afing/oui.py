"""Tra hãng sản xuất từ 3 byte đầu của MAC (bảng OUI của IEEE)."""

import csv
import logging
import os
import urllib.request
from typing import Dict, Optional

log = logging.getLogger("afing.oui")

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
RANDOM_MAC = "Random MAC (private)"
LEGACY_RANDOM_MAC = "MAC ngẫu nhiên (riêng tư)"  # nhãn mà các bản cũ đã lưu vào database


class OuiTable:
    def __init__(self, path: str):
        self.path = path
        self._table: Dict[str, str] = {}
        self.load()

    def __len__(self):
        return len(self._table)

    def load(self) -> None:
        if not os.path.exists(self.path):
            return
        table = {}
        with open(self.path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f):
                # Registry,Assignment,Organization Name,Organization Address
                if len(row) >= 3 and len(row[1]) == 6:
                    table[row[1].lower()] = row[2].strip()
        self._table = table

    def download(self, timeout: float = 60) -> int:
        """Tải bảng OUI mới nhất từ IEEE về `self.path`. Trả số hãng đã nạp."""
        tmp = self.path + ".tmp"
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0 afing"})
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
            while chunk := resp.read(65536):
                out.write(chunk)
        os.replace(tmp, self.path)
        self.load()
        return len(self)

    def lookup(self, mac: str) -> Optional[str]:
        if int(mac[:2], 16) & 0x02:
            # Bit "locally administered": điện thoại/laptop đời mới tự sinh MAC cho từng Wi-Fi.
            return RANDOM_MAC
        return self._table.get(mac.replace(":", "")[:6])
